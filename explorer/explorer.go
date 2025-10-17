// Package explorer provides a high-performance blockchain explorer client with support for
// multiple concurrent WebSocket connections, batched subscriptions, and automatic deduplication.
//
// # Architecture
//
//   - Multiple concurrent WebSocket connections (configurable, default: 3)
//   - Hash-based address distribution for consistent routing
//   - Batched subscriptions to prevent overwhelming individual connections
//   - Instance-scoped deduplication to prevent duplicate subscriptions
//   - Automatic fallback to polling if WebSocket connections fails
//
// # Usage
//
// Basic usage with default settings:
//
//	svc, err := explorer.NewExplorer("", arklib.Bitcoin,
//	    explorer.WithTracker(true))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer svc.Stop()
//
// Advanced usage with custom connection pool settings:
//
//	svc, err := explorer.NewExplorer("https://mempool.space/api", arklib.Bitcoin,
//	    explorer.WithTracker(true),
//	    explorer.WithMaxConnections(5),        // 5 concurrent connections
//	    explorer.WithBatchSize(25),            // 25 addresses per batch
//	    explorer.WithBatchDelay(50*time.Millisecond)) // 50ms between batches
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer svc.Stop()
//
//	// Subscribe to addresses
//	addresses := []string{"bc1q...", "bc1p...", ...}
//	if err := svc.SubscribeForAddresses(addresses); err != nil {
//	    log.Fatal(err)
//	}
//
//	// Listen for events
//	for event := range svc.GetAddressesEvents() {
//	    fmt.Printf("New UTXOs: %d, Spent: %d\n",
//	        len(event.NewUtxos), len(event.SpentUtxos))
//	}
//
// # Performance Considerations
//
// When subscribing to many addresses (100+), consider:
//   - Increase MaxConnections (3-5) to distribute load
//   - Adjust BatchSize (25-50) to control subscription rate
//   - Set BatchDelay (50-100ms) to avoid rate limiting
//
// # Thread Safety
//
// All public methods are thread-safe and can be called concurrently.
package explorer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	BitcoinExplorer = "bitcoin"
	pongInterval    = 60 * time.Second
	pingInterval    = (pongInterval * 9) / 10
)

var (
	defaultExplorerUrls = utils.SupportedType[string]{
		arklib.Bitcoin.Name:        "https://mempool.space/api",
		arklib.BitcoinTestNet.Name: "https://mempool.space/testnet/api",
		//arklib.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
		arklib.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
		arklib.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
		arklib.BitcoinRegTest.Name:   "http://localhost:3000",
	}
)

// Explorer provides methods to interact with blockchain explorers (e.g., mempool.space, esplora).
// It supports both HTTP REST API calls and WebSocket connections for real-time address tracking.
// The implementation uses a connection pool architecture with multiple concurrent WebSocket connections
// to handle high-volume address subscriptions without overwhelming individual connections.
type Explorer interface {
	// Start must be used when using the explorer with tracking enabled.
	Start()

	// GetTxHex retrieves the raw transaction hex for a given transaction ID.
	GetTxHex(txid string) (string, error)

	// Broadcast broadcasts one or more raw transactions to the network.
	// Returns the transaction ID of the first transaction on success.
	Broadcast(txs ...string) (string, error)

	// GetTxs retrieves all transactions associated with a given address.
	GetTxs(addr string) ([]tx, error)

	// GetTxOutspends returns the spent status of all outputs for a given transaction.
	GetTxOutspends(tx string) ([]spentStatus, error)

	// GetUtxos retrieves all unspent transaction outputs (UTXOs) for a given address.
	GetUtxos(addr string) ([]Utxo, error)

	// GetRedeemedVtxosBalance calculates the redeemed virtual UTXO balance for an address
	// considering the unilateral exit delay.
	GetRedeemedVtxosBalance(
		addr string, unilateralExitDelay arklib.RelativeLocktime,
	) (uint64, map[int64]uint64, error)

	// GetTxBlockTime returns whether a transaction is confirmed and its block time.
	GetTxBlockTime(
		txid string,
	) (confirmed bool, blocktime int64, err error)

	// BaseUrl returns the base URL of the explorer service.
	BaseUrl() string

	// GetFeeRate retrieves the current recommended fee rate in sat/vB.
	GetFeeRate() (float64, error)

	// GetConnectionCount returns the number of active WebSocket connections.
	GetConnectionCount() int

	// GetBatchSize returns the configured batch size for address subscriptions.
	GetBatchSize() int

	// GetBatchDelay returns the configured delay between batches.
	GetBatchDelay() time.Duration

	// GetSubscribedAddressCount returns the number of currently subscribed addresses.
	GetSubscribedAddressCount() int

	// GetSubscribedAddresses returns a list of all currently subscribed addresses.
	GetSubscribedAddresses() []string

	// IsAddressSubscribed checks if a specific address is currently subscribed.
	IsAddressSubscribed(address string) bool

	// GetErrors returns recent errors encountered by the explorer (max 100).
	GetErrors() []error

	// GetErrorCount returns the total number of errors encountered since creation.
	GetErrorCount() int

	// ClearErrors clears the error history.
	ClearErrors()

	// GetAddressesEvents returns a channel that receives onchain address events
	// (new UTXOs, spent UTXOs, confirmed UTXOs) for all subscribed addresses.
	GetAddressesEvents() <-chan types.OnchainAddressEvent

	// SubscribeForAddresses subscribes to address updates via WebSocket connections.
	// Addresses are automatically distributed across multiple connections using hash-based routing.
	// Subscriptions are batched to prevent overwhelming individual connections.
	// Duplicate subscriptions are automatically prevented via instance-scoped deduplication.
	SubscribeForAddresses(addresses []string) error

	// UnsubscribeForAddresses removes address subscriptions and updates the WebSocket connections.
	UnsubscribeForAddresses(addresses []string) error

	// Stop gracefully shuts down the explorer, closing all WebSocket connections and channels.
	Stop()
}

// addressData stores cached UTXO data for an address to detect changes during polling.
type addressData struct {
	hash  []byte
	utxos []Utxo
}

type explorerSvc struct {
	cache          *utils.Cache[string]
	baseUrl        string
	net            arklib.Network
	connPool       *connectionPool
	subscribedMu   *sync.RWMutex
	subscribedMap  map[string]addressData
	channel        chan types.OnchainAddressEvent
	stopTracking   func()
	pollInterval   time.Duration
	noTracking     bool
	batchSize      int
	batchDelay     time.Duration
	maxConnections int
	errorsMu       sync.RWMutex
	errors         []error
	errorCount     int
	// Instance-scoped address deduplication map
	// Prevents the same address from being subscribed multiple times within this explorer instance
	addressDedupMap map[string]bool
	addressDedupMu  sync.RWMutex
}

// NewExplorer creates a new Explorer instance for the specified network.
// If baseUrl is empty, it uses the default explorer URL for the network.
//
// The explorer supports:
//   - Multiple concurrent WebSocket connections for scalability
//   - Batched address subscriptions to prevent overwhelming connections
//   - Instance-scoped deduplication to prevent duplicate subscriptions
//   - Automatic fallback to polling if WebSocket connections fail
//
// Example:
//
//	svc, err := explorer.NewExplorer("https://mempool.space/api", arklib.Bitcoin,
//	    explorer.WithTracker(true),
//	    explorer.WithMaxConnections(3),
//	    explorer.WithBatchSize(25),
//	    explorer.WithBatchDelay(50*time.Millisecond))
func NewExplorer(baseUrl string, net arklib.Network, opts ...Option) (Explorer, error) {
	if len(baseUrl) == 0 {
		baseUrl, ok := defaultExplorerUrls[net.Name]
		if !ok {
			return nil, fmt.Errorf(
				"cannot find default explorer url associated with network %s",
				net.Name,
			)
		}
		return NewExplorer(baseUrl, net, opts...)
	}

	if _, err := deriveWsURL(baseUrl); err != nil {
		return nil, fmt.Errorf("invalid base url: %s", err)
	}

	svcOpts := &explorerSvc{
		batchSize:      50,
		batchDelay:     100 * time.Millisecond,
		maxConnections: 3,
	}
	for _, opt := range opts {
		opt(svcOpts)
	}

	if svcOpts.noTracking {
		return &explorerSvc{
			cache:      utils.NewCache[string](),
			baseUrl:    baseUrl,
			net:        net,
			noTracking: svcOpts.noTracking,
		}, nil
	}

	svc := &explorerSvc{
		cache:           utils.NewCache[string](),
		baseUrl:         baseUrl,
		net:             net,
		subscribedMu:    &sync.RWMutex{},
		subscribedMap:   make(map[string]addressData),
		pollInterval:    svcOpts.pollInterval,
		noTracking:      svcOpts.noTracking,
		batchSize:       svcOpts.batchSize,
		batchDelay:      svcOpts.batchDelay,
		maxConnections:  svcOpts.maxConnections,
		addressDedupMap: make(map[string]bool),
	}

	return svc, nil
}

func (e *explorerSvc) Start() {
	// Nothing to do if tracking disabled.
	if e.noTracking {
		return
	}

	// Nothing to do if service already started.
	if e.stopTracking != nil {
		return
	}

	e.connPool = newConnectionPool(e.maxConnections)
	e.channel = make(chan types.OnchainAddressEvent, 100)

	ctx, cancel := context.WithCancel(context.Background())
	// nolint
	wsURL, _ := deriveWsURL(e.baseUrl)

	// Initialize connection pool
	if err := e.initializeConnectionPool(ctx, wsURL); err != nil {
		log.WithError(err).WithFields(log.Fields{
			"network": e.net.Name,
			"url":     wsURL,
		}).Warn("explorer: failed to initialize ws connection pool, falling back to polling")
	}

	if count := e.connPool.getConnectionCount(); count == 0 {
		log.Debugf("explorer: starting tracking with polling interval %s", e.pollInterval)
	} else {
		log.Debugf("explorer: starting tracking with %d ws connections", count)
	}
	e.stopTracking = cancel
	go e.startTracking(ctx)
	log.Debug("explorer: started")
}

func (e *explorerSvc) Stop() {
	// Nothing to do is tracking disabled.
	if e.noTracking {
		return
	}

	// Nothing to do if service already stopped.
	if e.stopTracking == nil {
		return
	}

	e.stopTracking()

	// Close all connections in the pool
	if e.connPool != nil {
		e.connPool.mu.Lock()
		for _, wsConn := range e.connPool.connections {
			if wsConn.conn != nil {
				if err := wsConn.conn.Close(); err != nil {
					log.WithError(err).Warn("explorer: failed to close ws connection")
				}
			}
		}
		e.connPool.mu.Unlock()
	}

	// Clear subscribed addresses map
	e.subscribedMu.Lock()
	e.subscribedMap = make(map[string]addressData)
	e.subscribedMu.Unlock()

	// Clear instance-scoped deduplication map
	e.addressDedupMu.Lock()
	e.addressDedupMap = make(map[string]bool)
	e.addressDedupMu.Unlock()

	close(e.channel)
	e.stopTracking = nil
	log.Debug("explorer: stopped")
}

func (e *explorerSvc) BaseUrl() string {
	return e.baseUrl
}

func (e *explorerSvc) GetNetwork() arklib.Network {
	return e.net
}

func (e *explorerSvc) GetFeeRate() (float64, error) {
	endpoint, err := url.JoinPath(e.baseUrl, "fee-estimates")
	if err != nil {
		return 0, err
	}

	resp, err := http.Get(endpoint)
	if err != nil {
		return 0, err
	}
	// nolint:all
	defer resp.Body.Close()

	var response map[string]float64

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("failed to get fee rate: %s", resp.Status)
	}

	if len(response) == 0 {
		return 1, nil
	}

	return response["1"], nil
}

func (e *explorerSvc) GetConnectionCount() int {
	if e.connPool == nil {
		return 0
	}
	return e.connPool.getConnectionCount()
}

func (e *explorerSvc) GetBatchSize() int {
	return e.batchSize
}

func (e *explorerSvc) GetBatchDelay() time.Duration {
	return e.batchDelay
}

func (e *explorerSvc) GetSubscribedAddressCount() int {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	return len(e.subscribedMap)
}

func (e *explorerSvc) GetSubscribedAddresses() []string {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()

	addresses := make([]string, 0, len(e.subscribedMap))
	for addr := range e.subscribedMap {
		addresses = append(addresses, addr)
	}
	return addresses
}

func (e *explorerSvc) IsAddressSubscribed(address string) bool {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	_, exists := e.subscribedMap[address]
	return exists
}

func (e *explorerSvc) GetErrors() []error {
	e.errorsMu.RLock()
	defer e.errorsMu.RUnlock()

	// Return a copy to avoid race conditions
	errorsCopy := make([]error, len(e.errors))
	copy(errorsCopy, e.errors)
	return errorsCopy
}

func (e *explorerSvc) GetErrorCount() int {
	e.errorsMu.RLock()
	defer e.errorsMu.RUnlock()
	return e.errorCount
}

func (e *explorerSvc) ClearErrors() {
	e.errorsMu.Lock()
	defer e.errorsMu.Unlock()
	e.errors = nil
	e.errorCount = 0
}

func (e *explorerSvc) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	return e.channel
}

func (e *explorerSvc) GetTxHex(txid string) (string, error) {
	if hex, ok := e.cache.Get(txid); ok {
		return hex, nil
	}

	txHex, err := e.getTxHex(txid)
	if err != nil {
		return "", err
	}

	e.cache.Set(txid, txHex)

	return txHex, nil
}

func (e *explorerSvc) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("no txs to broadcast")
	}

	for _, tx := range txs {
		txStr, txid, err := parseBitcoinTx(tx)
		if err != nil {
			return "", err
		}

		e.cache.Set(txid, txStr)
	}

	if len(txs) == 1 {
		txid, err := e.broadcast(txs[0])
		if err != nil {
			if strings.Contains(
				strings.ToLower(err.Error()), "transaction already in block chain",
			) {
				return txid, nil
			}

			return "", err
		}

		return txid, nil
	}

	// package
	return e.broadcastPackage(txs...)
}

func (e *explorerSvc) GetTxs(addr string) ([]tx, error) {
	resp, err := http.Get(fmt.Sprintf("%s/address/%s/txs", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}
	payload := []tx{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func (e *explorerSvc) SubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}

	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	addressesToSubscribe := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		if _, ok := e.subscribedMap[addr]; ok {
			continue
		}
		addressesToSubscribe = append(addressesToSubscribe, addr)
	}

	if len(addressesToSubscribe) == 0 {
		return nil
	}

	// Add new addresses to the subscribed map
	for _, addr := range addressesToSubscribe {
		e.subscribedMap[addr] = addressData{}
	}

	if e.connPool != nil && e.connPool.getConnectionCount() > 0 {
		// Use connection pool for address subscription with batching
		return e.subscribeForAddressesWithPool(addressesToSubscribe)
	}
	return nil
}

func (e *explorerSvc) subscribeForAddressesWithPool(addressesToSubscribe []string) error {
	// Group addresses by their assigned connection
	addressBuckets := make(map[*websocketConnection][]string)

	for _, addr := range addressesToSubscribe {
		// Check if address is already subscribed in this instance (deduplication)
		e.addressDedupMu.RLock()
		if e.addressDedupMap[addr] {
			e.addressDedupMu.RUnlock()
			continue // Already subscribed in this instance
		}
		e.addressDedupMu.RUnlock()

		// Get the connection for this address
		wsConn, found := e.connPool.getConnectionForAddress(addr)
		if !found {
			continue // Skip if no available connection
		}

		addressBuckets[wsConn] = append(addressBuckets[wsConn], addr)
	}

	// Track addresses that were successfully subscribed for rollback on error
	var subscribedAddresses []string
	var subscriptionError error

	// Subscribe addresses to their respective connections in batches
	for wsConn, addrs := range addressBuckets {
		// Process in batches to avoid overwhelming a single websocket message
		for i := 0; i < len(addrs); i += e.batchSize {
			end := i + e.batchSize
			if end > len(addrs) {
				end = len(addrs)
			}
			batch := addrs[i:end]

			// Send subscription request
			payload := map[string][]string{"track-addresses": batch}
			wsConn.mu.Lock()
			if err := wsConn.conn.WriteJSON(payload); err != nil {
				wsConn.mu.Unlock()
				subscriptionError = fmt.Errorf("failed to subscribe for addresses batch: %s", err)
				break
			}
			wsConn.mu.Unlock()

			// Mark addresses as subscribed in instance dedup map
			e.addressDedupMu.Lock()
			for _, addr := range batch {
				e.addressDedupMap[addr] = true
				subscribedAddresses = append(subscribedAddresses, addr)
			}
			e.addressDedupMu.Unlock()

			// Mark addresses in this connection's bucket
			wsConn.mu.Lock()
			for _, addr := range batch {
				wsConn.addressBucket[addr] = true
			}
			wsConn.mu.Unlock()

			// Add delay between batches if configured
			if i+e.batchSize < len(addrs) && e.batchDelay > 0 {
				time.Sleep(e.batchDelay)
			}
		}

		if subscriptionError != nil {
			break
		}
	}

	// If there was an error, clean up the addresses that were subscribed
	if subscriptionError != nil {
		e.addressDedupMu.Lock()
		for _, addr := range subscribedAddresses {
			delete(e.addressDedupMap, addr)
		}
		e.addressDedupMu.Unlock()
		return subscriptionError
	}

	return nil
}

func (e *explorerSvc) UnsubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}

	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	for _, addr := range addresses {
		delete(e.subscribedMap, addr)

		// Remove from instance dedup map
		e.addressDedupMu.Lock()
		delete(e.addressDedupMap, addr)
		e.addressDedupMu.Unlock()
	}

	if e.connPool != nil && e.connPool.getConnectionCount() > 0 {
		// When unsubscribing we have to resubscribe for the remaining addresses.
		// Group remaining addresses by connection
		addressBuckets := make(map[*websocketConnection][]string)

		for addr := range e.subscribedMap {
			wsConn, found := e.connPool.getConnectionForAddress(addr)
			if found {
				addressBuckets[wsConn] = append(addressBuckets[wsConn], addr)
			}
		}

		// Resubscribe to each connection with its addresses
		for wsConn, addrs := range addressBuckets {
			payload := map[string][]string{"track-addresses": addrs}
			wsConn.mu.Lock()
			if err := wsConn.conn.WriteJSON(payload); err != nil {
				wsConn.mu.Unlock()
				return fmt.Errorf("failed to unsubscribe for addresses %s: %s", addresses, err)
			}
			wsConn.mu.Unlock()
		}
	}

	return nil
}

func (e *explorerSvc) GetTxOutspends(txid string) ([]spentStatus, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/outspends", e.baseUrl, txid))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get txs: %s", string(body))
	}

	spentStatuses := make([]spentStatus, 0)
	if err := json.Unmarshal(body, &spentStatuses); err != nil {
		return nil, err
	}
	return spentStatuses, nil
}

func (e *explorerSvc) GetUtxos(addr string) ([]Utxo, error) {
	decoded, err := btcutil.DecodeAddress(addr, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	outputScript, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	resp, err := http.Get(fmt.Sprintf("%s/address/%s/utxo", e.baseUrl, addr))
	if err != nil {
		return nil, err
	}

	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get utxos: %s", string(body))
	}
	utxos := []Utxo{}
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, err
	}

	for i := range utxos {
		utxos[i].Script = hex.EncodeToString(outputScript)
	}

	return utxos, nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos(addr)
	if err != nil {
		return
	}

	lockedBalance = make(map[int64]uint64, 0)
	now := time.Now()
	for _, utxo := range utxos {
		blocktime := now
		if utxo.Status.Confirmed {
			blocktime = time.Unix(utxo.Status.BlockTime, 0)
		}

		delay := time.Duration(unilateralExitDelay.Seconds()) * time.Second
		availableAt := blocktime.Add(delay)
		if availableAt.After(now) {
			if _, ok := lockedBalance[availableAt.Unix()]; !ok {
				lockedBalance[availableAt.Unix()] = 0
			}

			lockedBalance[availableAt.Unix()] += utxo.Amount
		} else {
			spendableBalance += utxo.Amount
		}
	}

	return
}

func (e *explorerSvc) GetTxBlockTime(
	txid string,
) (confirmed bool, blocktime int64, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s", e.baseUrl, txid))
	if err != nil {
		return false, 0, err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("failed to get block time: %s", string(body))
	}

	var tx struct {
		Status struct {
			Confirmed bool  `json:"confirmed"`
			Blocktime int64 `json:"block_time"`
		} `json:"status"`
	}
	if err := json.Unmarshal(body, &tx); err != nil {
		return false, 0, err
	}

	if !tx.Status.Confirmed {
		return false, -1, nil
	}

	return true, tx.Status.Blocktime, nil
}

func (e *explorerSvc) initializeConnectionPool(ctx context.Context, wsURL string) error {
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	// Try to establish connections up to maxConnections
	for i := 0; i < e.maxConnections; i++ {
		conn, _, err := dialer.DialContext(ctx, wsURL, nil)
		if err != nil {
			log.WithError(err).WithFields(log.Fields{
				"connection": i + 1,
				"max":        e.maxConnections,
				"url":        wsURL,
			}).Debug("explorer: failed to establish ws connection")
			break
		}

		e.connPool.addConnection(conn)
		log.WithField("connection", i+1).Debug("explorer: established ws connection")
	}

	if e.connPool.getConnectionCount() == 0 {
		return fmt.Errorf("failed to establish any websocket connections")
	}

	return nil
}

// recordError stores an error for later retrieval (keeps last 100 errors)
func (e *explorerSvc) recordError(err error) {
	if err == nil {
		return
	}

	e.errorsMu.Lock()
	defer e.errorsMu.Unlock()

	e.errorCount++
	e.errors = append(e.errors, err)

	// Keep only last 100 errors to prevent unbounded growth
	if len(e.errors) > 100 {
		e.errors = e.errors[len(e.errors)-100:]
	}
}

func (e *explorerSvc) startTracking(ctx context.Context) {
	// If the ws endpoint is available (mempool.space url), read from websocket and eventually
	// send notifications and periodically send a ping message to keep the connection alive.
	if e.connPool != nil && e.connPool.getConnectionCount() > 0 {
		// Start a listener and ping routine for each connection in the pool
		e.connPool.mu.RLock()
		for i, wsConn := range e.connPool.connections {
			connIndex := i
			conn := wsConn

			// Go routine to listen for addresses updates from websocket.
			go func(ctx context.Context, connIdx int, wsConn *websocketConnection) {
				if err := wsConn.conn.SetReadDeadline(time.Now().Add(pongInterval)); err != nil {
					e.recordError(
						fmt.Errorf("connection %d: failed to set read deadline: %w", connIdx, err),
					)
					log.WithError(err).WithField("connection", connIdx).Error(
						"explorer: failed to set read deadline",
					)
					return
				}
				wsConn.conn.SetPongHandler(func(string) error {
					return wsConn.conn.SetReadDeadline(time.Now().Add(pongInterval))
				})
				for {
					var payload addressNotification
					if err := wsConn.conn.ReadJSON(&payload); err != nil {
						if websocket.IsCloseError(
							err,
							websocket.CloseNormalClosure,
							websocket.CloseGoingAway,
							websocket.CloseAbnormalClosure,
						) ||
							errors.Is(err, net.ErrClosed) {
							return
						}
						e.recordError(fmt.Errorf(
							"connection %d: failed to read address notification: %w", connIdx, err,
						))
						log.WithError(err).WithField("connection", connIdx).Error(
							"explorer: failed to read address notification",
						)
						continue
					}
					// Skip handling the received message if it's not an address update.
					if payload.MultiAddrTx == nil {
						continue
					}

					go e.sendAddressEventFromWs(ctx, payload)
				}
			}(ctx, connIndex, conn)

			// Go routine to periodically send ping messages and keep the connection alive.
			go func(ctx context.Context, connIdx int, wsConn *websocketConnection) {
				ticker := time.NewTicker(pingInterval)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						deadline := time.Now().Add(10 * time.Second)
						if err := wsConn.conn.WriteControl(
							websocket.PingMessage, nil, deadline,
						); err != nil {
							e.recordError(fmt.Errorf(
								"connection %d: failed to ping explorer: %w", connIdx, err,
							))
							log.WithError(err).WithField("connection", connIdx).Error(
								"explorer: failed to ping explorer",
							)
							return
						}
					}
				}
			}(ctx, connIndex, conn)
		}
		e.connPool.mu.RUnlock()

		return
	}

	// Otherwise (esplora url), poll the explorer every 10s and manually send notifications of
	// spent, new and confirmed utxos.
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.subscribedMu.RLock()
			// make a snapshot copy of the map to avoid race conditions
			subscribedMap := make(map[string]addressData, len(e.subscribedMap))
			for addr, data := range e.subscribedMap {
				hashCopy := make([]byte, len(data.hash))
				copy(hashCopy, data.hash)
				utxosCopy := make([]Utxo, len(data.utxos))
				copy(utxosCopy, data.utxos)

				subscribedMap[addr] = addressData{
					hash:  hashCopy,
					utxos: utxosCopy,
				}
			}
			e.subscribedMu.RUnlock()

			if len(subscribedMap) == 0 {
				continue
			}
			for addr, oldUtxos := range subscribedMap {
				newUtxos, err := e.GetUtxos(addr)
				if err != nil {
					e.recordError(fmt.Errorf("polling: failed to get UTXOs for %s: %w", addr, err))
					log.WithError(err).Error("explorer: failed to poll explorer")
				}
				buf, _ := json.Marshal(newUtxos)
				hashedResp := sha256.Sum256(buf)
				if !bytes.Equal(oldUtxos.hash, hashedResp[:]) {
					go e.sendAddressEventFromPolling(ctx, oldUtxos.utxos, newUtxos)
					e.subscribedMu.Lock()
					e.subscribedMap[addr] = addressData{
						hash:  hashedResp[:],
						utxos: newUtxos,
					}
					e.subscribedMu.Unlock()
				}

			}
		case <-ctx.Done():
			return
		}
	}
}

func (e *explorerSvc) sendAddressEventFromWs(ctx context.Context, payload addressNotification) {
	// If there's an error the event message looks like:
	//
	// { "multi-address-transactions": "error message" }
	//
	// The following check makes sure we return an error event message as well so the receiver can
	// handle it properly.
	if errMsg, ok := payload.MultiAddrTx.(string); ok {
		e.sendAddressEvent(ctx, types.OnchainAddressEvent{
			Error: fmt.Errorf("%s", errMsg),
		})
	}

	spentUtxos := make([]types.OnchainOutput, 0)
	newUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	replacements := make(map[string]string)
	for addr, data := range payload.MultiAddrTx.(map[string]txNotificationSet) {
		if len(data.Removed) > 0 {
			for _, tx := range data.Removed {
				if len(data.Mempool) > 0 {
					replacementTxid := data.Mempool[0].Txid
					replacements[tx.Txid] = replacementTxid
				}
			}
			continue
		}
		if len(data.Mempool) > 0 {
			for _, tx := range data.Mempool {
				for _, in := range tx.Inputs {
					if in.Prevout.Address == addr {
						spentUtxos = append(spentUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: in.Txid,
								VOut: uint32(in.Vout),
							},
							SpentBy: tx.Txid,
							Spent:   true,
						})
					}
				}
				for i, out := range tx.Outputs {
					if out.Address == addr {
						var createdAt time.Time
						if tx.Status.Confirmed {
							createdAt = time.Unix(tx.Status.BlockTime, 0)
						}
						newUtxos = append(newUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: createdAt,
						})
					}
				}
			}
		}
		if len(data.Confirmed) > 0 {
			for _, tx := range data.Confirmed {
				for i, out := range tx.Outputs {
					if out.Address == addr {
						confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
							Outpoint: types.Outpoint{
								Txid: tx.Txid,
								VOut: uint32(i),
							},
							Script:    out.Script,
							Amount:    out.Amount,
							CreatedAt: time.Unix(tx.Status.BlockTime, 0),
						})
					}
				}
			}
		}
	}

	e.sendAddressEvent(ctx, types.OnchainAddressEvent{
		NewUtxos:       newUtxos,
		SpentUtxos:     spentUtxos,
		ConfirmedUtxos: confirmedUtxos,
		Replacements:   replacements,
	})
}

func (e *explorerSvc) sendAddressEventFromPolling(ctx context.Context, oldUtxos, newUtxos []Utxo) {
	indexedOldUtxos := make(map[string]Utxo, 0)
	indexedNewUtxos := make(map[string]Utxo, 0)
	for _, oldUtxo := range oldUtxos {
		indexedOldUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)] = oldUtxo
	}
	for _, newUtxo := range newUtxos {
		indexedNewUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)] = newUtxo
	}
	spentUtxos := make([]types.OnchainOutput, 0)
	for _, oldUtxo := range oldUtxos {
		if _, ok := indexedNewUtxos[fmt.Sprintf("%s:%d", oldUtxo.Txid, oldUtxo.Vout)]; !ok {
			var spentBy string
			spentStatus, _ := e.GetTxOutspends(oldUtxo.Txid)
			if len(spentStatus) > int(oldUtxo.Vout) {
				spentBy = spentStatus[oldUtxo.Vout].SpentBy
			}
			spentUtxos = append(spentUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: oldUtxo.Txid,
					VOut: oldUtxo.Vout,
				},
				SpentBy: spentBy,
				Spent:   true,
			})
		}
	}
	receivedUtxos := make([]types.OnchainOutput, 0)
	confirmedUtxos := make([]types.OnchainOutput, 0)
	for _, newUtxo := range newUtxos {
		oldUtxo, ok := indexedOldUtxos[fmt.Sprintf("%s:%d", newUtxo.Txid, newUtxo.Vout)]
		if !ok {
			var createdAt time.Time
			if newUtxo.Status.Confirmed {
				createdAt = time.Unix(newUtxo.Status.BlockTime, 0)
			}
			receivedUtxos = append(receivedUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script:    newUtxo.Script,
				Amount:    newUtxo.Amount,
				CreatedAt: createdAt,
			})
			continue
		}
		if !oldUtxo.Status.Confirmed && newUtxo.Status.Confirmed {
			confirmedUtxos = append(confirmedUtxos, types.OnchainOutput{
				Outpoint: types.Outpoint{
					Txid: newUtxo.Txid,
					VOut: newUtxo.Vout,
				},
				Script:    newUtxo.Script,
				Amount:    newUtxo.Amount,
				CreatedAt: time.Unix(newUtxo.Status.BlockTime, 0),
			})
		}
	}

	if len(spentUtxos) > 0 || len(receivedUtxos) > 0 || len(confirmedUtxos) > 0 {
		e.sendAddressEvent(ctx, types.OnchainAddressEvent{
			SpentUtxos:     spentUtxos,
			NewUtxos:       receivedUtxos,
			ConfirmedUtxos: confirmedUtxos,
		})
	}
}

func (e *explorerSvc) getTxHex(txid string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("%s/tx/%s/hex", e.baseUrl, txid))
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get tx hex: %s", string(body))
	}

	hex := string(body)
	e.cache.Set(txid, hex)
	return hex, nil
}

func (e *explorerSvc) broadcast(txHex string) (string, error) {
	body := bytes.NewBuffer([]byte(txHex))

	resp, err := http.Post(fmt.Sprintf("%s/tx", e.baseUrl), "text/plain", body)
	if err != nil {
		return "", err
	}
	// nolint:all
	defer resp.Body.Close()
	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func (e *explorerSvc) broadcastPackage(txs ...string) (string, error) {
	url := fmt.Sprintf("%s/txs/package", e.baseUrl)

	// body is a json array of txs hex
	body := bytes.NewBuffer(nil)
	if err := json.NewEncoder(body).Encode(txs); err != nil {
		return "", err
	}

	resp, err := http.Post(url, "application/json", body)
	if err != nil {
		return "", err
	}
	// nolint
	defer resp.Body.Close()

	bodyResponse, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to broadcast package: %s", string(bodyResponse))
	}

	return string(bodyResponse), nil
}

func (e *explorerSvc) sendAddressEvent(ctx context.Context, event types.OnchainAddressEvent) {
	select {
	case <-ctx.Done():
		return
	case e.channel <- event:
	}
}

func parseBitcoinTx(txStr string) (string, string, error) {
	var tx wire.MsgTx

	if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(txStr))); err != nil {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(txStr), true)
		if err != nil {
			return "", "", err
		}

		txFromPartial, err := psbt.Extract(ptx)
		if err != nil {
			return "", "", err
		}

		tx = *txFromPartial
	}

	var txBuf bytes.Buffer

	if err := tx.Serialize(&txBuf); err != nil {
		return "", "", err
	}

	txhex := hex.EncodeToString(txBuf.Bytes())
	txid := tx.TxHash().String()

	return txhex, txid, nil
}

func newUtxo(explorerUtxo Utxo, delay arklib.RelativeLocktime, tapscripts []string) types.Utxo {
	utxoTime := explorerUtxo.Status.BlockTime
	createdAt := time.Unix(utxoTime, 0)
	if utxoTime == 0 {
		createdAt = time.Time{}
		utxoTime = time.Now().Unix()
	}

	return types.Utxo{
		Outpoint: types.Outpoint{
			Txid: explorerUtxo.Txid,
			VOut: explorerUtxo.Vout,
		},
		Amount:      explorerUtxo.Amount,
		Delay:       delay,
		SpendableAt: time.Unix(utxoTime, 0).Add(time.Duration(delay.Seconds()) * time.Second),
		CreatedAt:   createdAt,
		Tapscripts:  tapscripts,
	}
}

func deriveWsURL(baseUrl string) (string, error) {
	var wsUrl string

	parsedUrl, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}

	scheme := "ws"
	if parsedUrl.Scheme == "https" {
		scheme = "wss"
	}
	parsedUrl.Scheme = scheme
	wsUrl = strings.TrimRight(parsedUrl.String(), "/")

	wsUrl = fmt.Sprintf("%s/v1/ws", wsUrl)

	return wsUrl, nil
}
