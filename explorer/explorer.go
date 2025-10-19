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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	wallet "github.com/arkade-os/arkd/pkg/wallet"
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

// var (
//	defaultExplorerUrls = utils.SupportedType[string]{
//		arklib.Bitcoin.Name:        "https://mempool.space/api",
//		arklib.BitcoinTestNet.Name: "https://mempool.space/testnet/api",
//		//arklib.BitcoinTestNet4.Name: "https://mempool.space/testnet4/api", //TODO uncomment once supported
//		arklib.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
//		arklib.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
//		arklib.BitcoinRegTest.Name:   "http://localhost:3000",
//	}
// )

// websocketConnection represents a single WebSocket connection with its subscribed addresses.
type websocketConnection struct {
	conn          *websocket.Conn
	addressBucket map[string]bool // Track subscribed addresses for this connection
	mu            sync.RWMutex
}

// connectionPool manages multiple WebSocket connections for load distribution.
// Addresses are distributed across connections using consistent hash-based routing.
type connectionPool struct {
	connections []*websocketConnection
	mu          sync.RWMutex
}

type explorerSvc struct {
	cache          *utils.Cache[string]
	baseUrl        string
	net            arklib.Network
	connPool       *connectionPool
	subscribedMu   *sync.RWMutex
	subscribedMap  map[string]wallet.Utxo
	channel        chan types.OnchainAddressEvent
	stopTracking   func()
	pollInterval   time.Duration
	noTracking     bool
	batchSize      int
	batchDelay     time.Duration
	maxConnections int
}

// Option is a functional option for configuring the Explorer service.
type Option func(*explorerSvc)

// WithPollInterval sets the polling interval for address tracking when WebSocket is unavailable.
// Default: 10 seconds.
func WithPollInterval(interval time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.pollInterval = interval
	}
}

// WithTracker enables or disables address tracking.
// When disabled, the explorer only provides REST API functionality without WebSocket connections.
// Default: tracking is disabled.
func WithTracker(withTracker bool) Option {
	return func(svc *explorerSvc) {
		if !withTracker {
			svc.noTracking = true
		}
	}
}

// WithBatchSize sets the number of addresses to subscribe per batch.
// Batching prevents overwhelming individual WebSocket connections with large subscription requests.
// Default: 50 addresses per batch.
func WithBatchSize(batchSize int) Option {
	return func(svc *explorerSvc) {
		svc.batchSize = batchSize
	}
}

// WithBatchDelay sets the delay between subscription batches.
// This helps rate-limit subscription requests to avoid overwhelming the explorer service.
// Default: 100 milliseconds.
func WithBatchDelay(batchDelay time.Duration) Option {
	return func(svc *explorerSvc) {
		svc.batchDelay = batchDelay
	}
}

// WithMaxConnections sets the maximum number of concurrent WebSocket connections.
// Multiple connections distribute the load and prevent I/O timeouts when subscribing to many addresses.
// Addresses are distributed across connections using consistent hash-based routing.
// Default: 3 connections.
func WithMaxConnections(maxConnections int) Option {
	return func(svc *explorerSvc) {
		svc.maxConnections = maxConnections
	}
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
// func NewExplorer(baseUrl string, net arklib.Network, opts ...Option) (Explorer, error) {
// 	if len(baseUrl) == 0 {
// 		baseUrl, ok := defaultExplorerUrls[net.Name]
// 		if !ok {
// 			return nil, fmt.Errorf(
// 				"cannot find default explorer url associated with network %s",
// 				net.Name,
// 			)
// 		}
// 		return NewExplorer(baseUrl, net, opts...)
// 	}

// 	svcOpts := &explorerSvc{
// 		batchSize:      50,
// 		batchDelay:     100 * time.Millisecond,
// 		maxConnections: 3,
// 	}
// 	for _, opt := range opts {
// 		opt(svcOpts)
// 	}

// 	if svcOpts.noTracking {
// 		return &explorerSvc{
// 			cache:        utils.NewCache[string](),
// 			baseUrl:      baseUrl,
// 			net:          net,
// 			pollInterval: svcOpts.pollInterval,
// 			noTracking:   svcOpts.noTracking,
// 		}, nil
// 	}

// 	wsURL, err := deriveWsURL(baseUrl)
// 	if err != nil {
// 		return nil, fmt.Errorf("invalid base url: %s", err)
// 	}

// 	ctx, cancel := context.WithCancel(context.Background())
// 	svc := &explorerSvc{
// 		cache:           utils.NewCache[string](),
// 		baseUrl:         baseUrl,
// 		net:             net,
// 		connPool:        newConnectionPool(svcOpts.maxConnections),
// 		subscribedMu:    &sync.RWMutex{},
// 		subscribedMap:   make(map[string]addressData),
// 		channel:         make(chan types.OnchainAddressEvent, 100),
// 		stopTracking:    cancel,
// 		pollInterval:    svcOpts.pollInterval,
// 		noTracking:      svcOpts.noTracking,
// 		batchSize:       svcOpts.batchSize,
// 		batchDelay:      svcOpts.batchDelay,
// 		maxConnections:  svcOpts.maxConnections,
// 		addressDedupMap: make(map[string]bool),
// 	}

// 	// Initialize connection pool
// 	if err := svc.initializeConnectionPool(ctx, wsURL); err != nil {
// 		log.WithFields(log.Fields{
// 			"network": net.Name,
// 			"url":     wsURL,
// 		}).WithError(err).Warn("websocket connection pool initialization failed, falling back to polling")
// 	}

// 	if svc.connPool.getConnectionCount() == 0 {
// 		log.Debugf(
// 			"starting explorer background tracking with polling interval %s",
// 			svc.pollInterval,
// 		)
// 	} else {
// 		log.Debugf("starting explorer background tracking with %d websocket connections", svc.connPool.getConnectionCount())
// 	}
// 	go svc.startTracking(ctx)

// 	return svc, nil
// }

func NewExplorer(baseUrl string, net arklib.Network, opts ...Option) (wallet.Explorer, error) {
	return wallet.NewExplorerClient(baseUrl)
}

func (cp *connectionPool) getConnectionCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.connections)
}

func (cp *connectionPool) getConnectionForAddress(address string) (*websocketConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	// Guard against empty connection pool
	n := len(cp.connections)
	if n == 0 {
		return nil, false
	}

	// Use hash-based distribution to consistently assign addresses to connections
	// Use actual number of live connections instead of maxConnections
	hash := sha256.Sum256([]byte(address))
	connectionIndex := int(hash[0]) % n

	return cp.connections[connectionIndex], true
}

func (e *explorerSvc) Stop() {
	if e.noTracking {
		return
	}

	e.stopTracking()

	// Close all connections in the pool
	if e.connPool != nil {
		e.connPool.mu.Lock()
		for _, wsConn := range e.connPool.connections {
			if wsConn.conn != nil {
				if err := wsConn.conn.Close(); err != nil {
					log.WithError(err).Error("failed to close websocket connection")
				}
			}
		}
		e.connPool.mu.Unlock()
	}

	// Clear subscribed addresses map
	e.subscribedMu.Lock()
	e.subscribedMap = make(map[string]wallet.Utxo)
	e.subscribedMu.Unlock()

	// Clear instance-scoped deduplication map

	close(e.channel)
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
		return 0, fmt.Errorf("error getting fee rate: %s", resp.Status)
	}

	if len(response) == 0 {
		return 1, nil
	}

	return response["1"], nil
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

func (e *explorerSvc) GetTransactions(addr string) ([]wallet.Tx, error) {
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
	payload := []wallet.Tx{}
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
		e.subscribedMap[addr] = wallet.Utxo{}
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

		// Get the connection for this address
		wsConn, found := e.connPool.getConnectionForAddress(addr)
		if !found {
			continue // Skip if no available connection
		}

		addressBuckets[wsConn] = append(addressBuckets[wsConn], addr)
	}

	// Track addresses that were successfully subscribed for rollback on error
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

func (e *explorerSvc) GetTxOutspends(txid string) ([]wallet.Utxo, error) {
	// resp, err := http.Get(fmt.Sprintf("%s/tx/%s/outspends", e.baseUrl, txid))
	// if err != nil {
	// 	return nil, err
	// }

	// // nolint:all
	// defer resp.Body.Close()
	// body, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }
	// if resp.StatusCode != http.StatusOK {
	// 	return nil, fmt.Errorf("failed to get txs: %s", string(body))
	// }

	// utxos := make([]wallet.Utxo, 0)
	// if err := json.Unmarshal(body, &utxos); err != nil {
	// 	return nil, err
	// }
	// return utxos, nil
	return nil, fmt.Errorf("not implemented")
}

func (e *explorerSvc) GetUtxos(addr string) ([]wallet.Utxo, error) {
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
	utxos := []wallet.Utxo{}
	if err := json.Unmarshal(body, &utxos); err != nil {
		return nil, err
	}

	for i := range utxos {
		utxos[i].Script = hex.EncodeToString(outputScript)
	}

	return utxos, nil
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
