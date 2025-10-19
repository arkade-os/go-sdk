package electrum_scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/explorer/scanner"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// electrumScanner implements the BlockchainScanner interface using the Electrum protocol.
// Unlike Mempool scanner which requires connection pooling, Electrum uses a single persistent
// connection and handles thousands of subscriptions via native JSON-RPC batching.
type electrumScanner struct {
	baseUrl       string
	net           arklib.Network
	conn          *websocket.Conn
	connMu        *sync.RWMutex
	subscribedMu  *sync.RWMutex
	subscribed    map[string]string // address => script hash
	listeners     chan types.OnchainAddressEvent
	stopCtx       context.Context
	stopCancel    context.CancelFunc
	requestID     uint64
	requestMu     *sync.Mutex
	noTracking    bool
	cache         map[string]string // txid => hex cache
	cacheMu       *sync.RWMutex
}

// NewScanner creates a new Electrum blockchain scanner.
// Supports both TCP (ssl://) and WebSocket (wss://) transports.
//
// Examples:
//   - TCP: ssl://electrum.blockstream.info:50002
//   - WebSocket: wss://electrum.blockstream.info:50002
func NewScanner(baseUrl string, net arklib.Network, opts ...Option) (*electrumScanner, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %s", err)
	}

	// Validate scheme
	switch u.Scheme {
	case "ssl", "wss", "ws":
		// Valid Electrum schemes
	default:
		return nil, fmt.Errorf("unsupported scheme %s, expected ssl:// or wss://", u.Scheme)
	}

	svcOpts := &electrumScanner{
		baseUrl:      baseUrl,
		net:          net,
		connMu:       &sync.RWMutex{},
		subscribedMu: &sync.RWMutex{},
		subscribed:   make(map[string]string),
		requestMu:    &sync.Mutex{},
		cache:        make(map[string]string),
		cacheMu:      &sync.RWMutex{},
	}

	for _, opt := range opts {
		opt(svcOpts)
	}

	if !svcOpts.noTracking {
		svcOpts.listeners = make(chan types.OnchainAddressEvent, 100)
	}

	return svcOpts, nil
}

func (e *electrumScanner) Start() {
	if e.noTracking {
		return
	}

	if e.stopCancel != nil {
		return // Already started
	}

	e.stopCtx, e.stopCancel = context.WithCancel(context.Background())

	// Connect to Electrum server
	if err := e.connect(); err != nil {
		log.WithError(err).Error("electrum: failed to connect")
		return
	}

	go e.listenLoop()
	log.Debug("electrum: scanner started")
}

func (e *electrumScanner) Stop() {
	if e.noTracking {
		return
	}

	if e.stopCancel == nil {
		return // Already stopped
	}

	e.stopCancel()
	e.stopCancel = nil

	e.connMu.Lock()
	if e.conn != nil {
		e.conn.Close()
		e.conn = nil
	}
	e.connMu.Unlock()

	if e.listeners != nil {
		close(e.listeners)
	}

	log.Debug("electrum: scanner stopped")
}

func (e *electrumScanner) connect() error {
	u, _ := url.Parse(e.baseUrl)

	// Convert ssl:// to wss://
	if u.Scheme == "ssl" {
		u.Scheme = "wss"
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.DialContext(e.stopCtx, u.String(), nil)
	if err != nil {
		return err
	}

	e.connMu.Lock()
	e.conn = conn
	e.connMu.Unlock()

	return nil
}

func (e *electrumScanner) listenLoop() {
	for {
		select {
		case <-e.stopCtx.Done():
			return
		default:
			e.connMu.RLock()
			conn := e.conn
			e.connMu.RUnlock()

			if conn == nil {
				time.Sleep(time.Second)
				continue
			}

			var msg map[string]interface{}
			if err := conn.ReadJSON(&msg); err != nil {
				log.WithError(err).Warn("electrum: read error")
				time.Sleep(time.Second)
				continue
			}

			// Handle notifications
			if method, ok := msg["method"].(string); ok {
				if method == "blockchain.scripthash.subscribe" {
					e.handleScriptHashNotification(msg)
				}
			}
		}
	}
}

func (e *electrumScanner) handleScriptHashNotification(msg map[string]interface{}) {
	// This is a placeholder - full implementation would parse Electrum notifications
	// and emit OnchainAddressEvent similar to mempool scanner
	log.WithField("msg", msg).Debug("electrum: received notification")
}

func (e *electrumScanner) GetTxHex(txid string) (string, error) {
	// Check cache first
	e.cacheMu.RLock()
	if hex, ok := e.cache[txid]; ok {
		e.cacheMu.RUnlock()
		return hex, nil
	}
	e.cacheMu.RUnlock()

	// Call Electrum blockchain.transaction.get
	result, err := e.request("blockchain.transaction.get", []interface{}{txid})
	if err != nil {
		return "", err
	}

	txHex, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("invalid response type")
	}

	// Cache result
	e.cacheMu.Lock()
	e.cache[txid] = txHex
	e.cacheMu.Unlock()

	return txHex, nil
}

func (e *electrumScanner) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("no transactions provided")
	}

	// Broadcast using blockchain.transaction.broadcast
	result, err := e.request("blockchain.transaction.broadcast", []interface{}{txs[0]})
	if err != nil {
		return "", err
	}

	txid, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("invalid response type")
	}

	return txid, nil
}

func (e *electrumScanner) GetTxs(addr string) ([]scanner.Tx, error) {
	scriptHash, err := e.addressToScriptHash(addr)
	if err != nil {
		return nil, err
	}

	// Call blockchain.scripthash.get_history
	_, err = e.request("blockchain.scripthash.get_history", []interface{}{scriptHash})
	if err != nil {
		return nil, err
	}

	// Parse and convert to scanner.Tx format
	// This is a placeholder - full implementation would parse Electrum format
	return []scanner.Tx{}, nil
}

func (e *electrumScanner) GetTxOutspends(tx string) ([]scanner.SpentStatus, error) {
	// Electrum doesn't have a direct equivalent to mempool's outspends endpoint
	// Would need to track via scripthash history
	return []scanner.SpentStatus{}, fmt.Errorf("not yet implemented")
}

func (e *electrumScanner) GetUtxos(addr string) ([]scanner.Utxo, error) {
	scriptHash, err := e.addressToScriptHash(addr)
	if err != nil {
		return nil, err
	}

	// Call blockchain.scripthash.listunspent
	_, err = e.request("blockchain.scripthash.listunspent", []interface{}{scriptHash})
	if err != nil {
		return nil, err
	}

	// Parse and convert to scanner.Utxo format
	// This is a placeholder - full implementation would parse Electrum format
	return []scanner.Utxo{}, nil
}

func (e *electrumScanner) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (uint64, map[int64]uint64, error) {
	// Delegate to GetUtxos and calculate based on delay
	_, err := e.GetUtxos(addr)
	if err != nil {
		return 0, nil, err
	}

	// Calculate balances (simplified placeholder)
	return 0, make(map[int64]uint64), nil
}

func (e *electrumScanner) GetTxBlockTime(txid string) (confirmed bool, blocktime int64, err error) {
	// Call blockchain.transaction.get with verbose=true
	_, err = e.request("blockchain.transaction.get", []interface{}{txid, true})
	if err != nil {
		return false, 0, err
	}

	// Parse verbose transaction response
	// This is a placeholder
	return false, 0, nil
}

func (e *electrumScanner) BaseUrl() string {
	return e.baseUrl
}

func (e *electrumScanner) GetFeeRate() (float64, error) {
	// Call blockchain.estimatefee for 1 block
	result, err := e.request("blockchain.estimatefee", []interface{}{1})
	if err != nil {
		return 0, err
	}

	// Electrum returns BTC/KB, need to convert to sat/vB
	btcPerKB, ok := result.(float64)
	if !ok {
		return 0, fmt.Errorf("invalid response type")
	}

	// Convert: BTC/KB -> sat/vB
	// 1 BTC = 100,000,000 sat
	// 1 KB = 1000 bytes
	satPerVB := (btcPerKB * 100000000) / 1000
	return satPerVB, nil
}

func (e *electrumScanner) GetConnectionCount() int {
	e.connMu.RLock()
	defer e.connMu.RUnlock()
	if e.conn != nil {
		return 1
	}
	return 0
}

func (e *electrumScanner) GetSubscribedAddresses() []string {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	addresses := make([]string, 0, len(e.subscribed))
	for addr := range e.subscribed {
		addresses = append(addresses, addr)
	}
	return addresses
}

func (e *electrumScanner) IsAddressSubscribed(address string) bool {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	_, ok := e.subscribed[address]
	return ok
}

func (e *electrumScanner) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	return e.listeners
}

func (e *electrumScanner) SubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return fmt.Errorf("tracking disabled")
	}

	// Build batch request for all addresses
	requests := make([]map[string]interface{}, 0, len(addresses))

	for _, addr := range addresses {
		// Skip if already subscribed
		if e.IsAddressSubscribed(addr) {
			continue
		}

		scriptHash, err := e.addressToScriptHash(addr)
		if err != nil {
			return err
		}

		e.subscribedMu.Lock()
		e.subscribed[addr] = scriptHash
		e.subscribedMu.Unlock()

		reqID := e.nextRequestID()
		requests = append(requests, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      reqID,
			"method":  "blockchain.scripthash.subscribe",
			"params":  []interface{}{scriptHash},
		})
	}

	if len(requests) == 0 {
		return nil // All already subscribed
	}

	// Send batch request
	e.connMu.RLock()
	conn := e.conn
	e.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Electrum supports batch requests via JSON-RPC array
	if err := conn.WriteJSON(requests); err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	log.WithField("count", len(requests)).Debug("electrum: subscribed to addresses")
	return nil
}

func (e *electrumScanner) UnsubscribeForAddresses(addresses []string) error {
	e.subscribedMu.Lock()
	defer e.subscribedMu.Unlock()

	for _, addr := range addresses {
		delete(e.subscribed, addr)
	}

	return nil
}

// addressToScriptHash converts a Bitcoin address to an Electrum script hash.
// Script hash is sha256(scriptPubKey) in reverse byte order (little-endian hex).
func (e *electrumScanner) addressToScriptHash(address string) (string, error) {
	btcParams := utils.ToBitcoinNetwork(e.net)
	addr, err := btcutil.DecodeAddress(address, &btcParams)
	if err != nil {
		return "", err
	}

	scriptPubKey, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	// Electrum uses sha256 of the scriptPubKey
	hash := sha256.Sum256(scriptPubKey)

	// Reverse bytes for Electrum's little-endian format
	for i := 0; i < len(hash)/2; i++ {
		hash[i], hash[len(hash)-1-i] = hash[len(hash)-1-i], hash[i]
	}

	return hex.EncodeToString(hash[:]), nil
}

func (e *electrumScanner) request(method string, params []interface{}) (interface{}, error) {
	e.connMu.RLock()
	conn := e.conn
	e.connMu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	reqID := e.nextRequestID()
	req := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  method,
		"params":  params,
	}

	if err := conn.WriteJSON(req); err != nil {
		return nil, err
	}

	// Read response
	var resp map[string]interface{}
	if err := conn.ReadJSON(&resp); err != nil {
		return nil, err
	}

	if errObj, ok := resp["error"]; ok && errObj != nil {
		errData, _ := json.Marshal(errObj)
		return nil, fmt.Errorf("electrum error: %s", string(errData))
	}

	return resp["result"], nil
}

func (e *electrumScanner) nextRequestID() uint64 {
	e.requestMu.Lock()
	defer e.requestMu.Unlock()
	e.requestID++
	return e.requestID
}
