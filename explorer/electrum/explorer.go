// See doc.go for the package-level overview, lifecycle, reconnection model,
// and restart/restore semantics.
package electrum_explorer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

type addressState struct {
	mu         sync.Mutex // serializes concurrent pollAddress calls for this address
	scripthash string
	utxos      []electrumUTXO
	// notifCh is the channel returned by client.subscribe(); nil when noTracking.
	notifCh <-chan string
}

type explorerSvc struct {
	client     *electrumClient
	serverURL  string
	esploraURL string // optional HTTP REST base URL for package broadcasts
	netParams  *chaincfg.Params

	noTracking   bool
	pollInterval time.Duration

	subscribedMu  sync.RWMutex
	subscribedMap map[string]*addressState // address => state
	// subscribingSet holds addresses currently being subscribed (reservation
	// held while the RPC is in flight). Protected by subscribedMu. Prevents
	// concurrent goroutines from racing to subscribe the same address, which
	// would orphan notification channels and cause Stop() to deadlock.
	subscribingSet map[string]struct{}
	// stopped is set to true by Stop() under subscribedMu before draining
	// subscribedMap. SubscribeForAddresses checks this flag (also under
	// subscribedMu) before calling notifWg.Add(1), preventing a race between
	// Add and the Wait() call in Stop().
	stopped bool

	// notifWg tracks the per-address goroutines spawned in SubscribeForAddresses.
	// Stop() waits on this before returning to ensure no goroutine outlives the svc.
	notifWg sync.WaitGroup

	// reverse lookup: scripthash => address
	scripthashToAddr   map[string]string
	scripthashToAddrMu sync.RWMutex

	startOnce    sync.Once
	stopTracking func()
	listeners    *listeners

	cacheMu sync.RWMutex
	cache   map[string]string // txid => hex; bounded to txCacheMaxSize entries
}

const txCacheMaxSize = 1024

// NewExplorer creates a new ElectrumX-backed Explorer.
// serverURL must begin with "tcp://" or "ssl://".
// Connection is established lazily when Start() is called.
func NewExplorer(serverURL string, net arklib.Network, opts ...Option) (explorer.Explorer, error) {
	if !strings.HasPrefix(serverURL, "tcp://") && !strings.HasPrefix(serverURL, "ssl://") {
		return nil, fmt.Errorf("electrum server url must start with tcp:// or ssl://")
	}

	svc := &explorerSvc{
		client:           newElectrumClient(serverURL),
		serverURL:        serverURL,
		netParams:        networkToChainParams(net),
		noTracking:       true, // default off; WithTracker(true) enables
		pollInterval:     10 * time.Second,
		subscribedMap:    make(map[string]*addressState),
		subscribingSet:   make(map[string]struct{}),
		scripthashToAddr: make(map[string]string),
		listeners:        newListeners(), // always initialised so GetAddressesEvents channels are closed on Stop
		cache:            make(map[string]string),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc, nil
}

func networkToChainParams(net arklib.Network) *chaincfg.Params {
	switch net.Name {
	case arklib.BitcoinTestNet.Name:
		return &chaincfg.TestNet3Params
	case arklib.BitcoinSigNet.Name:
		return &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		mutinyParams := arklib.MutinyNetSigNetParams
		return &mutinyParams
	case arklib.BitcoinRegTest.Name:
		return &chaincfg.RegressionNetParams
	default:
		return &chaincfg.MainNetParams
	}
}

// Start dials the ElectrumX server, performs the server.version handshake,
// and (if tracking is enabled via WithTracker(true)) launches the poll loop
// over subscribed addresses.
//
// If the initial connect fails Start does NOT return an error; it logs a
// warning and spawns a background goroutine that retries via the same
// exponential-backoff reconnect path used after a mid-life disconnect.
//
// Concurrency: idempotent. Concurrent Start() calls are safe; only the
// first call dials and launches goroutines.
func (e *explorerSvc) Start() {
	e.startOnce.Do(func() {
		if err := e.client.connect(); err != nil {
			log.WithError(err).
				Warn("electrum explorer: initial connect failed, retrying in background")
			go func() {
				if err := e.client.reconnect(); err != nil {
					log.WithError(err).Error("electrum explorer: background reconnect failed")
				}
			}()
		}

		if e.noTracking {
			return
		}

		stopCh := make(chan struct{})
		e.stopTracking = sync.OnceFunc(func() { close(stopCh) })
		go e.pollLoop(stopCh)
		log.Debug("electrum explorer: started")
	})
}

// Stop terminates the explorer in this order:
//
//  1. Closes the poll-loop stop channel; pollLoop returns on its next tick.
//  2. Calls client.shutdown(); cancels the root context, closes the live
//     conn, and drains in-flight pending requests so callers fail fast.
//  3. Calls unsubscribeLocal for every subscribed address; closes each
//     per-address notif channel, causing the per-address consumer goroutine
//     spawned in SubscribeForAddresses to exit.
//  4. Waits on notifWg until every per-address consumer has exited.
//  5. Clears the listeners hub; closes every consumer event channel.
//
// Concurrency: not safe to call concurrently with itself. Safe to call
// concurrently with one-shot RPC methods (GetTxHex, etc.); those will see
// "connection closed" errors as part of step 2.
func (e *explorerSvc) Stop() {
	if e.stopTracking != nil {
		e.stopTracking()
		e.stopTracking = nil
	}
	e.client.shutdown()

	// Set stopped and drain subscribedMap under the same lock so that any
	// concurrent SubscribeForAddresses call sees stopped=true before calling
	// notifWg.Add(1), preventing a race with the notifWg.Wait() below.
	e.subscribedMu.Lock()
	e.stopped = true
	for _, state := range e.subscribedMap {
		e.client.unsubscribeLocal(state.scripthash)
	}
	e.subscribedMap = make(map[string]*addressState)
	e.subscribedMu.Unlock()

	e.notifWg.Wait()

	e.listeners.clear()

	e.scripthashToAddrMu.Lock()
	e.scripthashToAddr = make(map[string]string)
	e.scripthashToAddrMu.Unlock()

	log.Debug("electrum explorer: stopped")
}

func (e *explorerSvc) BaseUrl() string { return e.serverURL }

func (e *explorerSvc) GetConnectionCount() int {
	if e.client.isConnected() {
		return 1
	}
	return 0
}

func (e *explorerSvc) GetSubscribedAddresses() []string {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	return slices.Collect(maps.Keys(e.subscribedMap))
}

func (e *explorerSvc) IsAddressSubscribed(address string) bool {
	e.subscribedMu.RLock()
	defer e.subscribedMu.RUnlock()
	_, ok := e.subscribedMap[address]
	return ok
}

func (e *explorerSvc) GetAddressesEvents() <-chan types.OnchainAddressEvent {
	ch := make(chan types.OnchainAddressEvent, 8)
	e.listeners.add(ch)
	return ch
}

func (e *explorerSvc) GetTxHex(txid string) (string, error) {
	e.cacheMu.RLock()
	if h, ok := e.cache[txid]; ok {
		e.cacheMu.RUnlock()
		return h, nil
	}
	e.cacheMu.RUnlock()

	result, err := e.client.request("blockchain.transaction.get", []any{txid, false})
	if err != nil {
		return "", err
	}
	var txHex string
	if err := json.Unmarshal(result, &txHex); err != nil {
		return "", err
	}
	e.setCacheTx(txid, txHex)
	return txHex, nil
}

// setCacheTx stores a txid→hex mapping, evicting a random entry if the cache
// is at capacity to keep memory bounded.
func (e *explorerSvc) setCacheTx(txid, hex string) {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	if _, exists := e.cache[txid]; !exists && len(e.cache) >= txCacheMaxSize {
		for k := range e.cache {
			delete(e.cache, k)
			break
		}
	}
	e.cache[txid] = hex
}

// Broadcast broadcasts one or more raw transactions sequentially.
// Returns the txid of the first transaction. Multiple txs are not atomic.
func (e *explorerSvc) Broadcast(txs ...string) (string, error) {
	if len(txs) == 0 {
		return "", fmt.Errorf("no txs to broadcast")
	}

	// When broadcasting a package (multiple transactions), use the esplora REST
	// /txs/package endpoint if configured. This is required for v3 transactions
	// that carry a zero-fee P2A anchor output: Bitcoin Core's sendrawtransaction
	// rejects them individually, but submitpackage (which /txs/package calls)
	// accepts the parent+child together.
	if len(txs) > 1 && e.esploraURL != "" {
		return e.broadcastPackage(txs...)
	}

	var firstTxid string
	for i, tx := range txs {
		txHex, txid, err := parseBitcoinTx(tx)
		if err != nil {
			return "", fmt.Errorf("tx %d: %w", i, err)
		}

		result, err := e.client.request("blockchain.transaction.broadcast", []any{txHex})
		if err != nil {
			if strings.Contains(
				strings.ToLower(err.Error()),
				"transaction already in block chain",
			) {
				// Tx is confirmed on-chain; safe to cache.
				e.setCacheTx(txid, txHex)
				if i == 0 {
					firstTxid = txid
				}
				continue
			}
			return "", err
		}
		// Cache only after a successful broadcast to avoid false positives on failure.
		e.setCacheTx(txid, txHex)

		var returnedTxid string
		// nolint
		json.Unmarshal(result, &returnedTxid)
		if returnedTxid == "" {
			returnedTxid = txid
		}
		if i == 0 {
			firstTxid = returnedTxid
		}
	}
	return firstTxid, nil
}

// broadcastPackage submits multiple transactions as a single package via the
// esplora REST API (POST /txs/package → Bitcoin Core submitpackage). This is
// the only way to broadcast a zero-fee v3 parent with a CPFP child that
// provides the fee.
func (e *explorerSvc) broadcastPackage(txs ...string) (string, error) {
	type parsedTx struct{ txid, txHex string }
	parsed := make([]parsedTx, 0, len(txs))
	hexes := make([]string, 0, len(txs))
	for i, tx := range txs {
		txHex, txid, err := parseBitcoinTx(tx)
		if err != nil {
			return "", fmt.Errorf("tx %d: %w", i, err)
		}
		hexes = append(hexes, txHex)
		parsed = append(parsed, parsedTx{txid, txHex})
	}

	body, err := json.Marshal(hexes)
	if err != nil {
		return "", fmt.Errorf("package marshal: %w", err)
	}

	url := strings.TrimRight(e.esploraURL, "/") + "/txs/package"
	resp, err := http.Post(url, "application/json", bytes.NewReader(body)) // nolint
	if err != nil {
		return "", fmt.Errorf("package broadcast: %w", err)
	}
	defer resp.Body.Close() // nolint

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("package broadcast failed (%d): %s", resp.StatusCode, respBody)
	}

	// The response is a JSON object describing per-tx results. We don't parse
	// it in detail — success is indicated by a 200 status. Return the first txid.
	for _, p := range parsed {
		e.setCacheTx(p.txid, p.txHex)
	}
	return parsed[0].txid, nil
}

func (e *explorerSvc) GetTxs(addr string) ([]explorer.Tx, error) {
	sh, err := addressToScripthash(addr, e.netParams)
	if err != nil {
		return nil, err
	}
	result, err := e.client.request("blockchain.scripthash.get_history", []any{sh})
	if err != nil {
		return nil, err
	}
	var history []electrumHistoryEntry
	if err := json.Unmarshal(result, &history); err != nil {
		return nil, err
	}

	// Electrs versions that don't index P2TR scripts return an empty history for
	// taproot addresses. Fall back to the esplora REST API when configured.
	if len(history) == 0 && e.esploraURL != "" {
		return e.esploraGetTxs(addr)
	}

	txs := make([]explorer.Tx, 0, len(history))
	for _, entry := range history {
		txHex, err := e.GetTxHex(entry.TxHash)
		if err != nil {
			return nil, err
		}
		tx, err := decodeBitcoinTx(txHex)
		if err != nil {
			return nil, err
		}
		confirmed := entry.Height > 0
		var blocktime int64
		if confirmed {
			blocktime, _ = e.blockTimestamp(entry.Height)
		}
		txs = append(txs, wireTxToExplorerTx(entry.TxHash, tx, blocktime, confirmed, e.netParams))
	}
	return txs, nil
}

// GetTxOutspends returns the spent status of each output of a transaction.
// There is no direct ElectrumX equivalent; this resolves by scanning
// the scripthash history of each output. This is O(outputs × history_depth)
// round-trips, which is acceptable for low-traffic Ark outputs.
func (e *explorerSvc) GetTxOutspends(txid string) ([]explorer.SpentStatus, error) {
	txHex, err := e.GetTxHex(txid)
	if err != nil {
		return nil, err
	}
	tx, err := decodeBitcoinTx(txHex)
	if err != nil {
		return nil, err
	}
	result := make([]explorer.SpentStatus, len(tx.TxOut))
	for i, out := range tx.TxOut {
		script := hex.EncodeToString(out.PkScript)
		if script == "" {
			continue
		}
		sh, err := scriptToScripthash(script)
		if err != nil {
			log.WithError(err).
				Debugf("electrum: scriptToScripthash failed for output %d of %s", i, txid)
			continue
		}
		histResult, err := e.client.request("blockchain.scripthash.get_history", []any{sh})
		if err != nil {
			return nil, fmt.Errorf("get_history for output %d of %s: %w", i, txid, err)
		}
		var history []electrumHistoryEntry
		if err := json.Unmarshal(histResult, &history); err != nil {
			log.WithError(err).
				Debugf("electrum: unmarshal history failed for output %d of %s", i, txid)
			continue
		}
		for _, entry := range history {
			if entry.TxHash == txid {
				continue
			}
			spendingHex, err := e.GetTxHex(entry.TxHash)
			if err != nil {
				continue
			}
			spendingTx, err := decodeBitcoinTx(spendingHex)
			if err != nil {
				continue
			}
			for _, vin := range spendingTx.TxIn {
				if vin.PreviousOutPoint.Hash.String() == txid &&
					vin.PreviousOutPoint.Index == uint32(i) {
					result[i] = explorer.SpentStatus{Spent: true, SpentBy: entry.TxHash}
					break
				}
			}
			if result[i].Spent {
				break
			}
		}
	}
	return result, nil
}

func (e *explorerSvc) GetUtxos(addresses []string) ([]explorer.Utxo, error) {
	btCache := make(map[int64]int64)
	var utxos []explorer.Utxo
	for _, addr := range addresses {
		sh, err := addressToScripthash(addr, e.netParams)
		if err != nil {
			return nil, err
		}
		script, err := addrToScript(addr, e.netParams)
		if err != nil {
			return nil, err
		}
		electrumUtxos, err := e.listUnspent(sh)
		if err != nil {
			return nil, err
		}
		if len(electrumUtxos) == 0 && e.esploraURL != "" {
			if fallback, ferr := e.esploraListUnspent(addr); ferr == nil {
				electrumUtxos = fallback
			} else {
				log.WithError(ferr).Debugf("electrum: esplora utxo fallback failed for %s", addr)
			}
		}
		for _, u := range electrumUtxos {
			var blocktime int64
			confirmed := u.Height > 0
			if confirmed {
				if t, ok := btCache[u.Height]; ok {
					blocktime = t
				} else {
					blocktime, _ = e.blockTimestamp(u.Height)
					btCache[u.Height] = blocktime
				}
			}
			utxos = append(utxos, explorer.Utxo{
				Txid:   u.TxHash,
				Vout:   u.TxPos,
				Amount: u.Value,
				Script: script,
				Status: explorer.ConfirmedStatus{Confirmed: confirmed, BlockTime: blocktime},
			})
		}
	}
	return utxos, nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos([]string{addr})
	if err != nil {
		return
	}
	lockedBalance = make(map[int64]uint64)
	now := time.Now()
	for _, utxo := range utxos {
		blocktime := now
		if utxo.Status.Confirmed {
			blocktime = time.Unix(utxo.Status.BlockTime, 0)
		}
		availableAt := blocktime.Add(time.Duration(unilateralExitDelay.Seconds()) * time.Second)
		if availableAt.After(now) {
			lockedBalance[availableAt.Unix()] += utxo.Amount
		} else {
			spendableBalance += utxo.Amount
		}
	}
	return
}

func (e *explorerSvc) GetTxBlockTime(txid string) (confirmed bool, blocktime int64, err error) {
	// blockchain.transaction.get does not return blocktime directly, so we decode
	// the raw TX to get an output script, then look up the tx in the scripthash
	// history to determine block height.
	txHex, err := e.GetTxHex(txid)
	if err != nil {
		return false, 0, err
	}
	tx, err := decodeBitcoinTx(txHex)
	if err != nil {
		return false, 0, err
	}
	if len(tx.TxOut) == 0 {
		return false, 0, nil
	}
	// Ark txs always have a spendable output first, so TxOut[0] is never OP_RETURN.
	script := hex.EncodeToString(tx.TxOut[0].PkScript)
	sh, err := scriptToScripthash(script)
	if err != nil {
		return false, 0, err
	}
	histResult, err := e.client.request("blockchain.scripthash.get_history", []any{sh})
	if err != nil {
		return false, 0, err
	}
	var history []electrumHistoryEntry
	if err := json.Unmarshal(histResult, &history); err != nil {
		return false, 0, err
	}
	for _, entry := range history {
		if entry.TxHash != txid || entry.Height <= 0 {
			continue
		}
		bt, err := e.blockTimestamp(entry.Height)
		if err != nil {
			return false, 0, err
		}
		return true, bt, nil
	}
	return false, 0, nil
}

func (e *explorerSvc) GetFeeRate() (float64, error) {
	result, err := e.client.request("blockchain.estimatefee", []any{1})
	if err != nil {
		return 1, err
	}
	var btcPerKB float64
	if err := json.Unmarshal(result, &btcPerKB); err != nil {
		return 1, err
	}
	if btcPerKB <= 0 {
		return 1, nil
	}
	// BTC/kB → sat/vB
	return btcPerKB * 1e8 / 1000, nil
}

// SubscribeForAddresses subscribes to ElectrumX push notifications.
// A background goroutine per address forwards notifications into the polling loop
// by triggering an immediate poll when ElectrumX reports a state change.
func (e *explorerSvc) SubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}
	for _, addr := range addresses {
		// Reserve the address slot before doing expensive work. subscribingSet
		// prevents a second concurrent goroutine from racing through subscribe
		// for the same address, which would orphan notification channels and
		// cause Stop() to deadlock on notifWg.Wait().
		e.subscribedMu.Lock()
		_, already := e.subscribedMap[addr]
		_, inFlight := e.subscribingSet[addr]
		if already || inFlight {
			e.subscribedMu.Unlock()
			continue
		}
		e.subscribingSet[addr] = struct{}{}
		e.subscribedMu.Unlock()

		sh, err := addressToScripthash(addr, e.netParams)
		if err != nil {
			e.subscribedMu.Lock()
			delete(e.subscribingSet, addr)
			e.subscribedMu.Unlock()
			return fmt.Errorf("invalid address %s: %w", addr, err)
		}
		notifCh, err := e.client.subscribe(sh)
		if err != nil {
			e.subscribedMu.Lock()
			delete(e.subscribingSet, addr)
			e.subscribedMu.Unlock()
			return fmt.Errorf("failed to subscribe for %s: %w", addr, err)
		}

		// Move notifWg.Add(1) inside subscribedMu so it is serialised with
		// Stop()'s stopped=true assignment. This prevents a race between Add
		// and the notifWg.Wait() call in Stop().
		e.subscribedMu.Lock()
		delete(e.subscribingSet, addr)
		if e.stopped {
			e.subscribedMu.Unlock()
			return fmt.Errorf("electrum explorer is stopped")
		}
		// Start with nil so pollAddress treats all current UTXOs as new on first
		// poll. Capturing initialUTXOs before subscribe risks a race where funds
		// arrive during a retry delay and get silently absorbed as the baseline.
		state := &addressState{scripthash: sh, utxos: nil, notifCh: notifCh}
		e.subscribedMap[addr] = state
		e.notifWg.Add(1)
		e.subscribedMu.Unlock()

		e.scripthashToAddrMu.Lock()
		e.scripthashToAddr[sh] = addr
		e.scripthashToAddrMu.Unlock()

		// When ElectrumX pushes a notification for this scripthash, immediately poll
		// the address rather than waiting for the next ticker cycle. The initial
		// pollAddress call establishes the UTXO baseline so that the first push
		// notification correctly detects changes rather than comparing against nil.
		go func(addr, sh string, notifCh <-chan string) {
			defer e.notifWg.Done()
			e.pollAddress(addr, sh)
			for range notifCh {
				e.pollAddress(addr, sh)
			}
		}(addr, sh, notifCh)
	}
	return nil
}

func (e *explorerSvc) UnsubscribeForAddresses(addresses []string) error {
	if e.noTracking {
		return nil
	}
	for _, addr := range addresses {
		e.subscribedMu.Lock()
		state, ok := e.subscribedMap[addr]
		if ok {
			delete(e.subscribedMap, addr)
		}
		e.subscribedMu.Unlock()
		if ok {
			e.scripthashToAddrMu.Lock()
			delete(e.scripthashToAddr, state.scripthash)
			e.scripthashToAddrMu.Unlock()
			e.client.unsubscribeLocal(state.scripthash)
		}
	}
	return nil
}

// pollLoop periodically polls all subscribed addresses for UTXO changes.
// ElectrumX push notifications trigger immediate polls via pollAddress.
func (e *explorerSvc) pollLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			e.pollAll()
		}
	}
}

func (e *explorerSvc) pollAll() {
	e.subscribedMu.RLock()
	snapshot := make(map[string]string, len(e.subscribedMap))
	for addr, state := range e.subscribedMap {
		snapshot[addr] = state.scripthash
	}
	e.subscribedMu.RUnlock()

	for addr, sh := range snapshot {
		e.pollAddress(addr, sh)
	}
}

func (e *explorerSvc) pollAddress(addr, scripthash string) {
	e.subscribedMu.RLock()
	state, ok := e.subscribedMap[addr]
	e.subscribedMu.RUnlock()
	if !ok {
		return
	}

	// Serialize concurrent polls for the same address so that two goroutines
	// cannot both read state.utxos, independently decide there is a diff, and
	// then each broadcast a partial or duplicated event.
	state.mu.Lock()
	defer state.mu.Unlock()

	newUTXOs, err := e.listUnspent(scripthash)
	if err != nil {
		log.WithError(err).Errorf("electrum: poll failed for %s", addr)
		go e.listeners.broadcast(types.OnchainAddressEvent{
			Error: fmt.Errorf("failed to poll %s: %w", addr, err),
		})
		return
	}
	if len(newUTXOs) == 0 && e.esploraURL != "" {
		if fallback, ferr := e.esploraListUnspent(addr); ferr == nil {
			newUTXOs = fallback
		} else {
			log.WithError(ferr).Debugf("electrum: esplora poll fallback failed for %s", addr)
		}
	}

	script, err := addrToScript(addr, e.netParams)
	if err != nil {
		log.WithError(err).Errorf("electrum: failed to derive script for %s", addr)
		return
	}
	event, changed := diffUTXOs(state.utxos, newUTXOs, script)
	if !changed {
		return
	}

	// Build outpoint → electrumUTXO lookup for height-based enrichment.
	newByOutpoint := make(map[types.Outpoint]electrumUTXO, len(newUTXOs))
	for _, u := range newUTXOs {
		newByOutpoint[types.Outpoint{Txid: u.TxHash, VOut: u.TxPos}] = u
	}

	// Cache block header timestamps to avoid redundant RPC calls within one poll.
	btCache := make(map[int64]int64)
	blocktime := func(height int64) time.Time {
		if height <= 0 {
			return time.Time{}
		}
		if t, ok := btCache[height]; ok {
			return time.Unix(t, 0)
		}
		t, err := e.blockTimestamp(height)
		if err != nil {
			return time.Time{}
		}
		btCache[height] = t
		return time.Unix(t, 0)
	}

	// Populate CreatedAt for newly seen UTXOs that are already confirmed.
	for i := range event.NewUtxos {
		if eu, ok := newByOutpoint[event.NewUtxos[i].Outpoint]; ok && eu.Height > 0 {
			event.NewUtxos[i].CreatedAt = blocktime(eu.Height)
		}
	}

	// Populate CreatedAt for UTXOs that just confirmed (unconfirmed → confirmed).
	for i := range event.ConfirmedUtxos {
		if eu, ok := newByOutpoint[event.ConfirmedUtxos[i].Outpoint]; ok && eu.Height > 0 {
			event.ConfirmedUtxos[i].CreatedAt = blocktime(eu.Height)
		}
	}

	// Populate SpentBy by querying the outspend status of each spent UTXO.
	for i := range event.SpentUtxos {
		op := event.SpentUtxos[i].Outpoint
		statuses, err := e.GetTxOutspends(op.Txid)
		if err == nil && int(op.VOut) < len(statuses) {
			event.SpentUtxos[i].SpentBy = statuses[op.VOut].SpentBy
		}
	}

	state.utxos = newUTXOs

	go e.listeners.broadcast(event)
}

func diffUTXOs(old, new []electrumUTXO, script string) (types.OnchainAddressEvent, bool) {
	type key struct {
		txid string
		vout uint32
	}
	oldMap := make(map[key]electrumUTXO, len(old))
	for _, u := range old {
		oldMap[key{u.TxHash, u.TxPos}] = u
	}
	newMap := make(map[key]electrumUTXO, len(new))
	for _, u := range new {
		newMap[key{u.TxHash, u.TxPos}] = u
	}

	var spent, received, confirmed []types.OnchainOutput

	for k, u := range oldMap {
		if _, exists := newMap[k]; !exists {
			spent = append(spent, types.OnchainOutput{
				Outpoint: types.Outpoint{Txid: u.TxHash, VOut: u.TxPos},
				Script:   script,
				Amount:   u.Value,
				Spent:    true,
			})
		}
	}
	for k, u := range newMap {
		oldU, existed := oldMap[k]
		if !existed {
			// CreatedAt is zero here; pollAddress fills it in from blockTimestamp.
			received = append(received, types.OnchainOutput{
				Outpoint: types.Outpoint{Txid: u.TxHash, VOut: u.TxPos},
				Script:   script,
				Amount:   u.Value,
			})
		} else if oldU.Height == 0 && u.Height > 0 {
			// CreatedAt is zero here; pollAddress fills it in from blockTimestamp.
			confirmed = append(confirmed, types.OnchainOutput{
				Outpoint: types.Outpoint{Txid: u.TxHash, VOut: u.TxPos},
				Script:   script,
				Amount:   u.Value,
			})
		}
	}

	if len(spent) == 0 && len(received) == 0 && len(confirmed) == 0 {
		return types.OnchainAddressEvent{}, false
	}
	return types.OnchainAddressEvent{
		SpentUtxos:     spent,
		NewUtxos:       received,
		ConfirmedUtxos: confirmed,
		Replacements:   make(map[string]string),
	}, true
}

func (e *explorerSvc) listUnspent(scripthash string) ([]electrumUTXO, error) {
	raw, err := e.client.request("blockchain.scripthash.listunspent", []any{scripthash})
	if err != nil {
		return nil, err
	}
	var utxos []electrumUTXO
	return utxos, json.Unmarshal(raw, &utxos)
}

// decodeBitcoinTx deserializes a hex-encoded raw Bitcoin transaction.
func decodeBitcoinTx(txHex string) (*wire.MsgTx, error) {
	b, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, err
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		return nil, err
	}
	return tx, nil
}

// wireTxToExplorerTx converts a decoded wire.MsgTx into the explorer.Tx format.
// Input prevout fields (script, address, amount) are not populated because
// electrs-esplora does not support verbose transactions.
func wireTxToExplorerTx(
	txid string,
	tx *wire.MsgTx,
	blocktime int64,
	confirmed bool,
	params *chaincfg.Params,
) explorer.Tx {
	vins := make([]explorer.Input, 0, len(tx.TxIn))
	for _, in := range tx.TxIn {
		vins = append(vins, explorer.Input{
			Txid: in.PreviousOutPoint.Hash.String(),
			Vout: in.PreviousOutPoint.Index,
		})
	}
	vouts := make([]explorer.Output, 0, len(tx.TxOut))
	for _, out := range tx.TxOut {
		script := hex.EncodeToString(out.PkScript)
		vouts = append(vouts, explorer.Output{
			Script:  script,
			Address: scriptToAddress(script, params),
			Amount:  uint64(out.Value),
		})
	}
	return explorer.Tx{
		Txid: txid,
		Vin:  vins,
		Vout: vouts,
		Status: explorer.ConfirmedStatus{
			Confirmed: confirmed,
			BlockTime: blocktime,
		},
	}
}

// blockTimestamp returns the Unix timestamp of a block at the given height by
// parsing the 80-byte raw block header returned by blockchain.block.header.
func (e *explorerSvc) blockTimestamp(height int64) (int64, error) {
	result, err := e.client.request("blockchain.block.header", []any{height, 0})
	if err != nil {
		return 0, err
	}
	var headerHex string
	if err := json.Unmarshal(result, &headerHex); err != nil {
		return 0, err
	}
	headerBytes, err := hex.DecodeString(headerHex)
	if err != nil {
		return 0, err
	}

	var hdr wire.BlockHeader
	if err := hdr.Deserialize(bytes.NewReader(headerBytes)); err != nil {
		// fallback: timestamp is at bytes 68-72 (LE uint32) in the 80-byte header
		if len(headerBytes) >= 72 {
			return int64(binary.LittleEndian.Uint32(headerBytes[68:72])), nil
		}
		return 0, err
	}
	return hdr.Timestamp.Unix(), nil
}

func addrToScript(addr string, params *chaincfg.Params) (string, error) {
	decoded, err := btcutil.DecodeAddress(addr, params)
	if err != nil {
		return "", err
	}
	script, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(script), nil
}

// esploraListUnspent fetches unspent outputs for addr via the esplora REST API.
// Used as a fallback when the electrum scripthash index returns empty (e.g.
// older electrs builds that don't index P2TR scripts).
func (e *explorerSvc) esploraListUnspent(addr string) ([]electrumUTXO, error) {
	url := strings.TrimRight(e.esploraURL, "/") + "/address/" + addr + "/utxo"
	resp, err := http.Get(url) // nolint
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("esplora utxo lookup failed (%d)", resp.StatusCode)
	}
	var items []esploraUtxo
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	utxos := make([]electrumUTXO, 0, len(items))
	for _, u := range items {
		height := int64(0)
		if u.Status.Confirmed {
			height = u.Status.BlockHeight
		}
		utxos = append(utxos, electrumUTXO{
			TxHash: u.Txid,
			TxPos:  u.Vout,
			Height: height,
			Value:  u.Value,
		})
	}
	return utxos, nil
}

// esploraGetTxs fetches the transaction history for addr via the esplora REST API.
// Used as a fallback when the electrum scripthash index returns empty.
func (e *explorerSvc) esploraGetTxs(addr string) ([]explorer.Tx, error) {
	url := strings.TrimRight(e.esploraURL, "/") + "/address/" + addr + "/txs"
	resp, err := http.Get(url) // nolint
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // nolint
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("esplora tx history lookup failed (%d)", resp.StatusCode)
	}
	var items []esploraTxEntry
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	txs := make([]explorer.Tx, 0, len(items))
	for _, t := range items {
		vins := make([]explorer.Input, 0, len(t.Vin))
		for _, vin := range t.Vin {
			vins = append(vins, explorer.Input{Txid: vin.Txid, Vout: vin.Vout})
		}
		vouts := make([]explorer.Output, 0, len(t.Vout))
		for _, vout := range t.Vout {
			vouts = append(vouts, explorer.Output{
				Script:  vout.Scriptpubkey,
				Address: vout.ScriptpubkeyAddress,
				Amount:  vout.Value,
			})
		}
		txs = append(txs, explorer.Tx{
			Txid: t.Txid,
			Vin:  vins,
			Vout: vouts,
			Status: explorer.ConfirmedStatus{
				Confirmed: t.Status.Confirmed,
				BlockTime: t.Status.BlockTime,
			},
		})
	}
	return txs, nil
}
