// Package electrum_explorer provides an Explorer implementation backed by an
// ElectrumX server over TCP or SSL. It is modeled on the ocean project's
// electrum blockchain scanner and requires no third-party ElectrumX library.
//
// Known limitations vs the mempool.space explorer:
//   - Broadcast of multiple txs is sequential, not atomic.
//   - UnsubscribeForAddresses removes the address locally only; ElectrumX has no unsubscribe wire message.
//   - OnchainAddressEvent.Replacements is always empty (ElectrumX has no RBF notification).
//   - GetConnectionCount always returns 1 (single multiplexed TCP connection).
//   - GetTxOutspends is O(outputs × history length) rather than a dedicated endpoint.
package electrum_explorer

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
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
	client    *electrumClient
	serverURL string
	netParams *chaincfg.Params

	noTracking   bool
	pollInterval time.Duration

	subscribedMu  sync.RWMutex
	subscribedMap map[string]*addressState // address → state

	// notifWg tracks the per-address goroutines spawned in SubscribeForAddresses.
	// Stop() waits on this before returning to ensure no goroutine outlives the svc.
	notifWg sync.WaitGroup

	// reverse lookup: scripthash → address
	scripthashToAddr   map[string]string
	scripthashToAddrMu sync.RWMutex

	stopTracking func()
	listeners    *listeners

	cacheMu sync.RWMutex
	cache   map[string]string // txid → hex; bounded to txCacheMaxSize entries
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
		scripthashToAddr: make(map[string]string),
		cache:            make(map[string]string),
	}
	for _, opt := range opts {
		opt(svc)
	}
	if !svc.noTracking {
		svc.listeners = newListeners()
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

func (e *explorerSvc) Start() {
	if err := e.client.connect(); err != nil {
		log.WithError(err).Warn("electrum explorer: initial connect failed, retrying in background")
		go func() {
			if err := e.client.reconnect(); err != nil {
				log.WithError(err).Error("electrum explorer: background reconnect failed")
			}
		}()
	}

	if e.noTracking || e.stopTracking != nil {
		return
	}

	stopCh := make(chan struct{})
	e.stopTracking = sync.OnceFunc(func() { close(stopCh) })
	go e.pollLoop(stopCh)
	log.Debug("electrum explorer: started")
}

func (e *explorerSvc) Stop() {
	if e.stopTracking != nil {
		e.stopTracking()
		e.stopTracking = nil
	}
	e.client.shutdown()

	// Close all per-address notification channels so that the goroutines spawned
	// in SubscribeForAddresses exit and notifWg can complete.
	e.subscribedMu.Lock()
	for _, state := range e.subscribedMap {
		e.client.unsubscribeLocal(state.scripthash)
	}
	e.subscribedMap = make(map[string]*addressState)
	e.subscribedMu.Unlock()

	e.notifWg.Wait()

	if e.listeners != nil {
		e.listeners.clear()
	}

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
	if e.listeners != nil {
		e.listeners.add(ch)
	}
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

	txs := make([]explorer.Tx, 0, len(history))
	for _, entry := range history {
		vtx, err := e.getVerboseTx(entry.TxHash)
		if err != nil {
			return nil, err
		}
		confirmed := entry.Height > 0
		var blocktime int64
		if confirmed {
			if vtx.Blocktime > 0 {
				blocktime = vtx.Blocktime
			} else {
				blocktime, _ = e.blockTimestamp(entry.Height)
			}
		}
		txs = append(txs, verboseTxToExplorerTx(vtx, blocktime, confirmed, e.netParams))
	}
	return txs, nil
}

// GetTxOutspends returns the spent status of each output of a transaction.
// There is no direct ElectrumX equivalent; this resolves by scanning
// the scripthash history of each output.
func (e *explorerSvc) GetTxOutspends(txid string) ([]explorer.SpentStatus, error) {
	vtx, err := e.getVerboseTx(txid)
	if err != nil {
		return nil, err
	}
	result := make([]explorer.SpentStatus, len(vtx.Vout))
	for i, out := range vtx.Vout {
		if out.ScriptPubKey.Hex == "" {
			continue
		}
		sh, err := scriptToScripthash(out.ScriptPubKey.Hex)
		if err != nil {
			log.WithError(err).
				Debugf("electrum: scriptToScripthash failed for output %d of %s (script %s)", i, txid, out.ScriptPubKey.Hex)
			continue
		}
		histResult, err := e.client.request("blockchain.scripthash.get_history", []any{sh})
		if err != nil {
			log.WithError(err).Debugf("electrum: get_history failed for output %d of %s", i, txid)
			continue
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
			spendingTx, err := e.getVerboseTx(entry.TxHash)
			if err != nil {
				continue
			}
			for _, vin := range spendingTx.Vin {
				if vin.TxID == txid && vin.Vout == uint32(i) {
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

func (e *explorerSvc) GetUtxos(addr string) ([]explorer.Utxo, error) {
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
	btCache := make(map[int64]int64)
	utxos := make([]explorer.Utxo, 0, len(electrumUtxos))
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
	return utxos, nil
}

func (e *explorerSvc) GetRedeemedVtxosBalance(
	addr string, unilateralExitDelay arklib.RelativeLocktime,
) (spendableBalance uint64, lockedBalance map[int64]uint64, err error) {
	utxos, err := e.GetUtxos(addr)
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
	vtx, err := e.getVerboseTx(txid)
	if err != nil {
		return false, -1, err
	}
	if vtx.Confirmations == 0 || vtx.BlockHeight <= 0 {
		return false, -1, nil
	}
	if vtx.Blocktime > 0 {
		return true, vtx.Blocktime, nil
	}
	bt, err := e.blockTimestamp(vtx.BlockHeight)
	if err != nil {
		return false, -1, err
	}
	return true, bt, nil
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
		e.subscribedMu.RLock()
		_, already := e.subscribedMap[addr]
		e.subscribedMu.RUnlock()
		if already {
			continue
		}

		sh, err := addressToScripthash(addr, e.netParams)
		if err != nil {
			return fmt.Errorf("invalid address %s: %w", addr, err)
		}
		initialUTXOs, err := e.listUnspent(sh)
		if err != nil {
			return fmt.Errorf("failed to get initial utxos for %s: %w", addr, err)
		}
		notifCh, err := e.client.subscribe(sh)
		if err != nil {
			return fmt.Errorf("failed to subscribe for %s: %w", addr, err)
		}

		e.subscribedMu.Lock()
		if _, already := e.subscribedMap[addr]; already {
			// Another concurrent caller subscribed this address between our check and now.
			e.subscribedMu.Unlock()
			e.client.unsubscribeLocal(sh)
			continue
		}
		state := &addressState{scripthash: sh, utxos: initialUTXOs, notifCh: notifCh}
		e.subscribedMap[addr] = state
		e.subscribedMu.Unlock()

		e.scripthashToAddrMu.Lock()
		e.scripthashToAddr[sh] = addr
		e.scripthashToAddrMu.Unlock()

		// When ElectrumX pushes a notification for this scripthash, immediately poll
		// the address rather than waiting for the next ticker cycle.
		e.notifWg.Add(1)
		go func(addr, sh string, notifCh <-chan string) {
			defer e.notifWg.Done()
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

func (e *explorerSvc) getVerboseTx(txid string) (*electrumVerboseTx, error) {
	result, err := e.client.request("blockchain.transaction.get", []any{txid, true})
	if err != nil {
		return nil, err
	}
	var vtx electrumVerboseTx
	return &vtx, json.Unmarshal(result, &vtx)
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

func verboseTxToExplorerTx(
	vtx *electrumVerboseTx,
	blocktime int64,
	confirmed bool,
	params *chaincfg.Params,
) explorer.Tx {
	vins := make([]explorer.Input, 0, len(vtx.Vin))
	for _, in := range vtx.Vin {
		vins = append(vins, explorer.Input{
			Output: explorer.Output{
				Script:  in.Prevout.ScriptPubKey.Hex,
				Address: scriptToAddress(in.Prevout.ScriptPubKey.Hex, params),
				Amount:  uint64(math.Round(in.Prevout.Value * 1e8)),
			},
			Txid: in.TxID,
			Vout: in.Vout,
		})
	}
	vouts := make([]explorer.Output, 0, len(vtx.Vout))
	for _, out := range vtx.Vout {
		vouts = append(vouts, explorer.Output{
			Script:  out.ScriptPubKey.Hex,
			Address: scriptToAddress(out.ScriptPubKey.Hex, params),
			Amount:  uint64(math.Round(out.Value * 1e8)),
		})
	}
	return explorer.Tx{
		Txid: vtx.Txid,
		Vin:  vins,
		Vout: vouts,
		Status: explorer.ConfirmedStatus{
			Confirmed: confirmed,
			BlockTime: blocktime,
		},
	}
}
