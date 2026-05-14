package electrum_explorer

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// wsTracker is a single-connection WebSocket client that speaks the
// mempool.space "track-addresses" protocol. Each call to subscribe(addr)
// re-sends the full address set so the upstream filter stays in sync.
// Notifications arrive as wsAddressNotification; for each one, we synthesize
// an OnchainAddressEvent (new / spent / confirmed / replacements) by walking
// the tx vin/vout fields and matching the subscribed address strings.
//
// The point of this path is to surface P2TR boarding-address activity when
// the Electrum scripthash index is missing taproot. The WS server (electrs
// or chopsticks) filters new TXs live against the tracked address set, so it
// works even when the historical scripthash index is empty.
type wsTracker struct {
	url       string
	netParams *chaincfg.Params
	listeners *listeners

	mu    sync.Mutex
	addrs map[string]struct{}
	conn  *websocket.Conn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

const (
	wsPingInterval = 30 * time.Second
	wsPongTimeout  = 60 * time.Second
	wsDialTimeout  = 10 * time.Second
	wsRedialDelay  = 2 * time.Second
)

func newWSTracker(url string, params *chaincfg.Params, listeners *listeners) *wsTracker {
	return &wsTracker{
		url:       url,
		netParams: params,
		listeners: listeners,
		addrs:     make(map[string]struct{}),
	}
}

// start brings up the connection and the reader/keepalive goroutines. Safe to
// call once; subsequent calls are no-ops.
func (t *wsTracker) start() {
	t.mu.Lock()
	if t.ctx != nil {
		t.mu.Unlock()
		return
	}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	t.mu.Unlock()

	t.wg.Add(1)
	go t.run()
}

// stop closes the connection and waits for goroutines to exit.
func (t *wsTracker) stop() {
	t.mu.Lock()
	if t.cancel == nil {
		t.mu.Unlock()
		return
	}
	t.cancel()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// subscribe adds addr to the tracked set and (if connected) re-sends
// track-addresses so the upstream filter updates immediately. All WS writes
// happen under t.mu so concurrent subscribe / unsubscribe / initial-send
// calls cannot interleave and clobber each other's track-addresses state.
func (t *wsTracker) subscribe(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.addrs[addr]; ok {
		return
	}
	t.addrs[addr] = struct{}{}
	if t.conn != nil {
		_ = sendTrackAddresses(t.conn, t.snapshotAddrsLocked())
	}
}

// unsubscribe removes addr from the tracked set and re-sends track-addresses.
func (t *wsTracker) unsubscribe(addr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.addrs[addr]; !ok {
		return
	}
	delete(t.addrs, addr)
	if t.conn != nil {
		_ = sendTrackAddresses(t.conn, t.snapshotAddrsLocked())
	}
}

func (t *wsTracker) snapshotAddrsLocked() []string {
	out := make([]string, 0, len(t.addrs))
	for a := range t.addrs {
		out = append(out, a)
	}
	return out
}

// run is the connect-read-redial loop. On any read error or context
// cancellation, it tears down and tries again after wsRedialDelay until ctx is
// done. After a successful redial it re-asserts the full track-addresses set
// so subscriptions survive transient drops.
func (t *wsTracker) run() {
	defer t.wg.Done()
	for {
		if err := t.ctx.Err(); err != nil {
			return
		}
		if err := t.dialAndServe(); err != nil {
			log.WithError(err).Debug("electrum ws: connection ended, redialing")
		}
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(wsRedialDelay):
		}
	}
}

func (t *wsTracker) dialAndServe() error {
	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: wsDialTimeout,
	}
	conn, _, err := dialer.DialContext(t.ctx, t.url, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	log.Debugf("electrum ws: connected to %s", t.url)

	// Take the lock around BOTH the conn assignment and the initial
	// track-addresses send. A concurrent subscribe() that lands between
	// these two would otherwise see t.conn set, send its [addrs..N] payload,
	// and then have its message overwritten by the empty initial send from
	// this goroutine. With everything inside the same critical section,
	// subscribe either runs before (sees t.conn nil, just stores) or after
	// (sees the up-to-date addr set and sends the merged list).
	t.mu.Lock()
	t.conn = conn
	addrs := t.snapshotAddrsLocked()
	var initialErr error
	if len(addrs) > 0 {
		initialErr = sendTrackAddresses(conn, addrs)
	}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.conn = nil
		t.mu.Unlock()
		_ = conn.Close()
	}()

	if initialErr != nil {
		return fmt.Errorf("track-addresses: %w", initialErr)
	}

	// Pong handler resets the read deadline so we notice silent drops.
	if err := conn.SetReadDeadline(time.Now().Add(wsPongTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	})

	pingDone := make(chan struct{})
	go t.pingLoop(conn, pingDone)
	defer close(pingDone)

	for {
		var payload wsAddressNotification
		if err := conn.ReadJSON(&payload); err != nil {
			return fmt.Errorf("read: %w", err)
		}
		t.handle(payload)
	}
}

func (t *wsTracker) pingLoop(conn *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			_ = conn.WriteControl(
				websocket.PingMessage, nil, time.Now().Add(10*time.Second),
			)
		}
	}
}

func sendTrackAddresses(conn *websocket.Conn, addrs []string) error {
	// Always send a non-nil slice so the upstream filter clears when empty.
	if addrs == nil {
		addrs = []string{}
	}
	return conn.WriteJSON(map[string][]string{"track-addresses": addrs})
}

// handle converts a wsAddressNotification into one OnchainAddressEvent per
// notification and broadcasts it to the listeners hub. The diff is computed
// from the message contents alone (mempool / confirmed / removed), so it does
// not depend on any local state.utxos baseline. Duplicate notifications are
// expected to be deduplicated downstream by UtxoStore (AddUtxos returns 0 for
// existing rows).
func (t *wsTracker) handle(payload wsAddressNotification) {
	if payload.Error != "" {
		go t.listeners.broadcast(types.OnchainAddressEvent{
			Error: fmt.Errorf("ws: %s", payload.Error),
		})
		return
	}
	if len(payload.MultiAddrTx) == 0 {
		return
	}

	spent := make([]types.OnchainOutput, 0)
	added := make([]types.OnchainOutput, 0)
	confirmed := make([]types.OnchainOutput, 0)
	replacements := make(map[string]string)

	for addr, set := range payload.MultiAddrTx {
		script := t.scriptFor(addr)
		// Mempool TXs: anything spending a UTXO owned by `addr` is a Spent
		// event, anything paying to `addr` is a New event.
		for _, tx := range set.Mempool {
			for _, in := range tx.Inputs {
				if in.Prevout.Address == addr {
					spent = append(spent, types.OnchainOutput{
						Outpoint: types.Outpoint{Txid: in.Txid, VOut: in.Vout},
						Script:   script,
						Amount:   in.Prevout.Amount,
						Spent:    true,
						SpentBy:  tx.Txid,
					})
				}
			}
			for i, out := range tx.Outputs {
				if out.Address == addr {
					added = append(added, types.OnchainOutput{
						Outpoint:  types.Outpoint{Txid: tx.Txid, VOut: uint32(i)},
						Script:    script,
						Amount:    out.Amount,
						CreatedAt: txCreatedAt(tx.Status),
					})
				}
			}
		}
		// Confirmed TXs: payments that just got mined.
		for _, tx := range set.Confirmed {
			for i, out := range tx.Outputs {
				if out.Address == addr {
					confirmed = append(confirmed, types.OnchainOutput{
						Outpoint:  types.Outpoint{Txid: tx.Txid, VOut: uint32(i)},
						Script:    script,
						Amount:    out.Amount,
						CreatedAt: txCreatedAt(tx.Status),
					})
				}
			}
		}
		// Removed TXs (RBF): pair each removed txid with the first mempool tx
		// in the same notification, mirroring the mempool_explorer behavior.
		if len(set.Removed) > 0 && len(set.Mempool) > 0 {
			replacementTxid := set.Mempool[0].Txid
			for _, rem := range set.Removed {
				replacements[rem.Txid] = replacementTxid
			}
		}
	}

	if len(spent) == 0 && len(added) == 0 && len(confirmed) == 0 && len(replacements) == 0 {
		return
	}
	go t.listeners.broadcast(types.OnchainAddressEvent{
		SpentUtxos:     spent,
		NewUtxos:       added,
		ConfirmedUtxos: confirmed,
		Replacements:   replacements,
	})
}

func (t *wsTracker) scriptFor(addr string) string {
	decoded, err := btcutil.DecodeAddress(addr, t.netParams)
	if err != nil {
		return ""
	}
	script, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(script)
}

func txCreatedAt(s wsTxStatusEnvelope) time.Time {
	if !s.Confirmed || s.BlockTime == 0 {
		return time.Time{}
	}
	return time.Unix(s.BlockTime, 0)
}
