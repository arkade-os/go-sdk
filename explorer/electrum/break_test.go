package electrum_explorer_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	electrum_explorer "github.com/arkade-os/go-sdk/explorer/electrum"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/stretchr/testify/require"
)

// TestBreak_ConcurrentSubscribeSameAddress probes the TOCTOU window between
// the RLock pre-check and the Lock confirm in SubscribeForAddresses. If
// electrumClient.subscribe overwrites c.subs[sh] without dedup, the loser
// orphans a notif channel and Stop() blocks on notifWg.Wait().
func TestBreak_ConcurrentSubscribeSameAddress(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			time.Sleep(20 * time.Millisecond) // widen the TOCTOU window
			writeResponse(conn, reqID(req), []any{})
		case "blockchain.scripthash.subscribe":
			writeResponse(conn, reqID(req), nil)
		}
	})

	exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin,
		electrum_explorer.WithTracker(true))
	require.NoError(t, err)
	exp.Start()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = exp.SubscribeForAddresses([]string{addr}) }()
	}
	wg.Wait()

	done := make(chan struct{})
	go func() { exp.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop() hung — orphan notifCh from concurrent SubscribeForAddresses")
	}
}

// TestBreak_GetAddressesEventsLeaksWhenTrackerOff documents that calling
// GetAddressesEvents on a no-tracker explorer returns a never-closed channel.
func TestBreak_GetAddressesEventsLeaksWhenTrackerOff(t *testing.T) {
	exp, err := electrum_explorer.NewExplorer("tcp://127.0.0.1:1", arklib.Bitcoin,
		electrum_explorer.WithTracker(false))
	require.NoError(t, err)
	ch := exp.GetAddressesEvents()
	require.NotNil(t, ch)

	exp.Stop()

	select {
	case _, ok := <-ch:
		require.False(t, ok, "channel should be closed after Stop")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("GetAddressesEvents channel never closes — consumer goroutine leaks forever")
	}
}

// TestBreak_GetTxOutspendsHidesRPCError verifies that an RPC error in the
// per-output history scan is surfaced rather than being interpreted as
// "output is unspent".
func TestBreak_GetTxOutspendsHidesRPCError(t *testing.T) {
	const txid = "tgt"
	// Minimal non-segwit TX: 1 input (null outpoint), 1 output (OP_1 script = 0x51).
	const minimalTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000015100000000"
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), minimalTxHex)
		case "blockchain.scripthash.get_history":
			resp := fmt.Sprintf(
				`{"id":%d,"error":{"code":-32603,"message":"internal error"}}`+"\n",
				reqID(req))
			_, _ = conn.Write([]byte(resp))
		}
	})

	exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin,
		electrum_explorer.WithTracker(false))
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	outspends, err := exp.GetTxOutspends(txid)
	if err == nil {
		require.NotEqual(t, false, outspends[0].Spent,
			"RPC error reported as Spent=false — caller cannot distinguish error from unspent")
	}
}

// TestBreak_StartIsIdempotent stresses concurrent Start() calls and asserts
// only one TCP connection is established. A second connection means the
// first one was leaked.
func TestBreak_StartIsIdempotent(t *testing.T) {
	var conns atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() }) // nolint

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go serveConn(c, func(conn net.Conn, req map[string]json.RawMessage) {
				if reqMethod(req) == "server.version" {
					writeResponse(conn, reqID(req), []string{"mock", "1.4"})
				}
			})
		}
	}()

	exp, err := electrum_explorer.NewExplorer("tcp://"+ln.Addr().String(), arklib.Bitcoin,
		electrum_explorer.WithTracker(false))
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); exp.Start() }()
	}
	wg.Wait()
	defer exp.Stop()
	time.Sleep(300 * time.Millisecond)

	require.LessOrEqualf(t, conns.Load(), int32(1),
		"Start() spawned %d TCP connections; second connection leaked", conns.Load())
}

// TestBreak_GetTxBlockTimeUnconfirmedReturnsZero verifies that GetTxBlockTime
// returns blocktime=0 for an unconfirmed transaction, consistent with GetTxs
// and GetUtxos. electrs-esplora does not support verbose transactions, so we
// derive confirmation status from blockchain.scripthash.get_history instead.
func TestBreak_GetTxBlockTimeUnconfirmedReturnsZero(t *testing.T) {
	const txid = "u"
	// Minimal non-segwit TX: 1 input (null outpoint), 1 P2WPKH output (20 zero bytes).
	const minimalTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000160014000000000000000000000000000000000000000000000000"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), minimalTxHex)
		case "blockchain.scripthash.get_history":
			// height=0 means unconfirmed in the electrum protocol.
			writeResponse(conn, reqID(req), []any{
				map[string]any{"tx_hash": txid, "height": 0},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin,
		electrum_explorer.WithTracker(false))
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	confirmed, bt, err := exp.GetTxBlockTime(txid)
	require.NoError(t, err)
	require.False(t, confirmed, "unconfirmed tx must report confirmed=false")
	require.Equal(t, int64(0), bt, "unconfirmed tx must report blocktime=0")
}

// TestBreak_PendingRequestHangsOnDisconnect verifies that an in-flight request
// fails fast when the connection drops, instead of waiting the full 15 s
// requestTimeout. listen()'s reconnect path currently does NOT flush c.pending,
// so callers wait for their individual timeouts before learning the conn died.
//
// Real-world impact: during wallet restore (discoverHDWalletKeys fires hundreds
// of GetTxs in succession), if the server restarts mid-restore, every in-flight
// request blocks the restore for 15 s × in-flight count.
func TestBreak_PendingRequestHangsOnDisconnect(t *testing.T) {
	const dropDelay = 50 * time.Millisecond

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			// Simulate a server crash mid-request: never respond, just close.
			go func() {
				time.Sleep(dropDelay)
				_ = conn.Close()
			}()
		}
	})

	exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin,
		electrum_explorer.WithTracker(false))
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	start := time.Now()
	_, err = exp.GetTxHex("any-txid-the-server-wont-answer")
	elapsed := time.Since(start)

	require.Error(t, err, "request should fail after disconnect")

	// With reconnect() draining pending on disconnect => ~50 ms (dropDelay).
	// Without the drain => 15 s (requestTimeout).
	require.Lessf(t, elapsed, 2*time.Second,
		"GetTxHex took %v after server disconnect; in-flight requests should fail "+
			"fast when the connection dies, not wait the 15 s requestTimeout", elapsed)
}

// TestBreak_ResubscribeIsSerial verifies that scripthash resubscription after
// a reconnect runs in parallel rather than one-RPC-at-a-time. With a wallet
// that has many subscribed addresses (boarding + unrolled VTXOs + delegate
// addresses), a serial resubscribe makes recovery time scale linearly with
// the number of subscriptions.
//
// Strategy: subscribe to N addresses, force a reconnect by closing the first
// connection, then time how long the resubscribe phase takes. With a 40 ms
// per-subscribe simulated server delay, a serial implementation needs
// N×40 ms; bounded parallelism (e.g. 8 workers) takes ≈80 ms regardless of N.
func TestBreak_ResubscribeIsSerial(t *testing.T) {
	const N = 12
	const subscribeDelay = 40 * time.Millisecond

	addrs := make([]string, 0, N)
	for i := 1; i <= N; i++ {
		prog := make([]byte, 20)
		binary.BigEndian.PutUint64(prog[12:], uint64(i))
		addr, err := btcutil.NewAddressWitnessPubKeyHash(prog, &chaincfg.MainNetParams)
		require.NoError(t, err)
		addrs = append(addrs, addr.EncodeAddress())
	}

	var subscribeCount atomic.Int32
	// writeMu protects concurrent conn.Write calls from the async subscribe
	// handlers. serveConn calls each handler synchronously, so we return
	// immediately from the subscribe case and do the sleep + write in a
	// goroutine, letting serveConn pipeline subsequent requests.
	var writeMu sync.Mutex
	firstConnCh := make(chan net.Conn, 1)
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		select {
		case firstConnCh <- conn:
		default:
		}
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []any{})
		case "blockchain.scripthash.subscribe":
			subscribeCount.Add(1)
			id := reqID(req)
			go func() {
				time.Sleep(subscribeDelay)
				writeMu.Lock()
				writeResponse(conn, id, nil)
				writeMu.Unlock()
			}()
		}
	})

	exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin,
		electrum_explorer.WithTracker(true))
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	require.NoError(t, exp.SubscribeForAddresses(addrs))
	require.Eventually(t, func() bool { return subscribeCount.Load() >= int32(N) },
		15*time.Second, 50*time.Millisecond, "initial subscribes never completed")

	// Reset for the resubscribe phase, then drop the first connection.
	subscribeCount.Store(0)
	initial := <-firstConnCh
	_ = initial.Close()

	start := time.Now()
	require.Eventually(t, func() bool { return subscribeCount.Load() >= int32(N) },
		20*time.Second, 50*time.Millisecond, "resubscribe never completed")
	elapsed := time.Since(start)

	serialBaseline := time.Duration(N) * subscribeDelay // 12 × 40 ms = 480 ms
	parallelThreshold := serialBaseline / 3             // ≈ 160 ms (allows for partial overlap)

	require.Lessf(t, elapsed, parallelThreshold,
		"resubscribe of %d addresses took %v; serial baseline = %v; "+
			"reconnect should parallelise resubscribes (target < %v)",
		N, elapsed, serialBaseline, parallelThreshold)
}
