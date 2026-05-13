package electrum_explorer_test

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	electrum_explorer "github.com/arkade-os/go-sdk/explorer/electrum"
	"github.com/stretchr/testify/require"
)

// mockServer starts a local TCP listener and returns its address.
// The returned handler func is called once per complete JSON-RPC request line.
// It should write the full JSON-RPC response (including newline) to the conn.
type requestHandler func(conn net.Conn, req map[string]json.RawMessage)

func startMockServer(t *testing.T, handler requestHandler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() }) // nolint

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go serveConn(conn, handler)
		}
	}()
	return "tcp://" + ln.Addr().String()
}

func serveConn(conn net.Conn, handler requestHandler) {
	defer conn.Close() // nolint
	buf := make([]byte, 4096)
	var partial []byte
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		partial = append(partial, buf[:n]...)
		for {
			idx := -1
			for i, b := range partial {
				if b == '\n' {
					idx = i
					break
				}
			}
			if idx < 0 {
				break
			}
			line := partial[:idx]
			partial = partial[idx+1:]

			var req map[string]json.RawMessage
			if err := json.Unmarshal(line, &req); err != nil {
				continue
			}
			handler(conn, req)
		}
	}
}

func writeResponse(conn net.Conn, id uint64, result any) {
	data, _ := json.Marshal(result)
	resp := fmt.Sprintf(`{"id":%d,"result":%s}`, id, string(data))
	conn.Write([]byte(resp + "\n")) // nolint
}

func reqID(req map[string]json.RawMessage) uint64 {
	var id uint64
	json.Unmarshal(req["id"], &id) // nolint
	return id
}

func reqMethod(req map[string]json.RawMessage) string {
	var m string
	json.Unmarshal(req["method"], &m) // nolint
	return m
}

// TestNewExplorerValidation checks that NewExplorer rejects bad URLs.
func TestNewExplorerValidation(t *testing.T) {
	t.Run("rejects http URL", func(t *testing.T) {
		_, err := electrum_explorer.NewExplorer("http://example.com", arklib.Bitcoin)
		require.ErrorContains(t, err, "tcp:// or ssl://")
	})

	t.Run("rejects empty URL", func(t *testing.T) {
		_, err := electrum_explorer.NewExplorer("", arklib.Bitcoin)
		require.ErrorContains(t, err, "tcp:// or ssl://")
	})

	t.Run("accepts tcp:// URL", func(t *testing.T) {
		exp, err := electrum_explorer.NewExplorer("tcp://127.0.0.1:50001", arklib.Bitcoin)
		require.NoError(t, err)
		require.NotNil(t, exp)
	})

	t.Run("accepts ssl:// URL", func(t *testing.T) {
		exp, err := electrum_explorer.NewExplorer(
			"ssl://electrum.example.com:50002",
			arklib.Bitcoin,
		)
		require.NoError(t, err)
		require.NotNil(t, exp)
	})
}

// TestBaseUrl checks that BaseUrl returns the configured server URL.
func TestBaseUrl(t *testing.T) {
	url := "tcp://127.0.0.1:50001"
	exp, err := electrum_explorer.NewExplorer(url, arklib.Bitcoin)
	require.NoError(t, err)
	require.Equal(t, url, exp.BaseUrl())
}

// TestGetTxHex tests the GetTxHex method against a mock ElectrumX server.
func TestGetTxHex(t *testing.T) {
	const txid = "abc123"
	const txHex = "0200000000"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), txHex)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	got, err := exp.GetTxHex(txid)
	require.NoError(t, err)
	require.Equal(t, txHex, got)
}

// TestGetTxHexCached verifies that a second call for the same txid does not
// make a second network request.
func TestGetTxHexCached(t *testing.T) {
	const txHex = "deadbeef"
	callCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			callCount++
			writeResponse(conn, reqID(req), txHex)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	_, err = exp.GetTxHex("txid1")
	require.NoError(t, err)
	_, err = exp.GetTxHex("txid1")
	require.NoError(t, err)
	require.Equal(t, 1, callCount, "second call should use cache")
}

// TestBroadcast verifies that Broadcast sends blockchain.transaction.broadcast
// and returns the txid.
func TestBroadcast(t *testing.T) {
	// Minimal valid raw transaction (version 2, no inputs, no outputs, locktime 0).
	const rawTx = "02000000000000000000"
	const returnedTxid = "aaaa"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.broadcast":
			writeResponse(conn, reqID(req), returnedTxid)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txid, err := exp.Broadcast(rawTx)
	require.NoError(t, err)
	require.Equal(t, returnedTxid, txid)
}

// TestBroadcastAlreadyInChain verifies that "transaction already in block chain"
// errors are treated as success.
func TestBroadcastAlreadyInChain(t *testing.T) {
	const rawTx = "02000000000000000000"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.broadcast":
			// ElectrumX error for already-confirmed tx.
			resp := fmt.Sprintf(
				`{"id":%d,"error":{"code":2,"message":"transaction already in block chain"}}`,
				reqID(req),
			)
			conn.Write([]byte(resp + "\n")) // nolint
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	_, err = exp.Broadcast(rawTx)
	require.NoError(t, err, "already-in-chain should not be an error")
}

// TestGetFeeRate verifies that GetFeeRate converts BTC/kB to sat/vB correctly.
func TestGetFeeRate(t *testing.T) {
	// 0.00010000 BTC/kB = 10 sat/vB (0.0001 * 1e8 / 1000)
	const btcPerKB = 0.00010000
	const expectedSatPerVB = 10.0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.estimatefee":
			writeResponse(conn, reqID(req), btcPerKB)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	rate, err := exp.GetFeeRate()
	require.NoError(t, err)
	require.InDelta(t, expectedSatPerVB, rate, 0.001)
}

// TestGetFeeRateUnknown verifies that a -1 response from the server returns 1 sat/vB.
func TestGetFeeRateUnknown(t *testing.T) {
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.estimatefee":
			writeResponse(conn, reqID(req), -1.0)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	rate, err := exp.GetFeeRate()
	require.NoError(t, err)
	require.Equal(t, 1.0, rate)
}

// TestGetConnectionCount verifies GetConnectionCount returns 1 when connected and 0 when not.
func TestGetConnectionCount(t *testing.T) {
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		if reqMethod(req) == "server.version" {
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)

	require.Equal(t, 0, exp.GetConnectionCount(), "not connected yet")
	exp.Start()
	defer exp.Stop()
	require.Equal(t, 1, exp.GetConnectionCount(), "connected after Start")
}

// TestGetSubscribedAddresses verifies address subscription tracking.
func TestGetSubscribedAddresses(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []any{})
		case "blockchain.scripthash.subscribe":
			writeResponse(conn, reqID(req), nil) // null status = no history
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	require.Empty(t, exp.GetSubscribedAddresses())
	require.False(t, exp.IsAddressSubscribed(addr))

	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	require.Contains(t, exp.GetSubscribedAddresses(), addr)
	require.True(t, exp.IsAddressSubscribed(addr))
}

// TestUnsubscribeForAddresses verifies that unsubscribed addresses are removed from tracking.
func TestUnsubscribeForAddresses(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []any{})
		case "blockchain.scripthash.subscribe":
			writeResponse(conn, reqID(req), nil)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)
	require.True(t, exp.IsAddressSubscribed(addr))

	err = exp.UnsubscribeForAddresses([]string{addr})
	require.NoError(t, err)
	require.False(t, exp.IsAddressSubscribed(addr))
	require.Empty(t, exp.GetSubscribedAddresses())
}

// TestGetAddressesEvents verifies that GetAddressesEvents returns a readable channel.
func TestGetAddressesEvents(t *testing.T) {
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		if reqMethod(req) == "server.version" {
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	ch := exp.GetAddressesEvents()
	require.NotNil(t, ch)

	// Channel should be non-nil and not immediately closed.
	select {
	case _, ok := <-ch:
		if !ok {
			t.Fatal("channel closed immediately")
		}
	default:
		// expected: no event yet
	}
}

// TestDuplicateSubscription verifies that subscribing to the same address twice
// does not result in duplicate entries.
func TestDuplicateSubscription(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	subscribeCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []any{})
		case "blockchain.scripthash.subscribe":
			subscribeCount++
			writeResponse(conn, reqID(req), nil)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)
	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	require.Len(t, exp.GetSubscribedAddresses(), 1)
	require.Equal(t, 1, subscribeCount, "server should receive subscribe only once")
}

// TestRequestTimeout verifies that a request returns an error if the server never responds.
func TestRequestTimeout(t *testing.T) {
	// Server accepts the connection but never sends responses after handshake.
	handshakeDone := make(chan struct{})
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		if reqMethod(req) == "server.version" {
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
			select {
			case <-handshakeDone:
			default:
				close(handshakeDone)
			}
		}
		// All other requests: no response (simulate timeout).
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	// Wait for handshake.
	select {
	case <-handshakeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake timed out")
	}

	// GetTxHex should time out since the server won't respond.
	_, err = exp.GetTxHex("sometxid")
	require.Error(t, err)
	require.Contains(t, err.Error(), "timed out")
}

// TestCleanEOFTriggersReconnect verifies that a clean TCP close (FIN, EOF) from the
// server causes the client to reconnect, not silently stop. This covers the case
// where an ElectrumX server restarts gracefully.
func TestCleanEOFTriggersReconnect(t *testing.T) {
	var connectCount atomic.Int32
	reconnectCh := make(chan struct{}, 1)

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			n := connectCount.Add(1)
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
			if n == 1 {
				// Close the connection cleanly after the first handshake.
				conn.Close() // nolint
			} else {
				select {
				case reconnectCh <- struct{}{}:
				default:
				}
			}
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	select {
	case <-reconnectCh:
		// Client reconnected after the server's clean close.
	case <-time.After(10 * time.Second):
		t.Fatal("client did not reconnect after clean server close (EOF)")
	}
}

// TestKeepaliveGoroutineDoesNotLeak verifies that keepAlive goroutines do not
// accumulate across reconnects. Without the cycle-context fix, every reconnect
// spawned a new keepAlive without stopping the previous one; after N reconnects
// there would be N+1 keepAlive goroutines all pinging the same connection.
//
// Strategy: record goroutine count after the first stable connection, force N
// reconnects by having the server close connections, wait for the final stable
// connection, then record again. With the fix the delta is ≈0; with the bug it
// grows by N (one leaked keepAlive per reconnect).
func TestKeepaliveGoroutineDoesNotLeak(t *testing.T) {
	const reconnects = 3

	var connectCount int32
	// connReadyCh carries connections so the test can close them on demand.
	connReadyCh := make(chan net.Conn, reconnects+1)
	lastConnectedCh := make(chan struct{}, 1)

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
			n := int(atomic.AddInt32(&connectCount, 1))
			if n <= reconnects {
				// Hand the connection to the test goroutine so it can close it.
				connReadyCh <- conn
			} else {
				// Final stable connection — signal ready.
				select {
				case lastConnectedCh <- struct{}{}:
				default:
				}
			}
		case "server.ping":
			writeResponse(conn, reqID(req), true)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	// Wait for the first connection and snapshot goroutine count.
	var firstConn net.Conn
	select {
	case firstConn = <-connReadyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("initial connect timed out")
	}
	time.Sleep(50 * time.Millisecond) // let listen+keepAlive goroutines settle
	afterFirst := runtime.NumGoroutine()

	// Close each connection in turn to trigger successive reconnects.
	firstConn.Close() // nolint
	for i := 1; i < reconnects; i++ {
		var c net.Conn
		select {
		case c = <-connReadyCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("reconnect %d timed out", i)
		}
		c.Close() // nolint
	}

	// Wait for the final stable connection.
	select {
	case <-lastConnectedCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("client did not complete all %d reconnects", reconnects)
	}
	time.Sleep(100 * time.Millisecond) // let old keepAlive goroutines exit
	runtime.Gosched()

	afterAll := runtime.NumGoroutine()

	// With the fix: each reconnect cancels the old keepAlive before starting the
	// new one, so the net goroutine delta should be ≈0. With the bug: N leaked
	// keepAlives remain, making the delta ≈N. Slack of 2 for Go runtime fluctuation.
	require.LessOrEqual(t, afterAll-afterFirst, 2,
		"goroutine count grew by %d after %d reconnects — likely keepAlive goroutine leak",
		afterAll-afterFirst, reconnects)
}

// TestConcurrentRequestsDoNotInterleave verifies that concurrent JSON-RPC requests
// are serialised on the wire so that frames are never interleaved. The server
// echoes each request's id back; if bytes interleaved, the JSON parser would
// return errors or mismatched ids, which would cause the test to fail or hang.
func TestConcurrentRequestsDoNotInterleave(t *testing.T) {
	const workers = 20

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), "deadbeef")
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			txHex, err := exp.GetTxHex(fmt.Sprintf("txid%d", i))
			if err != nil {
				errs <- fmt.Errorf("worker %d: %w", i, err)
				return
			}
			if txHex != "deadbeef" {
				errs <- fmt.Errorf("worker %d: unexpected txHex %q", i, txHex)
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
}

// TestBroadcastNoTxs verifies that Broadcast with no arguments returns an error.
func TestBroadcastNoTxs(t *testing.T) {
	exp, err := electrum_explorer.NewExplorer("tcp://127.0.0.1:1", arklib.Bitcoin)
	require.NoError(t, err)

	_, err = exp.Broadcast()
	require.ErrorContains(t, err, "no txs to broadcast")
}

// fakeBlockHeader is an 80-byte Bitcoin block header (160 hex chars).
// Timestamp is at bytes 68-71 LE: 0x78563412 = big-endian 0x12345678 = 305419896.
const fakeBlockHeader = "0100000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"00000000785634120000000000000000"

const fakeBlockTime = int64(305419896)

// P2WPKH script for bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq (mainnet).
const addrScript = "0014e8df018c7e326cc253faac7e46cdc51e68542c42"

// minimalTxHex: 1 null-outpoint input, 1 OP_1 output (1000 sat). Used when
// only a syntactically valid TX is needed (e.g. GetTxOutspends error paths).
const minimalTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01e803000000000000015100000000"

// addrTxHex: 1 null-outpoint input, 1 P2WPKH output (100000 sat, addrScript).
// When decoded, Vout[0].Address == "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".
const addrTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff01a086010000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000"

// precisionTxHex: same structure as addrTxHex but with 123456789 sat output.
const precisionTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0115cd5b0700000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000"

// twoOutputTxHex: 1 null-outpoint input, 2 outputs (OP_1 @ 1000sat, OP_2 @ 2000sat).
const twoOutputTxHex = "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff02e8030000000000000151d007000000000000015200000000"

// Proper 64-hex-char txids (all same nibble so byte-reversing is a no-op, making
// Hash.String() return the same string as the txid literal — required for
// PreviousOutPoint.Hash.String() comparisons inside GetTxOutspends).
const (
	parentTxid    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	existTxid     = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	multivoutTxid = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	prevTxid      = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// spendingTxHex builds a raw TX that spends output vout of hash (64-hex-char txid).
// The TX has no outputs. hash must be a 64-char all-same-nibble hex string so that
// big-endian and little-endian byte orderings are identical.
func spendingTxHex(hash string, vout uint32) string {
	// vout as 4-byte little-endian hex
	indexHex := fmt.Sprintf("%02x%02x%02x%02x",
		vout&0xff, (vout>>8)&0xff, (vout>>16)&0xff, (vout>>24)&0xff)
	return "02000000" + "01" +
		hash + indexHex + "00" + "ffffffff" +
		"00" + "00000000"
}

// inputTxHex builds a raw TX with one P2WPKH output (value in satoshis) and
// one input spending hash:vout. Used for TestGetTxsInputFields.
func inputTxHex(hash string, vout uint32, valueSat int64) string {
	indexHex := fmt.Sprintf("%02x%02x%02x%02x",
		vout&0xff, (vout>>8)&0xff, (vout>>16)&0xff, (vout>>24)&0xff)
	valueHex := fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
		valueSat&0xff, (valueSat>>8)&0xff, (valueSat>>16)&0xff, (valueSat>>24)&0xff,
		(valueSat>>32)&0xff, (valueSat>>40)&0xff, (valueSat>>48)&0xff, (valueSat>>56)&0xff)
	return "02000000" + "01" +
		hash + indexHex + "00" + "ffffffff" +
		"01" + valueHex + "16" + addrScript + "00000000"
}

// reqStringParam extracts the string at index idx from the params array of a request.
func reqStringParam(req map[string]json.RawMessage, idx int) string {
	var params []json.RawMessage
	json.Unmarshal(req["params"], &params) // nolint
	if idx >= len(params) {
		return ""
	}
	var s string
	json.Unmarshal(params[idx], &s) // nolint
	return s
}

// TestGetTxBlockTime verifies that GetTxBlockTime fetches the block header and
// parses the correct timestamp from the 80-byte header.
func TestGetTxBlockTime(t *testing.T) {
	const txid = "abc"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), addrTxHex)
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 100},
			})
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	confirmed, blocktime, err := exp.GetTxBlockTime(txid)
	require.NoError(t, err)
	require.True(t, confirmed)
	require.Equal(t, fakeBlockTime, blocktime)
}

// TestGetTxs verifies that GetTxs returns correctly assembled transaction history,
// including the Address field on each output (required by addressTxHistoryToUtxos).
func TestGetTxs(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const txid = "deadbeef"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 100},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), addrTxHex)
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.Equal(t, txid, txs[0].Txid)
	require.True(t, txs[0].Status.Confirmed)
	require.Equal(t, fakeBlockTime, txs[0].Status.BlockTime)
	require.Len(t, txs[0].Vout, 1)
	// Address must be populated so that addressTxHistoryToUtxos can match outputs.
	require.Equal(t, addr, txs[0].Vout[0].Address)
}

// TestGetUtxos verifies that GetUtxos returns confirmed UTXOs with correct blocktime.
func TestGetUtxos(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const txid = "utxotx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "tx_pos": 0, "value": 5000, "height": 100},
			})
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	utxos, err := exp.GetUtxos([]string{addr})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.Equal(t, txid, utxos[0].Txid)
	require.Equal(t, uint32(0), utxos[0].Vout)
	require.Equal(t, uint64(5000), utxos[0].Amount)
	require.NotEmpty(t, utxos[0].Script)
	require.True(t, utxos[0].Status.Confirmed)
	require.Equal(t, fakeBlockTime, utxos[0].Status.BlockTime)
}

// TestGetTxOutspends verifies that GetTxOutspends identifies the spending transaction
// by scanning the scripthash history of each output.
func TestGetTxOutspends(t *testing.T) {
	const spenderTxid = "spender_tx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			switch reqStringParam(req, 0) {
			case parentTxid:
				writeResponse(conn, reqID(req), minimalTxHex)
			case spenderTxid:
				writeResponse(conn, reqID(req), spendingTxHex(parentTxid, 0))
			}
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": parentTxid, "height": 100},
				{"tx_hash": spenderTxid, "height": 101},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	outspends, err := exp.GetTxOutspends(parentTxid)
	require.NoError(t, err)
	require.Len(t, outspends, 1)
	require.True(t, outspends[0].Spent)
	require.Equal(t, spenderTxid, outspends[0].SpentBy)
}

// TestPushNotificationTriggersEvent verifies that an ElectrumX scripthash push
// notification causes an immediate address poll and fires an OnchainAddressEvent.
func TestPushNotificationTriggersEvent(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	connCh := make(chan net.Conn, 1)
	scripthashCh := make(chan string, 1)
	listunspentCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		select {
		case connCh <- conn:
		default:
		}
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			listunspentCount++
			if listunspentCount == 1 {
				writeResponse(conn, reqID(req), []any{})
			} else {
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": "newtx", "tx_pos": 0, "value": 1000, "height": 0},
				})
			}
		case "blockchain.scripthash.subscribe":
			select {
			case scripthashCh <- reqStringParam(req, 0):
			default:
			}
			writeResponse(conn, reqID(req), nil)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	eventCh := exp.GetAddressesEvents()

	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	var conn net.Conn
	select {
	case conn = <-connCh:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive connection from mock")
	}

	var scripthash string
	select {
	case scripthash = <-scripthashCh:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive scripthash from mock")
	}

	// Push an ElectrumX notification — the client's listen() goroutine will read
	// it and forward the new status to the per-address notifCh, triggering a poll.
	notif := fmt.Sprintf(
		`{"method":"blockchain.scripthash.subscribe","params":[%q,"newstatus"]}`,
		scripthash,
	)
	conn.Write([]byte(notif + "\n")) // nolint

	select {
	case event := <-eventCh:
		require.NoError(t, event.Error)
		require.Len(t, event.NewUtxos, 1)
		require.Equal(t, "newtx", event.NewUtxos[0].Txid)
	case <-time.After(2 * time.Second):
		t.Fatal("expected OnchainAddressEvent from push notification, got none")
	}
}

// TestNewConfirmedUTXOHasCreatedAt verifies that when a push notification triggers
// a poll and reveals a new confirmed UTXO, the event's NewUtxos entry has CreatedAt
// populated from the block header timestamp (not from the block height).
func TestNewConfirmedUTXOHasCreatedAt(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	connCh := make(chan net.Conn, 1)
	scripthashCh := make(chan string, 1)
	listunspentCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		select {
		case connCh <- conn:
		default:
		}
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			listunspentCount++
			if listunspentCount == 1 {
				writeResponse(conn, reqID(req), []any{})
			} else {
				// New UTXO that is already confirmed at height 100.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": "newtx", "tx_pos": 0, "value": 1000, "height": 100},
				})
			}
		case "blockchain.scripthash.subscribe":
			select {
			case scripthashCh <- reqStringParam(req, 0):
			default:
			}
			writeResponse(conn, reqID(req), nil)
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	eventCh := exp.GetAddressesEvents()
	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	var conn net.Conn
	select {
	case conn = <-connCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	var scripthash string
	select {
	case scripthash = <-scripthashCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no scripthash")
	}

	notif := fmt.Sprintf(
		`{"method":"blockchain.scripthash.subscribe","params":[%q,"newstatus"]}`,
		scripthash,
	)
	conn.Write([]byte(notif + "\n")) // nolint

	select {
	case event := <-eventCh:
		require.NoError(t, event.Error)
		require.Len(t, event.NewUtxos, 1)
		// CreatedAt must come from the block header timestamp, not from block height.
		require.False(t, event.NewUtxos[0].CreatedAt.IsZero(), "CreatedAt should be set")
		require.Equal(t, time.Unix(fakeBlockTime, 0), event.NewUtxos[0].CreatedAt)
	case <-time.After(2 * time.Second):
		t.Fatal("expected event with CreatedAt, got none")
	}
}

// TestConfirmedUTXOEventHasCreatedAt verifies that when an unconfirmed UTXO confirms,
// the ConfirmedUtxos entry has CreatedAt populated from the block header.
func TestConfirmedUTXOEventHasCreatedAt(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	connCh := make(chan net.Conn, 1)
	scripthashCh := make(chan string, 1)
	listunspentCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		select {
		case connCh <- conn:
		default:
		}
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			listunspentCount++
			if listunspentCount == 1 {
				// Initial state: one unconfirmed UTXO.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": "pendtx", "tx_pos": 0, "value": 2000, "height": 0},
				})
			} else {
				// Same UTXO is now confirmed at height 100.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": "pendtx", "tx_pos": 0, "value": 2000, "height": 100},
				})
			}
		case "blockchain.scripthash.subscribe":
			select {
			case scripthashCh <- reqStringParam(req, 0):
			default:
			}
			writeResponse(conn, reqID(req), nil)
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	eventCh := exp.GetAddressesEvents()
	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	var conn net.Conn
	select {
	case conn = <-connCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	var scripthash string
	select {
	case scripthash = <-scripthashCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no scripthash")
	}

	notif := fmt.Sprintf(
		`{"method":"blockchain.scripthash.subscribe","params":[%q,"newstatus"]}`,
		scripthash,
	)
	conn.Write([]byte(notif + "\n")) // nolint

	// The initial poll fires a NewUtxos event for the pre-existing pending UTXO.
	// Keep reading until we see the ConfirmedUtxos event from the push notification.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case event := <-eventCh:
			require.NoError(t, event.Error)
			if len(event.ConfirmedUtxos) == 0 {
				continue
			}
			require.Len(t, event.ConfirmedUtxos, 1, "expected a confirmed UTXO event")
			require.Equal(t, "pendtx", event.ConfirmedUtxos[0].Txid)
			require.Equal(t, time.Unix(fakeBlockTime, 0), event.ConfirmedUtxos[0].CreatedAt)
			return
		case <-deadline:
			t.Fatal("expected confirmed event with CreatedAt, got none")
		}
	}
}

// TestSpentUTXOEventHasSpentBy verifies that when a UTXO disappears from the UTXO
// set, the SpentUtxos entry has SpentBy populated via GetTxOutspends.
func TestSpentUTXOEventHasSpentBy(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const spenderTxid = "spender_tx"

	connCh := make(chan net.Conn, 1)
	scripthashCh := make(chan string, 1)
	listunspentCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		select {
		case connCh <- conn:
		default:
		}
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			listunspentCount++
			if listunspentCount == 1 {
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": existTxid, "tx_pos": 0, "value": 3000, "height": 100},
				})
			} else {
				writeResponse(conn, reqID(req), []any{})
			}
		case "blockchain.scripthash.subscribe":
			select {
			case scripthashCh <- reqStringParam(req, 0):
			default:
			}
			writeResponse(conn, reqID(req), nil)
		case "blockchain.transaction.get":
			switch reqStringParam(req, 0) {
			case existTxid:
				writeResponse(conn, reqID(req), minimalTxHex)
			case spenderTxid:
				writeResponse(conn, reqID(req), spendingTxHex(existTxid, 0))
			}
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": existTxid, "height": 100},
				{"tx_hash": spenderTxid, "height": 101},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(true),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	eventCh := exp.GetAddressesEvents()
	err = exp.SubscribeForAddresses([]string{addr})
	require.NoError(t, err)

	var conn net.Conn
	select {
	case conn = <-connCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection")
	}
	var scripthash string
	select {
	case scripthash = <-scripthashCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no scripthash")
	}

	notif := fmt.Sprintf(
		`{"method":"blockchain.scripthash.subscribe","params":[%q,"newstatus"]}`,
		scripthash,
	)
	conn.Write([]byte(notif + "\n")) // nolint

	// The initial poll fires a NewUtxos event for the pre-existing confirmed UTXO.
	// Keep reading until we see the SpentUtxos event from the push notification.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case event := <-eventCh:
			require.NoError(t, event.Error)
			if len(event.SpentUtxos) == 0 {
				continue
			}
			require.Len(t, event.SpentUtxos, 1, "expected a spent UTXO event")
			require.Equal(t, existTxid, event.SpentUtxos[0].Txid)
			require.Equal(t, spenderTxid, event.SpentUtxos[0].SpentBy,
				"SpentBy must be populated via GetTxOutspends")
			return
		case <-deadline:
			t.Fatal("expected spent event with SpentBy, got none")
		}
	}
}

// TestGetTxsAmountPrecision verifies that BTC float values are rounded to the nearest
// satoshi rather than truncated. For example, 1.23456789 BTC * 1e8 in IEEE-754 float64
// is 123456788.99..., which truncation would convert to 123456788 instead of 123456789.
func TestGetTxsAmountPrecision(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const txid = "precisiontx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 0},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), precisionTxHex)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.Equal(t, uint64(123456789), txs[0].Vout[0].Amount,
		"amount must be rounded, not truncated")
}

// TestGetTxsUnconfirmed verifies that a transaction with height=0 in the history
// is returned with Status.Confirmed=false and Status.BlockTime=0 (not -1).
// BlockTime=0 is the sentinel value used by callers to detect unconfirmed transactions.
func TestGetTxsUnconfirmed(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const txid = "mempooltx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 0},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), addrTxHex)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.False(t, txs[0].Status.Confirmed, "unconfirmed tx must have Confirmed=false")
	require.Equal(t, int64(0), txs[0].Status.BlockTime,
		"unconfirmed tx must have BlockTime=0, not -1")
}

// TestGetTxsInputFields verifies that input prevout fields (Txid, Vout) are populated
// from the decoded raw transaction. Script/Address/Amount are not available because
// electrs-esplora does not support verbose transactions.
func TestGetTxsInputFields(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const spendingTxid = "spendingtx"
	const prevVout = uint32(2)

	// inputTxHex encodes prevTxid ("eeee...ee") as the prevout hash. Since all bytes
	// are identical, byte-reversal is a no-op, so Hash.String() == prevTxid.
	spendingHex := inputTxHex(prevTxid, prevVout, 50000)

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": spendingTxid, "height": 0},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), spendingHex)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.Len(t, txs[0].Vin, 1)

	in := txs[0].Vin[0]
	require.Equal(t, prevTxid, in.Txid, "Input.Txid must match prevout tx")
	require.Equal(t, prevVout, in.Vout, "Input.Vout must match prevout index")
}

// TestGetTxBlockTimeUnconfirmed verifies that GetTxBlockTime returns (false, 0, nil)
// for an unconfirmed transaction. 0 is the same sentinel used by GetTxs and GetUtxos.
func TestGetTxBlockTimeUnconfirmed(t *testing.T) {
	const txid = "mempooltx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), minimalTxHex)
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 0},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	confirmed, blocktime, err := exp.GetTxBlockTime(txid)
	require.NoError(t, err)
	require.False(t, confirmed)
	require.Equal(t, int64(0), blocktime,
		"unconfirmed tx must return blocktime=0, consistent with GetTxs and GetUtxos")
}

// TestGetTxBlockTimeUsesVerboseBlocktime verifies that GetTxBlockTime always calls
// blockchain.block.header to get the block timestamp for confirmed transactions.
// (The previous optimization that skipped the header fetch when verbose TX had blocktime
// no longer applies because electrs-esplora does not support verbose transactions.)
func TestGetTxBlockTimeUsesVerboseBlocktime(t *testing.T) {
	const txid = "confirmedtx"
	blockHeaderCalled := false

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), addrTxHex)
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 100},
			})
		case "blockchain.block.header":
			blockHeaderCalled = true
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	confirmed, blocktime, err := exp.GetTxBlockTime(txid)
	require.NoError(t, err)
	require.True(t, confirmed)
	require.Equal(t, fakeBlockTime, blocktime)
	require.True(t, blockHeaderCalled,
		"blockchain.block.header must be called for confirmed tx")
}

// TestGetTxOutspendsUnspent verifies that an output with no spenders returns
// SpentStatus{Spent: false, SpentBy: ""}, matching mempool explorer behavior.
func TestGetTxOutspendsUnspent(t *testing.T) {
	const txid = "mytx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), minimalTxHex)
		case "blockchain.scripthash.get_history":
			// Only the creating tx — no spenders.
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 100},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	outspends, err := exp.GetTxOutspends(txid)
	require.NoError(t, err)
	require.Len(t, outspends, 1)
	require.False(t, outspends[0].Spent, "unspent output must have Spent=false")
	require.Empty(t, outspends[0].SpentBy, "unspent output must have SpentBy empty")
}

// TestGetTxOutspendsMultipleOutputs verifies per-output tracking when a tx has multiple
// outputs and only one is spent — the spent vout index must match the spender's input.
func TestGetTxOutspendsMultipleOutputs(t *testing.T) {
	const spenderTxid = "spender"

	// GetTxOutspends processes outputs in index order (0, 1), so the first
	// blockchain.scripthash.get_history call is for vout 0 and the second for vout 1.
	historyCallCount := 0

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			switch reqStringParam(req, 0) {
			case multivoutTxid:
				writeResponse(conn, reqID(req), twoOutputTxHex)
			case spenderTxid:
				// spendingTxHex encodes multivoutTxid as the prevout hash; since all
				// bytes are identical ("dd"), Hash.String() == multivoutTxid.
				writeResponse(conn, reqID(req), spendingTxHex(multivoutTxid, 0))
			}
		case "blockchain.scripthash.get_history":
			historyCallCount++
			if historyCallCount == 1 {
				// First call is for vout 0 (OP_1 script) — it has a spender.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": multivoutTxid, "height": 100},
					{"tx_hash": spenderTxid, "height": 101},
				})
			} else {
				// Second call is for vout 1 (OP_2 script) — no spenders.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": multivoutTxid, "height": 100},
				})
			}
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	outspends, err := exp.GetTxOutspends(multivoutTxid)
	require.NoError(t, err)
	require.Len(t, outspends, 2)
	require.True(t, outspends[0].Spent, "vout 0 must be spent")
	require.Equal(t, spenderTxid, outspends[0].SpentBy)
	require.False(t, outspends[1].Spent, "vout 1 must be unspent")
	require.Empty(t, outspends[1].SpentBy)
}

// TestGetUtxosUnconfirmed verifies that a UTXO with height=0 is returned with
// Status.Confirmed=false and Status.BlockTime=0, matching mempool explorer behavior.
func TestGetUtxosUnconfirmed(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const txid = "mempoolutxo"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "tx_pos": 0, "value": 7000, "height": 0},
			})
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	utxos, err := exp.GetUtxos([]string{addr})
	require.NoError(t, err)
	require.Len(t, utxos, 1)
	require.False(t, utxos[0].Status.Confirmed, "unconfirmed UTXO must have Confirmed=false")
	require.Equal(t, int64(0), utxos[0].Status.BlockTime,
		"unconfirmed UTXO must have BlockTime=0 so callers use time.Now() for delay calculation")
}

// TestGetRedeemedVtxosBalance verifies the spendable/locked split.
// An old confirmed UTXO (fakeBlockTime = 1979) with a 1000-second delay is spendable now.
// An unconfirmed UTXO with a 1000-second delay is locked (availableAt = now+1000s).
func TestGetRedeemedVtxosBalance(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.listunspent":
			writeResponse(conn, reqID(req), []map[string]any{
				// Confirmed at a very old block (fakeBlockTime) — always spendable.
				{"tx_hash": "oldtx", "tx_pos": 0, "value": 10000, "height": 100},
				// Unconfirmed — locked for the full delay duration.
				{"tx_hash": "newpending", "tx_pos": 0, "value": 5000, "height": 0},
			})
		case "blockchain.block.header":
			writeResponse(conn, reqID(req), fakeBlockHeader)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	delay := arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 1000}

	spendable, locked, err := exp.GetRedeemedVtxosBalance(addr, delay)
	require.NoError(t, err)
	require.Equal(t, uint64(10000), spendable,
		"old confirmed UTXO must be spendable (delay already elapsed)")
	require.Len(t, locked, 1, "unconfirmed UTXO must be locked for the delay duration")
	for _, amt := range locked {
		require.Equal(t, uint64(5000), amt)
	}
}

// TestBroadcastMultipleReturnsFirstTxid verifies that when multiple transactions are
// broadcast, the returned txid is that of the first transaction.
func TestBroadcastMultipleReturnsFirstTxid(t *testing.T) {
	// Two minimal valid raw transactions (version 2 and version 1, each with no inputs/outputs).
	const tx1 = "02000000000000000000"
	const tx2 = "01000000000000000000"
	const firstTxid = "aaaa"

	callCount := 0
	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.broadcast":
			callCount++
			if callCount == 1 {
				writeResponse(conn, reqID(req), firstTxid)
			} else {
				writeResponse(conn, reqID(req), "bbbb")
			}
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txid, err := exp.Broadcast(tx1, tx2)
	require.NoError(t, err)
	require.Equal(t, firstTxid, txid, "must return txid of first broadcast")
	require.Equal(t, 2, callCount, "must broadcast both transactions")
}

// TestGetTxHexServedFromBroadcastCache verifies that after a successful Broadcast,
// a subsequent GetTxHex call for the same txid is served from cache without an RPC call.
// The server returns null for the broadcast response so that Broadcast falls back to the
// locally computed txid — the same key under which the tx hex was cached.
func TestGetTxHexServedFromBroadcastCache(t *testing.T) {
	const rawTx = "02000000000000000000"
	getTxHexCalled := false

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.broadcast":
			// Return null so Broadcast falls back to the locally parsed txid,
			// which matches the cache key set during broadcast.
			writeResponse(conn, reqID(req), nil)
		case "blockchain.transaction.get":
			getTxHexCalled = true
			writeResponse(conn, reqID(req), rawTx)
		}
	})

	exp, err := electrum_explorer.NewExplorer(
		serverURL,
		arklib.Bitcoin,
		electrum_explorer.WithTracker(false),
	)
	require.NoError(t, err)
	exp.Start()
	defer exp.Stop()

	txid, err := exp.Broadcast(rawTx)
	require.NoError(t, err)
	require.NotEmpty(t, txid)

	_, err = exp.GetTxHex(txid)
	require.NoError(t, err)
	require.False(t, getTxHexCalled, "GetTxHex must use cache after Broadcast, no RPC needed")
}
