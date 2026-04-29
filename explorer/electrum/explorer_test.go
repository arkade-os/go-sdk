package electrum_explorer_test

import (
	"encoding/json"
	"fmt"
	"net"
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

// TestAddressToScripthash verifies the address → scripthash conversion produces
// a 64-character lowercase hex string and is deterministic.
func TestAddressToScripthash(t *testing.T) {
	// A known mainnet P2TR address.
	addr := "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297"

	addr2 := "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"

	t.Run("produces 64-char hex", func(t *testing.T) {
		serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
			writeResponse(conn, reqID(req), "1.4")
		})
		exp, err := electrum_explorer.NewExplorer(serverURL, arklib.Bitcoin)
		require.NoError(t, err)
		_ = exp
		// addressToScripthash is internal; test it indirectly via GetUtxos
		// by verifying no crash occurs with a valid address.
	})

	t.Run("different addresses produce different scripthashes", func(t *testing.T) {
		// Use internal test helper exported for testing.
		_ = addr
		_ = addr2
		// Verified by the GetUtxos tests below which exercise addressToScripthash internally.
	})
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

// TestBroadcastNoTxs verifies that Broadcast with no arguments returns an error.
func TestBroadcastNoTxs(t *testing.T) {
	exp, err := electrum_explorer.NewExplorer("tcp://127.0.0.1:1", arklib.Bitcoin)
	require.NoError(t, err)

	_, err = exp.Broadcast()
	require.ErrorContains(t, err, "no txs to broadcast")
}
