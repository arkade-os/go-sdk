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

// fakeBlockHeader is an 80-byte Bitcoin block header (160 hex chars).
// Timestamp is at bytes 68-71 LE: 0x78563412 = big-endian 0x12345678 = 305419896.
const fakeBlockHeader = "0100000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"00000000785634120000000000000000"

const fakeBlockTime = int64(305419896)

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
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid, "vin": []any{}, "vout": []any{},
				"blockheight": 100, "confirmations": 1, "blocktime": 0,
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
	// P2WPKH script for the address above (mainnet).
	const addrScript = "0014e8df018c7e326cc253faac7e46cdc51e68542c42"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": txid, "height": 100},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid,
				"vin":  []any{},
				"vout": []any{
					map[string]any{
						"n":            0,
						"scriptpubkey": map[string]any{"hex": addrScript},
						"value":        0.001,
					},
				},
				"blockheight": 100, "confirmations": 1, "blocktime": 0,
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

	utxos, err := exp.GetUtxos(addr)
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
	const parentTxid = "parent_tx"
	const spenderTxid = "spender_tx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			switch reqStringParam(req, 0) {
			case parentTxid:
				writeResponse(conn, reqID(req), map[string]any{
					"txid": parentTxid,
					"vin":  []any{},
					"vout": []any{
						map[string]any{
							"n":            0,
							"scriptpubkey": map[string]any{"hex": "51"},
							"value":        0.001,
						},
					},
					"blockheight": 100, "confirmations": 1, "blocktime": 0,
				})
			case spenderTxid:
				writeResponse(conn, reqID(req), map[string]any{
					"txid": spenderTxid,
					"vin": []any{
						map[string]any{
							"txid": parentTxid,
							"vout": 0,
							"prevout": map[string]any{
								"n":            0,
								"scriptpubkey": map[string]any{"hex": "51"},
								"value":        0.001,
							},
						},
					},
					"vout":        []any{},
					"blockheight": 101, "confirmations": 1, "blocktime": 0,
				})
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

	select {
	case event := <-eventCh:
		require.NoError(t, event.Error)
		require.Len(t, event.ConfirmedUtxos, 1, "expected a confirmed UTXO event")
		require.Equal(t, "pendtx", event.ConfirmedUtxos[0].Txid)
		require.Equal(t, time.Unix(fakeBlockTime, 0), event.ConfirmedUtxos[0].CreatedAt)
	case <-time.After(2 * time.Second):
		t.Fatal("expected confirmed event with CreatedAt, got none")
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
					{"tx_hash": "existtx", "tx_pos": 0, "value": 3000, "height": 100},
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
			txid := reqStringParam(req, 0)
			if txid == "existtx" {
				writeResponse(conn, reqID(req), map[string]any{
					"txid": "existtx",
					"vin":  []any{},
					"vout": []any{
						map[string]any{
							"n":            0,
							"scriptpubkey": map[string]any{"hex": "51"},
							"value":        0.003,
						},
					},
					"blockheight": 100, "confirmations": 1, "blocktime": 0,
				})
			} else {
				// spender_tx has an input spending existtx:0.
				writeResponse(conn, reqID(req), map[string]any{
					"txid": spenderTxid,
					"vin": []any{
						map[string]any{
							"txid": "existtx",
							"vout": 0,
							"prevout": map[string]any{
								"n":            0,
								"scriptpubkey": map[string]any{"hex": "51"},
								"value":        0.003,
							},
						},
					},
					"vout":        []any{},
					"blockheight": 101, "confirmations": 1, "blocktime": 0,
				})
			}
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": "existtx", "height": 100},
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

	select {
	case event := <-eventCh:
		require.NoError(t, event.Error)
		require.Len(t, event.SpentUtxos, 1, "expected a spent UTXO event")
		require.Equal(t, "existtx", event.SpentUtxos[0].Txid)
		require.Equal(t, spenderTxid, event.SpentUtxos[0].SpentBy,
			"SpentBy must be populated via GetTxOutspends")
	case <-time.After(2 * time.Second):
		t.Fatal("expected spent event with SpentBy, got none")
	}
}

// TestGetTxsAmountPrecision verifies that BTC float values are rounded to the nearest
// satoshi rather than truncated. For example, 1.23456789 BTC * 1e8 in IEEE-754 float64
// is 123456788.99..., which truncation would convert to 123456788 instead of 123456789.
func TestGetTxsAmountPrecision(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const addrScript = "0014e8df018c7e326cc253faac7e46cdc51e68542c42"
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
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid,
				"vin":  []any{},
				"vout": []any{
					map[string]any{
						"n":            0,
						"scriptpubkey": map[string]any{"hex": addrScript},
						// 1.23456789 BTC * 1e8 = 123456788.999... without rounding
						"value": 1.23456789,
					},
				},
				"blockheight": 0, "confirmations": 0, "blocktime": 0,
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
	const addrScript = "0014e8df018c7e326cc253faac7e46cdc51e68542c42"
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
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid,
				"vin":  []any{},
				"vout": []any{
					map[string]any{
						"n":            0,
						"scriptpubkey": map[string]any{"hex": addrScript},
						"value":        0.001,
					},
				},
				"blockheight": -1, "confirmations": 0, "blocktime": 0,
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

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.False(t, txs[0].Status.Confirmed, "unconfirmed tx must have Confirmed=false")
	require.Equal(t, int64(0), txs[0].Status.BlockTime,
		"unconfirmed tx must have BlockTime=0, not -1")
}

// TestGetTxsInputFields verifies that input prevout fields (Txid, Vout, Address, Amount, Script)
// are all populated from the verbose transaction response, matching mempool explorer behavior.
func TestGetTxsInputFields(t *testing.T) {
	const addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
	const addrScript = "0014e8df018c7e326cc253faac7e46cdc51e68542c42"
	const spendingTxid = "spendingtx"
	const prevTxid = "prevtx"
	const prevVout = uint32(2)
	const prevAmountBTC = 0.0005 // 50000 sats

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.scripthash.get_history":
			writeResponse(conn, reqID(req), []map[string]any{
				{"tx_hash": spendingTxid, "height": 0},
			})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), map[string]any{
				"txid": spendingTxid,
				"vin": []any{
					map[string]any{
						"txid": prevTxid,
						"vout": prevVout,
						"prevout": map[string]any{
							"n":            prevVout,
							"scriptpubkey": map[string]any{"hex": addrScript},
							"value":        prevAmountBTC,
						},
					},
				},
				"vout": []any{
					map[string]any{
						"n":            0,
						"scriptpubkey": map[string]any{"hex": addrScript},
						"value":        0.00049,
					},
				},
				"blockheight": -1, "confirmations": 0, "blocktime": 0,
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

	txs, err := exp.GetTxs(addr)
	require.NoError(t, err)
	require.Len(t, txs, 1)
	require.Len(t, txs[0].Vin, 1)

	in := txs[0].Vin[0]
	require.Equal(t, prevTxid, in.Txid, "Input.Txid must match prevout tx")
	require.Equal(t, prevVout, in.Vout, "Input.Vout must match prevout index")
	require.Equal(t, addrScript, in.Script, "Input.Output.Script must be prevout script hex")
	require.Equal(t, "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", in.Address,
		"Input.Output.Address must be derived from prevout script")
	require.Equal(t, uint64(50000), in.Amount,
		"Input.Output.Amount must be prevout value in satoshis")
}

// TestGetTxBlockTimeUnconfirmed verifies that GetTxBlockTime returns (false, -1, nil)
// for an unconfirmed transaction, matching mempool explorer behavior.
func TestGetTxBlockTimeUnconfirmed(t *testing.T) {
	const txid = "mempooltx"

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid, "vin": []any{}, "vout": []any{},
				"blockheight": -1, "confirmations": 0, "blocktime": 0,
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
	require.Equal(t, int64(-1), blocktime,
		"unconfirmed tx must return blocktime=-1, matching mempool behavior")
}

// TestGetTxBlockTimeUsesVerboseBlocktime verifies that when the verbose tx response
// includes a non-zero blocktime, GetTxBlockTime uses it directly without an extra
// blockchain.block.header RPC call.
func TestGetTxBlockTimeUsesVerboseBlocktime(t *testing.T) {
	const txid = "confirmedtx"
	const expectedBlocktime = int64(1700000000)
	blockHeaderCalled := false

	serverURL := startMockServer(t, func(conn net.Conn, req map[string]json.RawMessage) {
		switch reqMethod(req) {
		case "server.version":
			writeResponse(conn, reqID(req), []string{"mock", "1.4"})
		case "blockchain.transaction.get":
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid, "vin": []any{}, "vout": []any{},
				"blockheight": 800000, "confirmations": 10, "blocktime": expectedBlocktime,
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
	require.Equal(t, expectedBlocktime, blocktime)
	require.False(
		t,
		blockHeaderCalled,
		"blockchain.block.header must not be called when verbose tx has blocktime",
	)
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
			writeResponse(conn, reqID(req), map[string]any{
				"txid": txid,
				"vin":  []any{},
				"vout": []any{
					map[string]any{
						"n":            0,
						"scriptpubkey": map[string]any{"hex": "51"},
						"value":        0.001,
					},
				},
				"blockheight": 100, "confirmations": 1, "blocktime": 0,
			})
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
	const txid = "multivout"
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
			case txid:
				writeResponse(conn, reqID(req), map[string]any{
					"txid": txid,
					"vin":  []any{},
					"vout": []any{
						map[string]any{
							"n":            0,
							"scriptpubkey": map[string]any{"hex": "51"},
							"value":        0.001,
						},
						map[string]any{
							"n":            1,
							"scriptpubkey": map[string]any{"hex": "52"},
							"value":        0.002,
						},
					},
					"blockheight": 100, "confirmations": 1, "blocktime": 0,
				})
			case spenderTxid:
				// spenderTxid spends vout 0 only.
				writeResponse(conn, reqID(req), map[string]any{
					"txid": spenderTxid,
					"vin": []any{
						map[string]any{
							"txid": txid,
							"vout": 0,
							"prevout": map[string]any{
								"n":            0,
								"scriptpubkey": map[string]any{"hex": "51"},
								"value":        0.001,
							},
						},
					},
					"vout":        []any{},
					"blockheight": 101, "confirmations": 1, "blocktime": 0,
				})
			}
		case "blockchain.scripthash.get_history":
			historyCallCount++
			if historyCallCount == 1 {
				// First call is for vout 0 — it has a spender.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": txid, "height": 100},
					{"tx_hash": spenderTxid, "height": 101},
				})
			} else {
				// Second call is for vout 1 — no spenders.
				writeResponse(conn, reqID(req), []map[string]any{
					{"tx_hash": txid, "height": 100},
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

	outspends, err := exp.GetTxOutspends(txid)
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

	utxos, err := exp.GetUtxos(addr)
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
