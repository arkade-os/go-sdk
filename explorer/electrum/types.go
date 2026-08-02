package electrum_explorer

import "encoding/json"

// JSON-RPC wire types for the ElectrumX protocol.

type jsonRPCRequest struct {
	ID     uint64 `json:"id"`
	Method string `json:"method"`
	Params []any  `json:"params"`
}

type jsonRPCResponse struct {
	ID     uint64          `json:"id"`
	Result json.RawMessage `json:"result"`
	// Error is kept as RawMessage because electrs-esplora sends a plain string
	// while the JSON-RPC spec and ElectrumX send a {code, message} object.
	// Parsing is deferred to parseRPCError so listen() never drops valid responses
	// due to an unexpected error-field type.
	Error json.RawMessage `json:"error"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// jsonRPCNotification is a server-pushed message with no "id" field.
type jsonRPCNotification struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// ElectrumX result types.

type electrumHistoryEntry struct {
	TxHash string `json:"tx_hash"`
	Height int64  `json:"height"`
}

type electrumUTXO struct {
	TxHash string `json:"tx_hash"`
	TxPos  uint32 `json:"tx_pos"`
	Value  uint64 `json:"value"`
	Height int64  `json:"height"`
}
