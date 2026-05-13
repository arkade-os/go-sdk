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

// Esplora REST API response types, used as fallback when the electrum
// scripthash index returns no results (e.g. for P2TR addresses on older
// electrs that don't index taproot scripts).

type esploraStatus struct {
	Confirmed   bool  `json:"confirmed"`
	BlockHeight int64 `json:"block_height"`
	BlockTime   int64 `json:"block_time"`
}

type esploraUtxo struct {
	Txid   string        `json:"txid"`
	Vout   uint32        `json:"vout"`
	Status esploraStatus `json:"status"`
	Value  uint64        `json:"value"`
}

type esploraVin struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type esploraVout struct {
	Scriptpubkey        string `json:"scriptpubkey"`
	ScriptpubkeyAddress string `json:"scriptpubkey_address"`
	Value               uint64 `json:"value"`
}

type esploraTxEntry struct {
	Txid   string        `json:"txid"`
	Vin    []esploraVin  `json:"vin"`
	Vout   []esploraVout `json:"vout"`
	Status esploraStatus `json:"status"`
}
