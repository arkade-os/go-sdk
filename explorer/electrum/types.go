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
	Error  *jsonRPCError   `json:"error"`
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

type electrumVerboseTx struct {
	Txid string             `json:"txid"`
	Vin  []electrumTxInput  `json:"vin"`
	Vout []electrumTxOutput `json:"vout"`
	// BlockHeight is -1 for unconfirmed transactions.
	BlockHeight   int64 `json:"blockheight"`
	Confirmations int   `json:"confirmations"`
	Blocktime     int64 `json:"blocktime"`
}

type electrumTxInput struct {
	TxID    string           `json:"txid"`
	Vout    uint32           `json:"vout"`
	Prevout electrumTxOutput `json:"prevout"`
}

type electrumTxOutput struct {
	N            uint32 `json:"n"`
	ScriptPubKey struct {
		Hex string `json:"hex"`
	} `json:"scriptpubkey"`
	// Value is in BTC for verbose transactions.
	Value float64 `json:"value"`
}
