package types

import (
	sdktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

const (
	InMemoryStore = "inmemory"
	FileStore     = "file"
	KVStore       = "kv"
	SQLStore      = "sql"
)

type UtxoEventType int

const (
	UtxosAdded UtxoEventType = iota
	UtxosConfirmed
	UtxosReplaced
	UtxosSpent
)

func (e UtxoEventType) String() string {
	return map[UtxoEventType]string{
		UtxosAdded:     "UTXOS_ADDED",
		UtxosConfirmed: "UTXOS_CONFIRMED",
		UtxosReplaced:  "UTXOS_REPLACED",
		UtxosSpent:     "UTXOS_SPENT",
	}[e]
}

type UtxoEvent struct {
	Type  UtxoEventType
	Utxos []sdktypes.Utxo
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxosUpdated
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded:   "VTXOS_ADDED",
		VtxosSpent:   "VTXOS_SPENT",
		VtxosUpdated: "VTXOS_UPDATED",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []sdktypes.Vtxo
}

type TxEventType int

const (
	TxsAdded TxEventType = iota
	TxsSettled
	TxsConfirmed
	TxsReplaced
	TxsUpdated
)

func (e TxEventType) String() string {
	return map[TxEventType]string{
		TxsAdded:     "TXS_ADDED",
		TxsSettled:   "TXS_SETTLED",
		TxsConfirmed: "TXS_CONFIRMED",
		TxsReplaced:  "TXS_REPLACED",
	}[e]
}

type TransactionEvent struct {
	Type         TxEventType
	Txs          []sdktypes.Transaction
	Replacements map[string]string
}

type OnchainAddressEvent struct {
	Error          error
	SpentUtxos     []sdktypes.OnchainOutput
	NewUtxos       []sdktypes.OnchainOutput
	ConfirmedUtxos []sdktypes.OnchainOutput
	Replacements   map[string]string // replacedTxid -> replacementTxid
}

type SyncEvent struct {
	Synced bool
	Err    error
}
