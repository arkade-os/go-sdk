package types

import (
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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
	Utxos []clientTypes.Utxo
}

type VtxoEventType int

const (
	VtxosAdded VtxoEventType = iota
	VtxosSpent
	VtxoSettled
	VtxosSwept
	VtxosUnrolled
)

func (e VtxoEventType) String() string {
	return map[VtxoEventType]string{
		VtxosAdded:    "VTXOS_ADDED",
		VtxosSpent:    "VTXOS_SPENT",
		VtxoSettled:   "VTXOS_SETTLED",
		VtxosSwept:    "VTXOS_SWEPT",
		VtxosUnrolled: "VTXOS_UNROLLED",
	}[e]
}

type VtxoEvent struct {
	Type  VtxoEventType
	Vtxos []clientTypes.Vtxo
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
		TxsUpdated:   "TXS_UPDATED",
	}[e]
}

type TransactionEvent struct {
	Type         TxEventType
	Txs          []clientTypes.Transaction
	Replacements map[string]string
}

type OnchainAddressEvent struct {
	Error          error
	SpentUtxos     []clientTypes.OnchainOutput
	NewUtxos       []clientTypes.OnchainOutput
	ConfirmedUtxos []clientTypes.OnchainOutput
	Replacements   map[string]string // replacedTxid -> replacementTxid
}

type SyncEvent struct {
	Synced bool
	Err    error
}

type ContractState string

const (
	ContractStateActive   ContractState = "active"
	ContractStateInactive ContractState = "inactive"
)

// MaxPageSize is the maximum number of VTXOs returned per page.
const MaxPageSize uint32 = 200

// Page specifies offset-based pagination for VTXO listing operations.
// PageNum is 1-based; 0 is treated as 1.
// PageSize 0 means "return all rows" (no LIMIT applied).
// PageSize values above MaxPageSize are clamped to MaxPageSize.
type Page struct {
	PageNum  uint32
	PageSize uint32
}

// VtxoFilter controls which VTXOs are returned by listing operations.
type VtxoFilter int

const (
	// VtxoFilterAll returns every VTXO regardless of state.
	VtxoFilterAll VtxoFilter = iota
	// VtxoFilterSpendable returns VTXOs that are not spent and not unrolled
	// (i.e. actively usable for new off-chain transactions).
	VtxoFilterSpendable
	// VtxoFilterSpent returns VTXOs that have been spent or unrolled.
	VtxoFilterSpent
	// VtxoFilterRecoverable returns VTXOs that are swept or expired but not
	// yet spent, meaning the owner can still recover them on-chain.
	VtxoFilterRecoverable
)

type ContractType string

const (
	ContractTypeDefault  ContractType = "default"
	ContractTypeBoarding ContractType = "boarding"
)

type Contract struct {
	Type      ContractType
	Label     string
	Params    map[string]string
	Script    string
	Address   string
	State     ContractState
	CreatedAt time.Time
	Metadata  map[string]string
}
