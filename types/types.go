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

// Balance represents the full wallet balance including both on-chain
// and off-chain (Ark) funds.
type Balance struct {
	OnchainBalance  OnchainBalance    `json:"onchain_balance"`
	OffchainBalance OffchainBalance   `json:"offchain_balance"`
	Total           uint64            `json:"total"`
	AssetBalances   map[string]uint64 `json:"asset_balances,omitempty"`
}

// OnchainBalance represents the on-chain (boarding) balance.
type OnchainBalance struct {
	Confirmed       uint64                 `json:"confirmed"`
	Unconfirmed     uint64                 `json:"unconfirmed"`
	Total           uint64                 `json:"total"`
	SpendableAmount uint64                 `json:"spendable_amount"`
	LockedAmount    []LockedOnchainBalance `json:"locked_amount,omitempty"`
}

// LockedOnchainBalance represents on-chain funds that are locked until
// a specific time.
type LockedOnchainBalance struct {
	SpendableAt string `json:"spendable_at"`
	Amount      uint64 `json:"amount"`
}

// OffchainBalance represents the off-chain (Ark) balance with state breakdowns.
type OffchainBalance struct {
	Total          uint64        `json:"total"`
	NextExpiration string        `json:"next_expiration,omitempty"`
	Details        []VtxoDetails `json:"details"`
	Available      uint64        `json:"available"`
	Preconfirmed   uint64        `json:"preconfirmed"`
	Recoverable    uint64        `json:"recoverable"`
	Settled        uint64        `json:"settled"`
}

// VtxoDetails provides per-expiration balance breakdown.
type VtxoDetails struct {
	ExpiryTime string `json:"expiry_time"`
	Amount     uint64 `json:"amount"`
}
