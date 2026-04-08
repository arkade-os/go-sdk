package arksdk

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
	Available uint64 `json:"available"`
	Preconfirmed uint64 `json:"preconfirmed"`
	Recoverable uint64 `json:"recoverable"`
	Settled uint64 `json:"settled"`
}

// VtxoDetails provides per-expiration balance breakdown.
type VtxoDetails struct {
	ExpiryTime string `json:"expiry_time"`
	Amount     uint64 `json:"amount"`
}
