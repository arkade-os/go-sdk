package types

import (
	"context"
	"time"

	"github.com/arkade-os/go-sdk/swap/boltz"
)

type SwapStore interface {
	Add(ctx context.Context, swap Swap) error
	Get(ctx context.Context, id string) (*Swap, error)
	Update(ctx context.Context, swap Swap) error
}

type Store interface {
	Swaps() SwapStore
	Close() error
}

type Swap struct {
	Id          string
	From        boltz.Currency
	To          boltz.Currency
	CreatedAt   time.Time
	UpdatedAt   time.Time
	Status      int
	VHTLCScript string
	Amount      uint64
	FundingTxid string
	RedeemTxid  string
	Preimage    []byte
	LNSwap      *LNSwapInfo
	ChainSwap   *ChainSwapInfo
}

type LNSwapInfo struct {
	PreimageHash []byte
	Invoice      string
}

type ChainSwapInfo struct {
	FundingTxid string
	RedeemTxid  string
	Address     string
	PrivateKey  string
	SwapTree    boltz.SwapTree
}
