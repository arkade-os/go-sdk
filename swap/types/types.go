package types

import (
	"context"
	"time"

	"github.com/arkade-os/go-sdk/swap/boltz"
)

type SwapStore interface {
	Add(ctx context.Context, swap Swap) error
	Get(ctx context.Context, id string) (*Swap, error)
	// List returns all swaps sorted by creation time, optionally filtered by status.
	List(ctx context.Context, status ...int) ([]Swap, error)
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
	// PrivateKey is our ephemeral BTC HTLC claim key.
	PrivateKey string
	// DestinationAddress is the onchain address the claimed BTC is sent to. Only we know it
	// (Boltz doesn't), so it must be persisted to recover the claim of an Arkade -> BTC chain
	// swap.
	DestinationAddress string
	// ServerPublicKey and RefundLocktime are Boltz's key and the timeout of the BTC HTLC,
	// needed to rebuild it when recovering the claim. The full server key (with its Y parity)
	// must be persisted: the swap tree only carries the x-only key, which is not enough to
	// recompute the MuSig2 taproot output.
	ServerPublicKey string
	RefundLocktime  uint32
}
