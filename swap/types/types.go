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
	Id        string
	From      boltz.Currency
	To        boltz.Currency
	CreatedAt time.Time
	UpdatedAt time.Time
	// Status can be either pending, success or failure
	Status      int
	VHTLCScript string
	// Amount in sats
	Amount uint64
	// The txid of the funding transaction, if any.
	FundingTxid string
	// The txid of the claim or refund transaction, if any.
	RedeemTxid string
	// The preimage is stored only in case it can't be derived (no usage of hd identity)
	Preimage []byte
	// Info about the submarine or reverse swap, nil if this is a chainswap
	LNSwap *LNSwapInfo
	// Info about the chain swap, nil if this is a submarine/reverse swap
	ChainSwap *ChainSwapInfo
}

type LNSwapInfo struct {
	PreimageHash []byte
	Invoice      string
}

type ChainSwapInfo struct {
	// The txid of the funding transaction, if any.
	FundingTxid string
	// The txid of the claim or refund transaction, if any.
	RedeemTxid string
	// The HTLC address (onchain) to fund
	Address string
	// PrivateKey is our ephemeral key locking the HTLC: the claim key in an Arkade -> BTC
	// swap, the refund key in a BTC -> Arkade one.
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
	// The absolute locktime for refund
	RefundLocktime uint32
}
