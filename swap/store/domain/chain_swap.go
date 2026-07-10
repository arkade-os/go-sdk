package swapdomain

import "context"

type ChainSwap struct {
	ID                      string
	FromCurrency            string
	ToCurrency              string
	Amount                  uint64
	Status                  int
	UserLockupTxID          string
	ServerLockupTxID        string
	ClaimTxID               string
	RefundTxID              string
	UserBTCLockupAddress    string
	BTCHTLCPrivateKey       string
	ErrorMessage            string
	BoltzCreateResponseJSON string
	CreatedAt               int64
	UpdatedAt               int64
}

type ChainSwapRepository interface {
	Add(ctx context.Context, swap ChainSwap) error
	Get(ctx context.Context, id string) (*ChainSwap, error)
	Update(ctx context.Context, swap ChainSwap) error
}
