package store

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("not found")

type SwapRecord struct {
	ID                  string
	Amount              uint64
	Timestamp           int64
	ToCurrency          string
	FromCurrency        string
	Status              int
	Invoice             string
	FundingTxID         string
	RedeemTxID          string
	VHTLCContractScript string
}

type ChainSwapRecord struct {
	ID                      string
	FromCurrency            string
	ToCurrency              string
	Amount                  uint64
	Status                  int
	UserLockupTxID          string
	ServerLockupTxID        string
	ClaimTxID               string
	ClaimPreimage           string
	RefundTxID              string
	UserBTCLockupAddress    string
	BTCHTLCPrivateKey       string
	ErrorMessage            string
	BoltzCreateResponseJSON string
	CreatedAt               int64
	UpdatedAt               int64
}

type Store interface {
	Swaps() SwapRepository
	ChainSwaps() ChainSwapRepository
	Close() error
}

type SwapRepository interface {
	Add(ctx context.Context, swaps []SwapRecord) (int, error)
	Get(ctx context.Context, id string) (*SwapRecord, error)
	Update(ctx context.Context, swap SwapRecord) error
}

type ChainSwapRepository interface {
	Add(ctx context.Context, swap ChainSwapRecord) error
	Get(ctx context.Context, id string) (*ChainSwapRecord, error)
	Update(ctx context.Context, swap ChainSwapRecord) error
}
