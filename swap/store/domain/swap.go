package swapdomain

import (
	"context"
)

type Swap struct {
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

type SwapRepository interface {
	Add(ctx context.Context, swaps []Swap) (int, error)
	Get(ctx context.Context, id string) (*Swap, error)
	Update(ctx context.Context, swap Swap) error
}
