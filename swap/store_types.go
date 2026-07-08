package swap

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("not found")

type SwapRecordType int

const (
	SwapRecordRegular SwapRecordType = iota
	SwapRecordPayment
)

type SwapRecord struct {
	ID                  string
	Amount              uint64
	Timestamp           int64
	ToCurrency          string
	FromCurrency        string
	Status              SwapStatus
	Type                SwapRecordType
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
	Status                  ChainSwapStatus
	UserLockupTxID          string
	ServerLockupTxID        string
	ClaimTxID               string
	ClaimPreimage           string
	RefundTxID              string
	UserBTCLockupAddress    string
	ErrorMessage            string
	BoltzCreateResponseJSON string
	CreatedAt               int64
	UpdatedAt               int64
}

type HTLCKeyRecord struct {
	Address       string
	PrivateKeyHex string
	CreatedAt     int64
}

type Store interface {
	Swaps() SwapRepository
	ChainSwaps() ChainSwapRepository
	HTLCKeys() HTLCKeyRepository
	Close() error
}

type SwapRepository interface {
	Add(ctx context.Context, swaps []SwapRecord) (int, error)
	Update(ctx context.Context, swap SwapRecord) error
}

type ChainSwapRepository interface {
	Add(ctx context.Context, swap ChainSwapRecord) error
	Get(ctx context.Context, id string) (*ChainSwapRecord, error)
	Update(ctx context.Context, swap ChainSwapRecord) error
}

type HTLCKeyRepository interface {
	Add(ctx context.Context, key HTLCKeyRecord) error
	Get(ctx context.Context, address string) (*HTLCKeyRecord, error)
}

type HandlerOption func(*SwapHandler)

func WithStore(store Store) HandlerOption {
	return func(h *SwapHandler) {
		h.store = store
	}
}
