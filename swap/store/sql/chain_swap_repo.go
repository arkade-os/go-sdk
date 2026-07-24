package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	swapdomain "github.com/arkade-os/go-sdk/swap/store/domain"
	"github.com/arkade-os/go-sdk/swap/store/sql/sqlc/queries"
)

type chainSwapRepository struct {
	querier *queries.Queries
}

func NewChainSwapRepository(db *sql.DB) swapdomain.ChainSwapRepository {
	return &chainSwapRepository{
		querier: queries.New(db),
	}
}

func (r *chainSwapRepository) Add(ctx context.Context, record swapdomain.ChainSwap) error {
	if record.CreatedAt == 0 {
		record.CreatedAt = time.Now().Unix()
	}
	if record.UpdatedAt == 0 {
		record.UpdatedAt = record.CreatedAt
	}
	if record.Amount > math.MaxInt64 {
		return fmt.Errorf("chain swap %s amount overflows int64", record.ID)
	}

	return r.querier.InsertChainSwap(ctx, queries.InsertChainSwapParams{
		ID:                      record.ID,
		FromCurrency:            record.FromCurrency,
		ToCurrency:              record.ToCurrency,
		Amount:                  int64(record.Amount),
		Status:                  int64(record.Status),
		UserLockupTxID:          nullableString(record.UserLockupTxID),
		ServerLockupTxID:        nullableString(record.ServerLockupTxID),
		ClaimTxID:               nullableString(record.ClaimTxID),
		RefundTxID:              nullableString(record.RefundTxID),
		UserBtcLockupAddress:    nullableString(record.UserBTCLockupAddress),
		BtcHtlcPrivateKey:       nullableString(record.BTCHTLCPrivateKey),
		ErrorMessage:            nullableString(record.ErrorMessage),
		BoltzCreateResponseJson: nullableString(record.BoltzCreateResponseJSON),
		CreatedAt:               nullableInt64(record.CreatedAt),
		UpdatedAt:               nullableInt64(record.UpdatedAt),
	})
}

func (r *chainSwapRepository) Get(
	ctx context.Context, id string,
) (*swapdomain.ChainSwap, error) {
	row, err := r.querier.SelectChainSwap(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: chain swap %s", swapdomain.ErrNotFound, id)
		}
		return nil, err
	}
	record := toChainSwapRecord(row)
	return &record, nil
}

func (r *chainSwapRepository) Update(ctx context.Context, record swapdomain.ChainSwap) error {
	if record.UpdatedAt == 0 {
		record.UpdatedAt = time.Now().Unix()
	}

	n, err := r.querier.UpdateChainSwap(ctx, queries.UpdateChainSwapParams{
		Status:                  int64(record.Status),
		UserLockupTxID:          nullableString(record.UserLockupTxID),
		ServerLockupTxID:        nullableString(record.ServerLockupTxID),
		ClaimTxID:               nullableString(record.ClaimTxID),
		RefundTxID:              nullableString(record.RefundTxID),
		BtcHtlcPrivateKey:       nullableString(record.BTCHTLCPrivateKey),
		ErrorMessage:            nullableString(record.ErrorMessage),
		BoltzCreateResponseJson: nullableString(record.BoltzCreateResponseJSON),
		UpdatedAt:               nullableInt64(record.UpdatedAt),
		ID:                      record.ID,
	})
	if err != nil {
		return err
	}
	return requireAffected(n, "chain swap %s", record.ID)
}

func toChainSwapRecord(row queries.ChainSwap) swapdomain.ChainSwap {
	return swapdomain.ChainSwap{
		ID:                      row.ID,
		FromCurrency:            row.FromCurrency,
		ToCurrency:              row.ToCurrency,
		Amount:                  uint64(row.Amount),
		Status:                  int(row.Status),
		UserLockupTxID:          stringValue(row.UserLockupTxID),
		ServerLockupTxID:        stringValue(row.ServerLockupTxID),
		ClaimTxID:               stringValue(row.ClaimTxID),
		RefundTxID:              stringValue(row.RefundTxID),
		UserBTCLockupAddress:    stringValue(row.UserBtcLockupAddress),
		BTCHTLCPrivateKey:       stringValue(row.BtcHtlcPrivateKey),
		ErrorMessage:            stringValue(row.ErrorMessage),
		BoltzCreateResponseJSON: stringValue(row.BoltzCreateResponseJson),
		CreatedAt:               int64Value(row.CreatedAt),
		UpdatedAt:               int64Value(row.UpdatedAt),
	}
}
