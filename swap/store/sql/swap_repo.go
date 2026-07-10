package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	swapdomain "github.com/arkade-os/go-sdk/swap/store/domain"
	"github.com/arkade-os/go-sdk/swap/store/sql/sqlc/queries"
)

type swapRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewSwapRepository(db *sql.DB) swapdomain.SwapRepository {
	return &swapRepository{
		db:      db,
		querier: queries.New(db),
	}
}

func (r *swapRepository) Add(ctx context.Context, swaps []swapdomain.Swap) (int, error) {
	if len(swaps) == 0 {
		return 0, nil
	}

	count := int64(0)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	qtx := r.querier.WithTx(tx)
	for _, record := range swaps {
		if record.Amount > math.MaxInt64 {
			return 0, fmt.Errorf("swap %s amount overflows int64", record.ID)
		}
		n, err := qtx.InsertSwap(ctx, queries.InsertSwapParams{
			ID:                  record.ID,
			Amount:              int64(record.Amount),
			Timestamp:           record.Timestamp,
			ToCurrency:          record.ToCurrency,
			FromCurrency:        record.FromCurrency,
			Status:              int64(record.Status),
			Invoice:             record.Invoice,
			FundingTxID:         nullableString(record.FundingTxID),
			RedeemTxID:          nullableString(record.RedeemTxID),
			VhtlcContractScript: record.VHTLCContractScript,
		})
		if err != nil {
			return 0, err
		}
		count += n
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return int(count), nil
}

func (r *swapRepository) Get(ctx context.Context, id string) (*swapdomain.Swap, error) {
	row, err := r.querier.SelectSwap(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: swap %s", swapdomain.ErrNotFound, id)
		}
		return nil, err
	}
	record := toSwapRecord(row)
	return &record, nil
}

func (r *swapRepository) Update(ctx context.Context, record swapdomain.Swap) error {
	n, err := r.querier.UpdateSwap(ctx, queries.UpdateSwapParams{
		Status:      int64(record.Status),
		FundingTxID: nullableString(record.FundingTxID),
		RedeemTxID:  nullableString(record.RedeemTxID),
		ID:          record.ID,
	})
	if err != nil {
		return err
	}
	return requireAffected(n, "swap %s", record.ID)
}

func toSwapRecord(row queries.Swap) swapdomain.Swap {
	return swapdomain.Swap{
		ID:                  row.ID,
		Amount:              uint64(row.Amount),
		Timestamp:           row.Timestamp,
		ToCurrency:          row.ToCurrency,
		FromCurrency:        row.FromCurrency,
		Status:              int(row.Status),
		Invoice:             row.Invoice,
		FundingTxID:         stringValue(row.FundingTxID),
		RedeemTxID:          stringValue(row.RedeemTxID),
		VHTLCContractScript: row.VhtlcContractScript,
	}
}
