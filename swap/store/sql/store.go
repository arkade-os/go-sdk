package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	swapstore "github.com/arkade-os/go-sdk/swap/store"
	"github.com/arkade-os/go-sdk/swap/store/sql/sqlc/queries"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

//go:embed migration/*
var migrations embed.FS

const (
	driverName   = "sqlite"
	sqliteDbFile = "swap.sqlite.db"
)

type Store struct {
	db         *sql.DB
	swaps      swapstore.SwapRepository
	chainSwaps swapstore.ChainSwapRepository
}

func NewStore(dir string) (swapstore.Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("missing swap sqlite datadir")
	}
	return Open(filepath.Join(dir, sqliteDbFile))
}

func Open(dbPath string) (swapstore.Store, error) {
	if dbPath == "" {
		return nil, fmt.Errorf("missing swap sqlite db path")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create swap sqlite datadir: %w", err)
	}

	db, err := sql.Open(driverName, dbPath)
	if err != nil {
		return nil, fmt.Errorf("open swap sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)

	succeeded := false
	defer func() {
		if !succeeded {
			_ = db.Close()
		}
	}()

	if err := migrateDB(db); err != nil {
		return nil, err
	}

	querier := queries.New(db)
	store := &Store{
		db:         db,
		swaps:      &swapRepository{db: db, querier: querier},
		chainSwaps: &chainSwapRepository{querier: querier},
	}
	succeeded = true
	return store, nil
}

func (s *Store) Swaps() swapstore.SwapRepository { return s.swaps }

func (s *Store) ChainSwaps() swapstore.ChainSwapRepository { return s.chainSwaps }

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

type swapRepository struct {
	db      *sql.DB
	querier *queries.Queries
}

func (r *swapRepository) Add(ctx context.Context, swaps []swapstore.SwapRecord) (int, error) {
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

func (r *swapRepository) Get(ctx context.Context, id string) (*swapstore.SwapRecord, error) {
	row, err := r.querier.SelectSwap(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: swap %s", swapstore.ErrNotFound, id)
		}
		return nil, err
	}
	record := toSwapRecord(row)
	return &record, nil
}

func (r *swapRepository) Update(ctx context.Context, record swapstore.SwapRecord) error {
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

type chainSwapRepository struct {
	querier *queries.Queries
}

func (r *chainSwapRepository) Add(ctx context.Context, record swapstore.ChainSwapRecord) error {
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
		ClaimPreimage:           record.ClaimPreimage,
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
) (*swapstore.ChainSwapRecord, error) {
	row, err := r.querier.SelectChainSwap(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: chain swap %s", swapstore.ErrNotFound, id)
		}
		return nil, err
	}
	record := toChainSwapRecord(row)
	return &record, nil
}

func (r *chainSwapRepository) Update(ctx context.Context, record swapstore.ChainSwapRecord) error {
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

func migrateDB(db *sql.DB) error {
	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	if err != nil {
		return fmt.Errorf("open swap sqlite migration driver: %w", err)
	}
	source, err := iofs.New(migrations, "migration")
	if err != nil {
		return fmt.Errorf("embed swap sqlite migrations: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "swaps", driver)
	if err != nil {
		return fmt.Errorf("create swap sqlite migration instance: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run swap sqlite migrations: %w", err)
	}
	return nil
}

func toChainSwapRecord(row queries.ChainSwap) swapstore.ChainSwapRecord {
	return swapstore.ChainSwapRecord{
		ID:                      row.ID,
		FromCurrency:            row.FromCurrency,
		ToCurrency:              row.ToCurrency,
		Amount:                  uint64(row.Amount),
		Status:                  int(row.Status),
		UserLockupTxID:          stringValue(row.UserLockupTxID),
		ServerLockupTxID:        stringValue(row.ServerLockupTxID),
		ClaimTxID:               stringValue(row.ClaimTxID),
		ClaimPreimage:           row.ClaimPreimage,
		RefundTxID:              stringValue(row.RefundTxID),
		UserBTCLockupAddress:    stringValue(row.UserBtcLockupAddress),
		BTCHTLCPrivateKey:       stringValue(row.BtcHtlcPrivateKey),
		ErrorMessage:            stringValue(row.ErrorMessage),
		BoltzCreateResponseJSON: stringValue(row.BoltzCreateResponseJson),
		CreatedAt:               int64Value(row.CreatedAt),
		UpdatedAt:               int64Value(row.UpdatedAt),
	}
}

func toSwapRecord(row queries.Swap) swapstore.SwapRecord {
	return swapstore.SwapRecord{
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

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func stringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: value != 0}
}

func int64Value(value sql.NullInt64) int64 {
	if !value.Valid {
		return 0
	}
	return value.Int64
}

func requireAffected(count int64, format, id string) error {
	if count == 0 {
		return fmt.Errorf("%w: "+format, swapstore.ErrNotFound, id)
	}
	return nil
}
