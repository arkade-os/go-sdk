package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path/filepath"

	sqlstore "github.com/arkade-os/go-sdk/store/sql"
	"github.com/arkade-os/go-sdk/types"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed sql/migration/*
var migrations embed.FS

const (
	sqliteDbFile = "sqlite.db"
)

type service struct {
	utxoStore     types.UtxoStore
	vtxoStore     types.VtxoStore
	txStore       types.TransactionStore
	assetStore    types.AssetStore
	contractStore types.ContractStore
}

type Config struct {
	AppDataStoreType string
	BaseDir          string
}

func NewStore(storeConfig Config) (types.Store, error) {
	if len(storeConfig.AppDataStoreType) > 0 && storeConfig.AppDataStoreType != types.SQLStore {
		return nil, fmt.Errorf("unknown appdata store type")
	}

	dbFile := filepath.Join(storeConfig.BaseDir, sqliteDbFile)
	db, err := sqlstore.OpenDb(dbFile)
	if err != nil {
		return nil, err
	}

	succeeded := false
	defer func() {
		if !succeeded {
			//nolint
			db.Close()
		}
	}()

	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open store: %s", err)
	}

	source, err := iofs.New(migrations, "sql/migration")
	if err != nil {
		return nil, fmt.Errorf("failed to embed migrations: %s", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "arkdb", driver)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration instance: %s", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("failed to run migrations: %s", err)
	}

	succeeded = true
	utxoStore := sqlstore.NewUtxoStore(db)
	vtxoStore := sqlstore.NewVtxoStore(db)
	txStore := sqlstore.NewTransactionStore(db)
	assetStore := sqlstore.NewAssetStore(db)
	contractStore := sqlstore.NewContractStore(db)

	return &service{
		utxoStore:     utxoStore,
		vtxoStore:     vtxoStore,
		txStore:       txStore,
		assetStore:    assetStore,
		contractStore: contractStore,
	}, nil
}

func (s *service) UtxoStore() types.UtxoStore {
	return s.utxoStore
}

func (s *service) VtxoStore() types.VtxoStore {
	return s.vtxoStore
}

func (s *service) TransactionStore() types.TransactionStore {
	return s.txStore
}

func (s *service) AssetStore() types.AssetStore {
	return s.assetStore
}

func (s *service) ContractStore() types.ContractStore {
	return s.contractStore
}

func (s *service) Clean(ctx context.Context) {
	if s.utxoStore != nil {
		//nolint
		s.utxoStore.Clean(ctx)
	}
	if s.txStore != nil {
		//nolint
		s.txStore.Clean(ctx)
	}
	if s.vtxoStore != nil {
		//nolint
		s.vtxoStore.Clean(ctx)
	}
	if s.assetStore != nil {
		//nolint
		s.assetStore.Clean(ctx)
	}
	if s.contractStore != nil {
		//nolint
		s.contractStore.Clean(ctx)
	}
}

func (s *service) Close() {
	if s.utxoStore != nil {
		s.utxoStore.Close()
	}
	if s.txStore != nil {
		s.txStore.Close()
	}
	if s.vtxoStore != nil {
		s.vtxoStore.Close()
	}
	if s.assetStore != nil {
		s.assetStore.Close()
	}
	if s.contractStore != nil {
		s.contractStore.Close()
	}
}
