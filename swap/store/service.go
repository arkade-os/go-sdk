package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	sqlstore "github.com/arkade-os/go-sdk/swap/store/sql"
	"github.com/arkade-os/go-sdk/swap/types"
	"github.com/golang-migrate/migrate/v4"
	sqlitemigrate "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "modernc.org/sqlite"
)

//go:embed sql/migration/*
var migrations embed.FS

const (
	driverName   = "sqlite"
	sqliteDbFile = "swap.db"
)

type service struct {
	db    *sql.DB
	swaps types.SwapStore
}

func NewService(dir string) (types.Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("missing swap sqlite datadir")
	}

	dbPath := filepath.Join(dir, sqliteDbFile)
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
	if err := configureSQLite(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = db.Close()
		}
	}()

	if err := migrateDB(db); err != nil {
		return nil, err
	}

	swapRepo := sqlstore.NewSwapStore(db)

	succeeded = true
	return &service{
		db:    db,
		swaps: swapRepo,
	}, nil
}

func (s *service) Swaps() types.SwapStore { return s.swaps }

func (s *service) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func migrateDB(db *sql.DB) error {
	driver, err := sqlitemigrate.WithInstance(db, &sqlitemigrate.Config{})
	if err != nil {
		return fmt.Errorf("open swap sqlite migration driver: %w", err)
	}
	source, err := iofs.New(migrations, "sql/migration")
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

// configureSQLite reduces lock contention when the handler and tests open
// separate connections to the same swap database.
func configureSQLite(db *sql.DB) error {
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return fmt.Errorf("configure swap sqlite busy timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("configure swap sqlite journal mode: %w", err)
	}
	return nil
}
