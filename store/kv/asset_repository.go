package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	sdktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	assetStoreDir = "assets"
)

type assetStore struct {
	db   *badgerhold.Store
	lock *sync.Mutex
}

func NewAssetStore(dir string, logger badger.Logger) (types.AssetStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, assetStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open asset store: %s", err)
	}
	return &assetStore{
		db:   badgerDb,
		lock: &sync.Mutex{},
	}, nil
}

func (a *assetStore) GetAsset(ctx context.Context, assetId string) (*sdktypes.AssetInfo, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	var assetInfo sdktypes.AssetInfo
	if err := a.db.Get(assetId, &assetInfo); err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return nil, fmt.Errorf("asset not found: %s", assetId)
		}
		return nil, err
	}
	return &assetInfo, nil
}

func (a *assetStore) UpsertAsset(ctx context.Context, asset sdktypes.AssetInfo) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	var existing sdktypes.AssetInfo
	err := a.db.Get(asset.AssetId, &existing)
	if err != nil && !errors.Is(err, badgerhold.ErrNotFound) {
		return err
	}

	if existing.AssetId != "" {
		// Asset exists, merge fields
		if asset.ControlAssetId != "" {
			existing.ControlAssetId = asset.ControlAssetId
		}
		if len(asset.Metadata) > 0 {
			existing.Metadata = asset.Metadata
		}
		return a.db.Upsert(asset.AssetId, &existing)
	}

	return a.db.Upsert(asset.AssetId, &asset)
}

func (a *assetStore) Clean(_ context.Context) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if err := a.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the asset db: %s", err)
	}
	return nil
}

func (a *assetStore) Close() {
	a.lock.Lock()
	defer a.lock.Unlock()

	if err := a.db.Close(); err != nil {
		log.Debugf("error on closing asset db: %s", err)
	}
}
