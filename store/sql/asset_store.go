package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/store/sql/sqlc/queries"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

type assetStore struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
}

func NewAssetStore(db *sql.DB) types.AssetStore {
	return &assetStore{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
	}
}

func (a *assetStore) GetAsset(ctx context.Context, assetId string) (*clientTypes.AssetInfo, error) {
	row, err := a.querier.SelectAsset(ctx, assetId)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("asset not found %s", assetId)
		}
		return nil, err
	}

	controlAssetId := ""
	if row.ControlAssetID.Valid {
		controlAssetId = row.ControlAssetID.String
	}

	metadata := make([]asset.Metadata, 0)
	if row.Metadata.Valid {
		//nolint:errcheck
		json.Unmarshal([]byte(row.Metadata.String), &metadata)
	}

	return &clientTypes.AssetInfo{
		AssetId:        row.AssetID,
		ControlAssetId: controlAssetId,
		Metadata:       metadata,
	}, nil
}

func (a *assetStore) UpsertAsset(ctx context.Context, asset clientTypes.AssetInfo) error {
	metadata := sql.NullString{Valid: false}
	if len(asset.Metadata) > 0 {
		metadataBytes, err := json.Marshal(asset.Metadata)
		if err != nil {
			return err
		}
		metadata = sql.NullString{String: string(metadataBytes), Valid: true}
	}

	controlAssetId := sql.NullString{Valid: false}
	if asset.ControlAssetId != "" {
		controlAssetId = sql.NullString{String: asset.ControlAssetId, Valid: true}
	}

	return a.querier.UpsertAsset(ctx, queries.UpsertAssetParams{
		AssetID:        asset.AssetId,
		ControlAssetID: controlAssetId,
		Metadata:       metadata,
	})
}

func (a *assetStore) Clean(ctx context.Context) error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if err := a.querier.CleanAssetVtxos(ctx); err != nil {
		return err
	}
	if err := a.querier.CleanAssets(ctx); err != nil {
		return err
	}
	// nolint:all
	a.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (a *assetStore) Close() {
	a.lock.Lock()
	defer a.lock.Unlock()

	if err := a.db.Close(); err != nil {
		log.Debugf("error on closing asset db: %s", err)
	}
}
