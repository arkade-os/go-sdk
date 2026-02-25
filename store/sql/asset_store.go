package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/go-sdk/store/sql/sqlc/queries"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

type assetStore struct {
	db      *sql.DB
	querier *queries.Queries
}

func NewAssetStore(db *sql.DB) types.AssetStore {
	return &assetStore{
		db:      db,
		querier: queries.New(db),
	}
}

func (a *assetStore) GetAsset(ctx context.Context, assetId string) (*types.AssetInfo, error) {
	row, err := a.querier.SelectAsset(ctx, assetId)
	if err != nil {
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

	return &types.AssetInfo{
		AssetId:        row.AssetID,
		ControlAssetId: controlAssetId,
		Metadata:       metadata,
	}, nil
}

func (a *assetStore) UpsertAsset(ctx context.Context, asset types.AssetInfo) error {
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

func (a *assetStore) Close() {
	if err := a.db.Close(); err != nil {
		log.Debugf("error on closing asset db: %s", err)
	}
}
