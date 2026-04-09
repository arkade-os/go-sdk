package arksdk

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) IssueAsset(
	ctx context.Context,
	amount uint64, controlAsset clientTypes.ControlAsset, metadata []asset.Metadata,
) (string, []asset.AssetId, error) {
	if err := a.safeCheck(); err != nil {
		return "", nil, err
	}

	vtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", nil, err
	}

	res, err := a.ArkClient.IssueAsset(
		ctx, amount, controlAsset, metadata, client.WithVtxos(vtxos),
	)
	if err != nil {
		return "", nil, err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, res.OffchainTxRes); err != nil {
		return "", nil, err
	}

	// Persist the issued AssetInfo(s) into the local AssetStore so that
	// GetAssetDetails can serve lookups without an indexer round-trip.
	a.persistIssuedAssets(ctx, res.IssuedAssets, controlAsset, metadata)

	return res.Txid, res.IssuedAssets, nil
}

// persistIssuedAssets writes one AssetInfo entry per freshly issued asset
// id into the local AssetStore. When the caller requested a new control
// asset, the first issued id is the control asset itself — all siblings
// carry its ControlAssetId back-reference. Failures are logged and
// swallowed so they cannot mask a successful on-chain issuance.
func (a *arkClient) persistIssuedAssets(
	ctx context.Context, assetIds []asset.AssetId,
	controlAsset clientTypes.ControlAsset, metadata []asset.Metadata,
) {
	if a.store == nil || len(assetIds) == 0 {
		return
	}

	// Determine the control asset id to link all issued assets to.
	var controlAssetId string
	switch ca := controlAsset.(type) {
	case clientTypes.ExistingControlAsset:
		controlAssetId = ca.ID
	case clientTypes.NewControlAsset:
		// The service returns the control asset first when NewControlAsset
		// is requested (see client-lib/asset.go IssueAsset).
		if len(assetIds) > 0 {
			controlAssetId = assetIds[0].String()
		}
	}

	for i, id := range assetIds {
		info := clientTypes.AssetInfo{
			AssetId:        id.String(),
			ControlAssetId: controlAssetId,
			Metadata:       metadata,
		}
		// For NewControlAsset, the first id is the control asset itself:
		// do not set ControlAssetId on its own row to avoid a self-loop.
		if _, isNew := controlAsset.(clientTypes.NewControlAsset); isNew && i == 0 {
			info.ControlAssetId = ""
		}
		if storeErr := a.store.AssetStore().UpsertAsset(ctx, info); storeErr != nil {
			log.Warnf(
				"failed to persist issued asset info for %s: %v",
				id.String(), storeErr,
			)
		}
	}
}

// GetAssetDetails returns the AssetInfo for the given asset id from the
// local AssetStore
// The AssetInfo is populated at issuance time by IssueAsset (see
// persistIssuedAssets above). Callers that need data about assets issued
// by other wallets should query the indexer via Indexer().GetAsset.
func (a *arkClient) GetAssetDetails(
	ctx context.Context, assetId string,
) (*clientTypes.AssetInfo, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}
	if a.store == nil {
		return nil, fmt.Errorf("asset store not initialized")
	}
	info, err := a.store.AssetStore().GetAsset(ctx, assetId)
	if err != nil {
		return nil, fmt.Errorf("getting asset details for %s: %w", assetId, err)
	}
	return info, nil
}

func (a *arkClient) ReissueAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	res, err := a.ArkClient.ReissueAsset(ctx, assetId, amount, client.WithVtxos(vtxos))
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}

func (a *arkClient) BurnAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	res, err := a.ArkClient.BurnAsset(ctx, assetId, amount, client.WithVtxos(vtxos))
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}
