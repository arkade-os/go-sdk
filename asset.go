package arksdk

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", nil, err
	}

	issueOpts := []client.SendOption{client.WithVtxos(vtxos), client.WithKeys(signingKeys)}
	res, err := a.ArkClient.IssueAsset(ctx, amount, controlAsset, metadata, issueOpts...)
	if err != nil {
		return "", nil, err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, res.OffchainTxRes); err != nil {
		return "", nil, err
	}

	return res.Txid, res.IssuedAssets, nil
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

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	reissueOpts := []client.SendOption{client.WithVtxos(vtxos), client.WithKeys(signingKeys)}
	res, err := a.ArkClient.ReissueAsset(ctx, assetId, amount, reissueOpts...)
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

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	burnOpts := []client.SendOption{client.WithVtxos(vtxos), client.WithKeys(signingKeys)}
	res, err := a.ArkClient.BurnAsset(ctx, assetId, amount, burnOpts...)
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := a.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}
