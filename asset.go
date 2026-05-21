package arksdk

import (
	"context"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

func (w *wallet) IssueAsset(
	ctx context.Context,
	amount uint64, controlAsset clientTypes.ControlAsset, metadata []asset.Metadata,
) (string, []asset.AssetId, error) {
	if err := w.safeCheck(); err != nil {
		return "", nil, err
	}

	// Synchronize with other spend operations to avoid double-spending VTXOs.
	var h *spendOpHandle
	for {
		var acquired bool
		h, acquired = w.tryStartSpendOp(spendTypeAsset)
		if acquired {
			break
		}
		if err := waitForSpendOp(ctx, h.done); err != nil {
			return "", nil, err
		}
	}

	txid, issued, err := w.issueAsset(ctx, amount, controlAsset, metadata)
	w.finishSpendOp(h, txid, err)
	return txid, issued, err
}

func (w *wallet) issueAsset(
	ctx context.Context,
	amount uint64, controlAsset clientTypes.ControlAsset, metadata []asset.Metadata,
) (string, []asset.AssetId, error) {
	vtxos, err := w.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", nil, err
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", nil, err
	}

	offchainAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", nil, err
	}

	opts := []client.SendOption{
		client.WithVtxos(vtxos),
		client.WithReceiver(offchainAddr),
		client.WithKeys(signingKeyRefs),
	}
	res, err := w.client.IssueAsset(ctx, amount, controlAsset, metadata, opts...)
	if err != nil {
		return "", nil, err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := w.saveSendTransaction(ctx, res.OffchainTxRes); err != nil {
		return "", nil, err
	}

	return res.Txid, res.IssuedAssets, nil
}

func (w *wallet) ReissueAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	// Synchronize with other spend operations to avoid double-spending VTXOs.
	var h *spendOpHandle
	for {
		var acquired bool
		h, acquired = w.tryStartSpendOp(spendTypeAsset)
		if acquired {
			break
		}
		if err := waitForSpendOp(ctx, h.done); err != nil {
			return "", err
		}
	}

	txid, err := w.reissueAsset(ctx, assetId, amount)
	w.finishSpendOp(h, txid, err)
	return txid, err
}

func (w *wallet) reissueAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	vtxos, err := w.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	offchainAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	opts := []client.SendOption{
		client.WithVtxos(vtxos),
		client.WithReceiver(offchainAddr),
		client.WithKeys(signingKeyRefs),
	}

	res, err := w.client.ReissueAsset(ctx, assetId, amount, opts...)
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := w.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}

func (w *wallet) BurnAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	// Synchronize with other spend operations to avoid double-spending VTXOs.
	var h *spendOpHandle
	for {
		var acquired bool
		h, acquired = w.tryStartSpendOp(spendTypeAsset)
		if acquired {
			break
		}
		if err := waitForSpendOp(ctx, h.done); err != nil {
			return "", err
		}
	}

	txid, err := w.burnAsset(ctx, assetId, amount)
	w.finishSpendOp(h, txid, err)
	return txid, err
}

func (w *wallet) burnAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	vtxos, err := w.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	offchainAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	opts := []client.SendOption{
		client.WithVtxos(vtxos),
		client.WithReceiver(offchainAddr),
		client.WithKeys(signingKeyRefs),
	}

	res, err := w.client.BurnAsset(ctx, assetId, amount, opts...)
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
	if err := w.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}
