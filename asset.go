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

	// Synchronize with other operations to avoid overlapping.
	issuance := func() (any, error) {
		vtxos, err := w.getSpendableVtxos(ctx, false)
		if err != nil {
			return nil, err
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return nil, err
		}

		offchainAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return nil, err
		}

		opts := []client.SendOption{
			client.WithVtxos(vtxos),
			client.WithReceiver(offchainAddr),
			client.WithKeys(signingKeyRefs),
		}

		// Subscribe to the receiver address before submitting so we don't miss
		// the indexer notification once the server tracks the tx.
		tracked, cancel := w.notifyTracked(ctx, offchainAddr)
		defer cancel()

		res, err := w.client.IssueAsset(ctx, amount, controlAsset, metadata, opts...)
		if err != nil {
			return nil, err
		}

		// Persist within the critical section so the next queued operation
		// sees the spent VTXOs and freshly created change before it runs.
		if err := w.saveSendTransaction(ctx, res.OffchainTxRes); err != nil {
			return nil, err
		}

		// Wait until the indexer has tracked our new vtxo before releasing the
		// slot, so the next queued operation can spend it.
		if err := <-tracked; err != nil {
			return nil, err
		}
		return res, nil
	}

	rr, err := w.txHandler.handleTx(issuance)
	if err != nil {
		return "", nil, err
	}

	res := rr.(*client.IssueAssetRes)
	return res.Txid, res.IssuedAssets, nil
}

func (w *wallet) ReissueAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	// Synchronize with other operations to avoid overlapping.
	reissuance := func() (any, error) {
		vtxos, err := w.getSpendableVtxos(ctx, false)
		if err != nil {
			return nil, err
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return nil, err
		}

		offchainAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return nil, err
		}

		opts := []client.SendOption{
			client.WithVtxos(vtxos),
			client.WithReceiver(offchainAddr),
			client.WithKeys(signingKeyRefs),
		}

		// Subscribe to the receiver address before submitting so we don't miss
		// the indexer notification once the server tracks the tx.
		tracked, cancel := w.notifyTracked(ctx, offchainAddr)
		defer cancel()

		res, err := w.client.ReissueAsset(ctx, assetId, amount, opts...)
		if err != nil {
			return nil, err
		}

		// Persist within the critical section so the next queued operation
		// sees the spent VTXOs and freshly created change before it runs.
		if err := w.saveSendTransaction(ctx, *res); err != nil {
			return nil, err
		}

		// Wait until the indexer has tracked our new vtxo before releasing the
		// slot, so the next queued operation can spend it.
		if err := <-tracked; err != nil {
			return nil, err
		}
		return res, nil
	}

	rr, err := w.txHandler.handleTx(reissuance)
	if err != nil {
		return "", err
	}

	res := rr.(*client.ReissueAssetRes)
	return res.Txid, nil
}

func (w *wallet) BurnAsset(
	ctx context.Context, assetId string, amount uint64,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	// Synchronize with other operations to avoid overlapping.
	burn := func() (any, error) {
		vtxos, err := w.getSpendableVtxos(ctx, false)
		if err != nil {
			return nil, err
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return nil, err
		}

		offchainAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return nil, err
		}

		opts := []client.SendOption{
			client.WithVtxos(vtxos),
			client.WithReceiver(offchainAddr),
			client.WithKeys(signingKeyRefs),
		}

		// Subscribe to the receiver address before submitting so we don't miss
		// the indexer notification once the server tracks the tx.
		tracked, cancel := w.notifyTracked(ctx, offchainAddr)
		defer cancel()

		res, err := w.client.BurnAsset(ctx, assetId, amount, opts...)
		if err != nil {
			return nil, err
		}

		// Persist within the critical section so the next queued operation
		// sees the spent VTXOs and freshly created change before it runs.
		if err := w.saveSendTransaction(ctx, *res); err != nil {
			return nil, err
		}

		// Wait until the indexer has tracked our new vtxo before releasing the
		// slot, so the next queued operation can spend it.
		if err := <-tracked; err != nil {
			return nil, err
		}
		return res, nil
	}

	rr, err := w.txHandler.handleTx(burn)
	if err != nil {
		return "", err
	}

	res := rr.(*client.BurnAssetRes)
	return res.Txid, nil
}
