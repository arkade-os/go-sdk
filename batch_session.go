package arksdk

import (
	"context"
	"fmt"

	client "github.com/arkade-os/arkd/pkg/client-lib"
)

func (a *arkClient) Settle(ctx context.Context, opts ...BatchSessionOption) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, true)
	if err != nil {
		return "", err
	}
	a.dbMu.Lock()
	utxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return "", err
	}
	if len(vtxos)+len(utxos) == 0 {
		return "", fmt.Errorf("no funds to settle")
	}

	batchSessionOpts := newDefaultBatchSessionOptions()
	for _, opt := range opts {
		if err := opt(batchSessionOpts); err != nil {
			return "", err
		}
	}

	settleOpts := []client.BatchSessionOption{client.WithFunds(utxos, vtxos)}
	if batchSessionOpts.retryNum > 0 {
		settleOpts = append(settleOpts, client.WithRetries(batchSessionOpts.retryNum))
	}

	res, err := a.ArkClient.Settle(ctx, settleOpts...)
	if err != nil {
		return "", err
	}

	if err := a.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}

func (a *arkClient) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, true)
	if err != nil {
		return "", err
	}
	a.dbMu.Lock()
	utxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return "", err
	}

	batchSessionOpts := newDefaultBatchSessionOptions()
	for _, opt := range opts {
		if err := opt(batchSessionOpts); err != nil {
			return "", err
		}
	}

	exitOpts := []client.BatchSessionOption{client.WithFunds(utxos, vtxos)}
	if batchSessionOpts.retryNum > 0 {
		exitOpts = append(exitOpts, client.WithRetries(batchSessionOpts.retryNum))
	}

	res, err := a.ArkClient.CollaborativeExit(ctx, addr, amount, exitOpts...)
	if err != nil {
		return "", err
	}

	if err := a.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}

func (a *arkClient) RedeemNotes(
	ctx context.Context, notes []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	res, err := a.ArkClient.RedeemNotes(ctx, notes)
	if err != nil {
		return "", err
	}

	if err := a.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}
