package arksdk

import (
	"context"
	"fmt"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

func (a *arkClient) Settle(ctx context.Context, opts ...BatchSessionOption) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, scriptToKeyID, err := a.getSpendableVtxos(ctx, true)
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

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	settleOpts := []client.BatchSessionOption{client.WithFunds(utxos, vtxos)}
	if len(scriptToKeyID) > 0 {
		settleOpts = append(settleOpts, client.WithKeys(scriptToKeyID))
	}
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

	vtxos, scriptToKeyID, err := a.getSpendableVtxos(ctx, true)
	if err != nil {
		return "", err
	}
	a.dbMu.Lock()
	utxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return "", err
	}

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	exitOpts := []client.BatchSessionOption{client.WithFunds(utxos, vtxos)}
	if len(scriptToKeyID) > 0 {
		exitOpts = append(exitOpts, client.WithKeys(scriptToKeyID))
	}
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

func (a *arkClient) RegisterIntent(
	ctx context.Context,
	vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo, notes []string,
	outputs []clientTypes.Receiver, cosignersPublicKeys []string,
) (string, error) {
	return a.ArkClient.RegisterIntent(
		ctx,
		vtxos,
		boardingUtxos,
		notes,
		outputs,
		cosignersPublicKeys,
	)
}

func (a *arkClient) DeleteIntent(
	ctx context.Context,
	vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo, notes []string,
) error {
	return a.ArkClient.DeleteIntent(ctx, vtxos, boardingUtxos, notes)
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
