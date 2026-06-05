package arksdk

import (
	"context"
	"fmt"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	log "github.com/sirupsen/logrus"
)

const maxCoinsPerBatch = 50

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

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	batches := settlementBatches(utxos, vtxos)
	if len(batches) > 1 {
		log.Infof(
			"settling %d coin(s) in %d batches (max %d coins per batch)",
			len(utxos)+len(vtxos), len(batches), maxCoinsPerBatch,
		)
	}
	commitmentTxid := ""
	for i, batch := range batches {
		commitmentTxid, err = a.settleBatch(
			ctx, batch.utxos, batch.vtxos, signingKeys, batchSessionOpts.retryNum,
		)
		if err != nil {
			if len(batches) > 1 {
				return "", fmt.Errorf("failed to settle batch %d/%d: %w", i+1, len(batches), err)
			}
			return "", err
		}
		if len(batches) > 1 && i < len(batches)-1 {
			log.Infof(
				"settled batch %d/%d with commitment txid %s",
				i+1, len(batches), commitmentTxid,
			)
		}
	}

	return commitmentTxid, nil
}

type settlementBatch struct {
	utxos []clientTypes.Utxo
	vtxos []clientTypes.VtxoWithTapTree
}

func settlementBatches(
	utxos []clientTypes.Utxo,
	vtxos []clientTypes.VtxoWithTapTree,
) []settlementBatch {
	totalInputs := len(utxos) + len(vtxos)
	if totalInputs <= maxCoinsPerBatch {
		return []settlementBatch{{utxos: utxos, vtxos: vtxos}}
	}

	batches := make([]settlementBatch, 0, (totalInputs+maxCoinsPerBatch-1)/maxCoinsPerBatch)
	for utxoStart, vtxoStart := 0, 0; utxoStart < len(utxos) || vtxoStart < len(vtxos); {
		remaining := maxCoinsPerBatch
		batch := settlementBatch{}

		if utxoStart < len(utxos) {
			utxoEnd := utxoStart + remaining
			if utxoEnd > len(utxos) {
				utxoEnd = len(utxos)
			}
			batch.utxos = utxos[utxoStart:utxoEnd]
			remaining -= utxoEnd - utxoStart
			utxoStart = utxoEnd
		}

		if remaining > 0 && vtxoStart < len(vtxos) {
			vtxoEnd := vtxoStart + remaining
			if vtxoEnd > len(vtxos) {
				vtxoEnd = len(vtxos)
			}
			batch.vtxos = vtxos[vtxoStart:vtxoEnd]
			vtxoStart = vtxoEnd
		}

		batches = append(batches, batch)
	}

	return batches
}

func (a *arkClient) settleBatch(
	ctx context.Context,
	utxos []clientTypes.Utxo,
	vtxos []clientTypes.VtxoWithTapTree,
	signingKeys map[string]string,
	retryNum int,
) (string, error) {
	settleOpts := []client.BatchSessionOption{
		client.WithFunds(utxos, vtxos),
		client.WithKeys(signingKeys),
	}
	if retryNum > 0 {
		settleOpts = append(settleOpts, client.WithRetries(retryNum))
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

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	exitOpts := []client.BatchSessionOption{
		client.WithFunds(utxos, vtxos),
		client.WithKeys(signingKeys),
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

func (a *arkClient) RedeemNotes(
	ctx context.Context, notes []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	res, err := a.ArkClient.RedeemNotes(ctx, notes, client.WithKeys(signingKeys))
	if err != nil {
		return "", err
	}

	if err := a.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}
