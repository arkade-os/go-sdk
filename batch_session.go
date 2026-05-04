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

	signingKeyRefs, err := a.getSigningKeyRefs(ctx, vtxos, utxos)
	if err != nil {
		return "", err
	}

	changeAddr, err := a.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	clientOpts := []client.BatchSessionOption{
		client.WithFunds(utxos, vtxos),
		client.WithKeys(signingKeyRefs),
		client.WithReceiver(changeAddr),
	}
	if batchSessionOpts.retryNum > 0 {
		clientOpts = append(clientOpts, client.WithRetries(batchSessionOpts.retryNum))
	}

	res, err := a.ArkClient.Settle(ctx, clientOpts...)
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

	signingKeyRefs, err := a.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	changeAddr, err := a.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	clientOpts := []client.BatchSessionOption{
		client.WithFunds(utxos, vtxos),
		client.WithKeys(signingKeyRefs),
		client.WithReceiver(changeAddr),
	}
	if batchSessionOpts.retryNum > 0 {
		clientOpts = append(clientOpts, client.WithRetries(batchSessionOpts.retryNum))
	}

	res, err := a.ArkClient.CollaborativeExit(ctx, addr, amount, clientOpts...)
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
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vv := make([]clientTypes.VtxoWithTapTree, 0, len(vtxos))
	for _, vtxo := range vtxos {
		vv = append(vv, clientTypes.VtxoWithTapTree{Vtxo: vtxo})
	}
	keys, err := a.getSigningKeyRefs(ctx, vv, boardingUtxos)
	if err != nil {
		return "", err
	}

	return a.ArkClient.RegisterIntent(
		ctx, vtxos, boardingUtxos, notes, outputs, cosignersPublicKeys, client.WithKeys(keys),
	)
}

func (a *arkClient) DeleteIntent(
	ctx context.Context,
	vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo, notes []string,
) error {
	if err := a.safeCheck(); err != nil {
		return err
	}
	return a.ArkClient.DeleteIntent(ctx, vtxos, boardingUtxos, notes)
}

func (a *arkClient) RedeemNotes(
	ctx context.Context, notes []string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	addr, err := a.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	res, err := a.ArkClient.RedeemNotes(ctx, notes, client.WithReceiver(addr))
	if err != nil {
		return "", err
	}

	if err := a.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}
