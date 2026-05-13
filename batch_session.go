package arksdk

import (
	"context"
	"fmt"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
)

var (
	ErrNoFundsToSettle = fmt.Errorf("no funds to settle")
)

func (w *wallet) Settle(ctx context.Context, opts ...BatchSessionOption) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := w.getSpendableVtxos(ctx, true)
	if err != nil {
		return "", err
	}
	w.dbMu.Lock()
	utxos, _, err := w.store.UtxoStore().GetAllUtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return "", err
	}
	if len(vtxos)+len(utxos) == 0 {
		return "", ErrNoFundsToSettle
	}

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, utxos)
	if err != nil {
		return "", err
	}

	changeAddr, err := w.newOffchainAddress(ctx)
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

	res, err := w.client.Settle(ctx, clientOpts...)
	if err != nil {
		return "", err
	}

	if err := w.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}

func (w *wallet) CollaborativeExit(
	ctx context.Context, addr string, amount uint64, opts ...BatchSessionOption,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := w.getSpendableVtxos(ctx, true)
	if err != nil {
		return "", err
	}

	batchSessionOpts, err := applyBatchSessionOptions(opts...)
	if err != nil {
		return "", fmt.Errorf("invalid options: %v", (err))
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	changeAddr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	clientOpts := []client.BatchSessionOption{
		client.WithFunds(nil, vtxos),
		client.WithKeys(signingKeyRefs),
		client.WithReceiver(changeAddr),
	}
	if batchSessionOpts.retryNum > 0 {
		clientOpts = append(clientOpts, client.WithRetries(batchSessionOpts.retryNum))
	}

	res, err := w.client.CollaborativeExit(ctx, addr, amount, clientOpts...)
	if err != nil {
		return "", err
	}

	if err := w.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}

func (w *wallet) RegisterIntent(
	ctx context.Context,
	vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
	outputs []clienttypes.Receiver, cosignersPublicKeys []string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	vv := make([]clienttypes.VtxoWithTapTree, 0, len(vtxos))
	for _, vtxo := range vtxos {
		vv = append(vv, clienttypes.VtxoWithTapTree{Vtxo: vtxo})
	}
	keys, err := w.getSigningKeyRefs(ctx, vv, boardingUtxos)
	if err != nil {
		return "", err
	}

	return w.client.RegisterIntent(
		ctx, vtxos, boardingUtxos, notes, outputs, cosignersPublicKeys, client.WithKeys(keys),
	)
}

func (w *wallet) DeleteIntent(
	ctx context.Context,
	vtxos []clienttypes.Vtxo, boardingUtxos []clienttypes.Utxo, notes []string,
) error {
	if err := w.safeCheck(); err != nil {
		return err
	}
	return w.client.DeleteIntent(ctx, vtxos, boardingUtxos, notes)
}

func (w *wallet) RedeemNotes(
	ctx context.Context, notes []string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	addr, err := w.newOffchainAddress(ctx)
	if err != nil {
		return "", err
	}

	res, err := w.client.RedeemNotes(ctx, notes, client.WithReceiver(addr))
	if err != nil {
		return "", err
	}

	if err := w.saveBatchTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.CommitmentTxid, nil
}
