package arksdk

import (
	"context"
	"fmt"
	"sort"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (w *wallet) SendOffChain(
	ctx context.Context, receivers []clienttypes.Receiver,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	send := func() (any, error) {
		vtxos, err := w.getSpendableVtxos(ctx, false)
		if err != nil {
			return nil, err
		}

		signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
		if err != nil {
			return nil, err
		}

		// Ensure asset-carrying receivers have at least dust sats as a carrier
		clone := make([]clienttypes.Receiver, len(receivers))
		copy(clone, receivers)
		for i, receiver := range clone {
			if len(receiver.Assets) > 0 && receiver.Amount < w.dustAmount {
				clone[i].Amount = w.dustAmount
			}
		}

		opts := []clientwallet.SendOption{
			clientwallet.WithVtxos(vtxos),
			clientwallet.WithKeys(signingKeyRefs),
		}

		outAmount := uint64(0)
		for _, r := range clone {
			outAmount += r.Amount
		}
		inAmount := uint64(0)
		for _, v := range vtxos {
			inAmount += v.Amount
		}
		var changeAddr string
		if inAmount > outAmount {
			changeAddr, err = w.newOffchainAddress(ctx)
			if err != nil {
				return nil, err
			}
			opts = append(opts, clientwallet.WithReceiver(changeAddr))
		}

		// Subscribe to the change address before submitting so we don't miss
		// the indexer notification once the server tracks the tx.
		var tracked <-chan error
		if changeAddr != "" {
			var cancel context.CancelFunc
			tracked, cancel = w.notifyTracked(ctx, changeAddr)
			defer cancel()
		}

		res, err := w.client.SendOffChain(ctx, clone, opts...)
		if err != nil {
			return nil, err
		}

		// Keep the queued operation view current before releasing txHandler.
		if err := w.saveSendTransaction(ctx, *res); err != nil {
			return nil, err
		}

		// Wait for tracked change so the next queued op can spend it.
		if err := waitTracked(ctx, tracked); err != nil {
			return nil, err
		}
		return res.Txid, nil
	}

	rr, err := w.txHandler.handleTx(send)
	if err != nil {
		return "", err
	}

	txid, ok := rr.(string)
	if !ok {
		return "", fmt.Errorf("unexpected send result type %T", rr)
	}
	return txid, nil
}

// buildConsolidatedReceiver collapses all migrated BTC and assets into one
// current-signer receiver. Sats are summed exactly, asset amounts are grouped by
// asset id, and dustAmount is enforced defensively.
func buildConsolidatedReceiver(
	vtxos []clienttypes.VtxoWithTapTree, destAddr string, dustAmount uint64,
) clienttypes.Receiver {
	var amount uint64
	totals := make(map[string]uint64)
	for _, v := range vtxos {
		amount += v.Amount
		for _, a := range v.Assets {
			totals[a.AssetId] += a.Amount
		}
	}

	if amount < dustAmount {
		amount = dustAmount
	}

	if len(totals) == 0 {
		return clienttypes.Receiver{To: destAddr, Amount: amount}
	}

	ids := make([]string, 0, len(totals))
	for id := range totals {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic asset ordering on the receiver
	assets := make([]clienttypes.Asset, 0, len(ids))
	for _, id := range ids {
		assets = append(assets, clienttypes.Asset{AssetId: id, Amount: totals[id]})
	}

	return clienttypes.Receiver{To: destAddr, Amount: amount, Assets: assets}
}

// sendOffchainConsolidated is the pinned-input, safeCheck-free migration send.
// Call through sendOffchain so txHandler still serializes it.
func (w *wallet) sendOffchainConsolidated(
	ctx context.Context,
	vtxos []clienttypes.VtxoWithTapTree,
	receiver clienttypes.Receiver,
) (string, error) {
	if len(vtxos) == 0 {
		return "", nil
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	// Subscribe before submitting so the destination notification is not missed.
	tracked, cancel := w.notifyTracked(ctx, receiver.To)
	defer cancel()

	res, err := w.client.SendOffChain(
		ctx,
		[]clienttypes.Receiver{receiver},
		clientwallet.WithVtxos(vtxos),
		clientwallet.WithKeys(signingKeyRefs),
	)
	if err != nil {
		return "", err
	}

	if err := w.saveSendTransaction(ctx, withMigrationOutput(*res, receiver)); err != nil {
		return "", err
	}

	if err := waitTracked(ctx, tracked); err != nil {
		return "", err
	}

	return res.Txid, nil
}

func withMigrationOutput(
	res clientwallet.OffchainTxRes, receiver clienttypes.Receiver,
) clientwallet.OffchainTxRes {
	for _, output := range res.Outputs {
		if sameReceiver(output, receiver) {
			return res
		}
	}

	res.Outputs = append(res.Outputs, receiver)
	return res
}

func sameReceiver(a, b clienttypes.Receiver) bool {
	if a.To != b.To || a.Amount != b.Amount || len(a.Assets) != len(b.Assets) {
		return false
	}

	for i := range a.Assets {
		if a.Assets[i] != b.Assets[i] {
			return false
		}
	}
	return true
}

// sendOffchain migrates deprecated-signer vtxos into one current-signer output.
// It bypasses safeCheck for unlock migration but still uses txHandler.
func (w *wallet) sendOffchain(
	ctx context.Context, toMigrate []clienttypes.VtxoWithTapTree,
) (string, error) {
	if len(toMigrate) == 0 {
		return "", nil
	}

	if w.txHandler == nil {
		return "", ErrNotInitialized
	}

	migrate := func() (any, error) {
		destAddr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return nil, err
		}

		receiver := buildConsolidatedReceiver(toMigrate, destAddr, w.dustAmount)
		return w.sendOffchainConsolidated(ctx, toMigrate, receiver)
	}

	rr, err := w.txHandler.handleTx(migrate)
	if err != nil {
		return "", err
	}

	txid, ok := rr.(string)
	if !ok {
		return "", fmt.Errorf("unexpected migration send result type %T", rr)
	}
	return txid, nil
}

func (w *wallet) getSpendableVtxos(
	ctx context.Context, withRecoverable bool,
) ([]clienttypes.VtxoWithTapTree, error) {
	w.dbMu.Lock()
	spendableVtxos, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return nil, err
	}

	eligible := make([]clienttypes.Vtxo, 0, len(spendableVtxos))
	scripts := make([]string, 0, len(spendableVtxos))
	for _, v := range spendableVtxos {
		if v.Unrolled || (!withRecoverable && v.IsRecoverable()) {
			continue
		}
		eligible = append(eligible, v)
		scripts = append(scripts, v.Script)
	}

	// No eligible vtxos → nothing to look up. Skip the manager call so we
	// don't hand contract.WithScripts an empty slice (which it rightly
	// rejects as a programmer error). Callers (Unroll, Settle, …) already
	// handle a (nil, nil) return as "no vtxos available".
	if len(scripts) == 0 {
		return nil, nil
	}

	contracts, err := w.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]types.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clienttypes.VtxoWithTapTree, 0, len(eligible))
	for _, v := range eligible {
		contract, ok := contractsByScript[v.Script]
		if !ok {
			log.Warnf("skipping vtxo %s: no matching contract", v.Script)
			continue
		}

		handler, err := w.contractManager.GetHandler(ctx, contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get handler for contract %s", contract.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get tapscripts for contract %s", contract.Script)
			continue
		}

		vtxos = append(vtxos, clienttypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: tapscripts,
		})
	}

	return vtxos, nil
}
