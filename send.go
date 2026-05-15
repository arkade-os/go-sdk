package arksdk

import (
	"context"

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

	vtxos, err := w.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	signingKeyRefs, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
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
	if inAmount > outAmount {
		addr, err := w.newOffchainAddress(ctx)
		if err != nil {
			return "", err
		}
		opts = append(opts, clientwallet.WithReceiver(addr))
	}

	res, err := w.client.SendOffChain(ctx, clone, opts...)
	if err != nil {
		return "", err
	}

	if err := w.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
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
