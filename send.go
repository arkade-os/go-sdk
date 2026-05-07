package arksdk

import (
	"context"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) SendOffChain(
	ctx context.Context, receivers []clientTypes.Receiver,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	vtxos, err := a.getSpendableVtxos(ctx, false)
	if err != nil {
		return "", err
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return "", err
	}

	signingKeyRefs, err := a.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return "", err
	}

	// Ensure asset-carrying receivers have at least dust sats as a carrier
	clone := make([]clientTypes.Receiver, len(receivers))
	copy(clone, receivers)
	dust := cfg.Dust
	for i, receiver := range clone {
		if len(receiver.Assets) > 0 && receiver.Amount < dust {
			clone[i].Amount = dust
		}
	}

	opts := []client.SendOption{
		client.WithVtxos(vtxos),
		client.WithKeys(signingKeyRefs),
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
		addr, err := a.newOffchainAddress(ctx)
		if err != nil {
			return "", err
		}
		opts = append(opts, client.WithReceiver(addr))
	}

	res, err := a.ArkClient.SendOffChain(ctx, clone, opts...)
	if err != nil {
		return "", err
	}

	if err := a.saveSendTransaction(ctx, *res); err != nil {
		return "", err
	}

	return res.Txid, nil
}

func (a *arkClient) getSpendableVtxos(
	ctx context.Context, withRecoverable bool,
) ([]clientTypes.VtxoWithTapTree, error) {
	a.dbMu.Lock()
	spendableVtxos, err := a.store.VtxoStore().GetSpendableVtxos(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return nil, err
	}

	eligible := make([]clientTypes.Vtxo, 0, len(spendableVtxos))
	scripts := make([]string, 0, len(spendableVtxos))
	for _, v := range spendableVtxos {
		if v.Unrolled || (!withRecoverable && v.IsRecoverable()) {
			continue
		}
		eligible = append(eligible, v)
		scripts = append(scripts, v.Script)
	}

	contracts, err := a.contractManager.GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]types.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clientTypes.VtxoWithTapTree, 0, len(eligible))
	for _, v := range eligible {
		contract, ok := contractsByScript[v.Script]
		if !ok {
			log.Warnf("skipping vtxo %s: no matching contract", v.Script)
			continue
		}

		handler, err := a.contractManager.GetHandler(ctx, contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get handler for contract %s", contract.Script)
			continue
		}
		tapscripts, err := handler.GetTapscripts(contract)
		if err != nil {
			log.WithError(err).Warnf("failed to get tapscripts for contract %s", contract.Script)
			continue
		}

		vtxos = append(vtxos, clientTypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: tapscripts,
		})
	}

	return vtxos, nil
}
