package arksdk

import (
	"context"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
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

	signingKeys, err := a.signingKeysByScript(ctx)
	if err != nil {
		return "", err
	}

	// ensure asset-carrying receivers have at least dust sats as a carrier
	clone := make([]clientTypes.Receiver, len(receivers))
	copy(clone, receivers)
	dust := cfg.Dust
	for i, receiver := range clone {
		if len(receiver.Assets) > 0 && receiver.Amount < dust {
			clone[i].Amount = dust
		}
	}

	res, err := a.ArkClient.SendOffChain(
		ctx,
		clone,
		client.WithVtxos(vtxos),
		client.WithKeys(signingKeys),
	)
	if err != nil {
		return "", err
	}

	// mark vtxos as spent and add transaction to DB before unlocking the mutex
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

	contracts, err := a.contractManager.GetContractsForVtxos(ctx, scripts)
	if err != nil {
		return nil, err
	}

	contractsByScript := make(map[string]contract.Contract, len(contracts))
	for _, c := range contracts {
		contractsByScript[c.Script] = c
	}

	vtxos := make([]clientTypes.VtxoWithTapTree, 0, len(eligible))
	for _, v := range eligible {
		c, ok := contractsByScript[v.Script]
		if !ok {
			log.Debugf("skipping vtxo %s:%d: no contract for script %s", v.Txid, v.VOut, v.Script)
			continue
		}
		vtxos = append(vtxos, clientTypes.VtxoWithTapTree{
			Vtxo:       v,
			Tapscripts: c.GetTapscripts(),
		})
	}

	return vtxos, nil
}
