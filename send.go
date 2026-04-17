package arksdk

import (
	"context"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
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

	// ensure asset-carrying receivers have at least dust sats as a carrier
	clone := make([]clientTypes.Receiver, len(receivers))
	copy(clone, receivers)
	dust := cfg.Dust
	for i, receiver := range clone {
		if len(receiver.Assets) > 0 && receiver.Amount < dust {
			clone[i].Amount = dust
		}
	}

	res, err := a.ArkClient.SendOffChain(ctx, clone, client.WithVtxos(vtxos))
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
	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	contracts, err := a.contractManager.GetContracts(ctx, contract.Filter{})
	if err != nil {
		return nil, err
	}

	addrToTapscripts := make(map[string][]string, len(contracts))
	for _, c := range contracts {
		addrToTapscripts[c.Address] = c.Tapscripts
	}

	vtxos := make([]clientTypes.VtxoWithTapTree, 0, len(spendableVtxos))
	for _, v := range spendableVtxos {
		if v.Unrolled || (!withRecoverable && v.IsRecoverable()) {
			continue
		}

		vtxoAddr, err := v.Address(cfg.SignerPubKey, cfg.Network)
		if err != nil {
			return nil, err
		}

		if tapscripts, ok := addrToTapscripts[vtxoAddr]; ok {
			vtxos = append(vtxos, clientTypes.VtxoWithTapTree{
				Vtxo:       v,
				Tapscripts: tapscripts,
			})
		}
	}

	return vtxos, nil
}
