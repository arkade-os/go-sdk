package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) Unroll(ctx context.Context) error {
	if err := a.safeCheck(); err != nil {
		return err
	}

	allVtxos, err := a.getSpendableVtxos(ctx, true)
	if err != nil {
		return err
	}

	if len(allVtxos) == 0 {
		return fmt.Errorf("no vtxos to unroll")
	}

	vtxos := make([]clientTypes.Vtxo, 0, len(allVtxos))
	for _, vtxo := range allVtxos {
		vtxos = append(vtxos, vtxo.Vtxo)
	}

	res, err := a.ArkClient.Unroll(ctx, client.WithVtxos(allVtxos))
	if err != nil {
		return err
	}

	for _, rr := range res {
		var parentTx wire.MsgTx
		dec := hex.NewDecoder(strings.NewReader(rr.ParentTx))
		if err := parentTx.Deserialize(dec); err != nil {
			return err
		}

		parentTxid := parentTx.TxID()
		vtxosToUpdate := make([]clientTypes.Vtxo, 0, len(allVtxos))
		for _, vtxo := range allVtxos {
			if vtxo.Txid == parentTxid {
				v := vtxo.Vtxo
				v.Unrolled = true
				vtxosToUpdate = append(vtxosToUpdate, v)
			}
		}
		count, err := a.store.VtxoStore().UnrollVtxos(ctx, vtxosToUpdate)
		if err != nil {
			return fmt.Errorf("failed to update vtxos: %w", err)
		}
		if count > 0 {
			log.Debugf("unrolled %d vtxos", count)
		}
	}
	return nil
}

func (a *arkClient) CompleteUnroll(ctx context.Context, to string) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	utxos, err := a.getMatureUtxos(ctx)
	if err != nil {
		return "", err
	}

	unrolledVtxos := make([]clientTypes.VtxoWithTapTree, 0, len(utxos))
	for _, utxo := range utxos {
		unrolledVtxos = append(unrolledVtxos, clientTypes.VtxoWithTapTree{
			Vtxo: clientTypes.Vtxo{
				Outpoint: clientTypes.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.VOut,
				},
				Script: utxo.Script,
				Amount: utxo.Amount,
			},
		})
	}

	signingKeys, err := a.getSigningKeyRefs(ctx, unrolledVtxos, nil)
	if err != nil {
		return "", err
	}

	opts := []client.UnrollOption{client.WithUtxosToClaim(utxos), client.WithKeys(signingKeys)}
	return a.ArkClient.CompleteUnroll(ctx, to, opts...)
}

func (a *arkClient) WithdrawFromAllExpiredBoardings(
	ctx context.Context, to string,
) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	contracts, err := a.contractManager.GetContracts(ctx, contract.WithIsOnchain())
	if err != nil {
		return "", err
	}
	// Nothing to do
	if len(contracts) <= 0 {
		return "", nil
	}

	scripts := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		scripts = append(scripts, contract.Script)
	}
	signingKeys, err := a.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}

	return a.ArkClient.WithdrawFromAllExpiredBoardings(ctx, to, client.WithKeys(signingKeys))
}

func (a *arkClient) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {
	if err := a.safeCheck(); err != nil {
		return "", err
	}

	contracts, err := a.contractManager.GetContracts(ctx, contract.WithIsOnchain())
	if err != nil {
		return "", err
	}
	// Nothing to do
	if len(contracts) <= 0 {
		return "", nil
	}

	scripts := make([]string, 0, len(contracts))
	for _, contract := range contracts {
		scripts = append(scripts, contract.Script)
	}
	signingKeys, err := a.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}

	return a.ArkClient.OnboardAgainAllExpiredBoardings(ctx, client.WithKeys(signingKeys))
}

func (a *arkClient) getMatureUtxos(ctx context.Context) ([]clientTypes.Utxo, error) {
	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	contracts, err := a.contractManager.GetContracts(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	explorer := a.Explorer()

	addresses := make([]string, 0, len(contracts))
	type params struct {
		exitDelay  arklib.RelativeLocktime
		tapscripts []string
	}
	addrParams := make(map[string]params)
	for _, contract := range contracts {
		addr := toOnchainAddress(contract.Address, cfg.Network)

		exitDelay, err := a.contractManager.GetExitDelay(ctx, contract)
		if err != nil {
			return nil, err
		}
		tapscripts, err := a.contractManager.GetTapscripts(ctx, contract)
		if err != nil {
			return nil, err
		}

		addresses = append(addresses, addr)
		addrParams[contract.Script] = params{*exitDelay, tapscripts}
	}

	fetchedUtxos, err := explorer.GetUtxos(addresses)
	if err != nil {
		return nil, err
	}

	utxos := make([]clientTypes.Utxo, 0, len(fetchedUtxos))
	for _, utxo := range fetchedUtxos {
		params := addrParams[utxo.Script]
		u := utxo.ToUtxo(params.exitDelay, params.tapscripts)
		if u.SpendableAt.Before(now) {
			utxos = append(utxos, u)
		}
	}
	return utxos, nil
}
