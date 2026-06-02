package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

func (w *wallet) Unroll(ctx context.Context) error {
	if err := w.safeCheck(); err != nil {
		return err
	}

	vtxos, err := w.getSpendableVtxos(ctx, true)
	if err != nil {
		return err
	}

	if len(vtxos) == 0 {
		return fmt.Errorf("no vtxos to unroll")
	}

	res, err := w.client.Unroll(ctx, clientwallet.WithVtxos(vtxos))
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
		vtxosToUpdate := make([]clienttypes.Vtxo, 0, len(vtxos))
		for _, vtxo := range vtxos {
			if vtxo.Txid == parentTxid {
				v := vtxo.Vtxo
				v.Unrolled = true
				vtxosToUpdate = append(vtxosToUpdate, v)
			}
		}
		count, err := w.store.VtxoStore().UnrollVtxos(ctx, vtxosToUpdate)
		if err != nil {
			return fmt.Errorf("failed to update vtxos: %w", err)
		}
		if count > 0 {
			log.Debugf("unrolled %d vtxos", count)
		}
	}
	return nil
}

func (w *wallet) CompleteUnroll(ctx context.Context, to string) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	utxos, err := w.getMatureUtxos(ctx)
	if err != nil {
		return "", err
	}

	if len(utxos) <= 0 {
		return "", fmt.Errorf("no mature utxos to claim")
	}

	unrolledVtxos := make([]clienttypes.VtxoWithTapTree, 0, len(utxos))
	for _, utxo := range utxos {
		unrolledVtxos = append(unrolledVtxos, clienttypes.VtxoWithTapTree{
			Vtxo: clienttypes.Vtxo{
				Outpoint: clienttypes.Outpoint{
					Txid: utxo.Txid,
					VOut: utxo.VOut,
				},
				Script: utxo.Script,
				Amount: utxo.Amount,
			},
		})
	}

	signingKeys, err := w.getSigningKeyRefs(ctx, unrolledVtxos, nil)
	if err != nil {
		return "", err
	}

	opts := []clientwallet.UnrollOption{
		clientwallet.WithUtxosToClaim(utxos), clientwallet.WithKeys(signingKeys),
	}
	return w.client.CompleteUnroll(ctx, to, opts...)
}

func (w *wallet) WithdrawFromAllExpiredBoardings(
	ctx context.Context, to string,
) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	contracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeBoarding),
	)
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
	signingKeys, err := w.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}

	return w.client.WithdrawFromAllExpiredBoardings(ctx, to, clientwallet.WithKeys(signingKeys))
}

func (w *wallet) OnboardAgainAllExpiredBoardings(ctx context.Context) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	contracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeBoarding),
	)
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
	signingKeys, err := w.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}

	return w.client.OnboardAgainAllExpiredBoardings(ctx, clientwallet.WithKeys(signingKeys))
}

func (w *wallet) getMatureUtxos(ctx context.Context) ([]clienttypes.Utxo, error) {
	contracts, err := w.contractManager.GetContracts(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	explorer := w.Explorer()

	addresses := make([]string, 0, len(contracts))
	type params struct {
		exitDelay  arklib.RelativeLocktime
		tapscripts []string
	}
	addrParams := make(map[string]params)
	for _, contract := range contracts {
		if contract.Type == types.ContractTypeBoarding {
			continue
		}

		addr := toOnchainAddress(contract.Address, w.network)

		handler, err := w.contractManager.GetHandler(ctx, contract)
		if err != nil {
			return nil, err
		}
		exitDelay, err := handler.GetExitDelay(contract)
		if err != nil {
			return nil, err
		}
		tapscripts, err := handler.GetTapscripts(contract)
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

	utxos := make([]clienttypes.Utxo, 0, len(fetchedUtxos))
	for _, utxo := range fetchedUtxos {
		params := addrParams[utxo.Script]
		u := utxo.ToUtxo(params.exitDelay, params.tapscripts)
		if u.SpendableAt.Before(now) {
			utxos = append(utxos, u)
		}
	}
	return utxos, nil
}
