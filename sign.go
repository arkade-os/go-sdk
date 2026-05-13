package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func (w *wallet) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := w.safeCheck(); err != nil {
		return "", err
	}

	ptx, err := psbt.NewFromRawBytes(strings.NewReader(tx), true)
	if err != nil {
		return "", fmt.Errorf("failed to parse tx: %w", err)
	}

	scripts := make([]string, 0, len(ptx.Inputs))
	for i, v := range ptx.Inputs {
		if v.WitnessUtxo == nil {
			return "", fmt.Errorf("missing prevout for input %d", i)
		}
		scripts = append(scripts, hex.EncodeToString(v.WitnessUtxo.PkScript))
	}
	signingKeys, err := w.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}
	// Nothing to sign
	if len(signingKeys) == 0 {
		return tx, nil
	}

	return w.client.SignTransaction(ctx, tx, clientwallet.WithKeys(signingKeys))
}

func (w *wallet) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	return w.finalizePendingTxs(ctx, createdAfter)
}

func (w *wallet) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	contracts, err := w.contractManager.GetContracts(ctx)
	if err != nil {
		return nil, err
	}
	// Nothing to do
	if len(contracts) <= 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(contracts))
	contractsByScript := make(map[string]types.Contract)
	for _, contract := range contracts {
		if contract.Type == types.ContractTypeBoarding {
			continue
		}
		scripts = append(scripts, contract.Script)
		contractsByScript[contract.Script] = contract
	}

	resp, err := w.Indexer().GetVtxos(ctx, indexer.WithPendingOnly(), indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}
	// Nothing to do
	if len(resp.Vtxos) <= 0 {
		return nil, nil
	}

	vtxos := make([]clienttypes.VtxoWithTapTree, 0, len(resp.Vtxos))
	for _, vtxo := range resp.Vtxos {
		c := contractsByScript[vtxo.Script]
		handler, err := w.contractManager.GetHandler(ctx, c)
		if err != nil {
			return nil, err
		}
		tapscripts, err := handler.GetTapscripts(c)
		if err != nil {
			return nil, err
		}
		vtxos = append(vtxos, clienttypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: tapscripts,
		})
	}

	signingKeys, err := w.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return nil, err
	}

	opts := []clientwallet.SendOption{
		clientwallet.WithVtxos(vtxos), clientwallet.WithKeys(signingKeys),
	}
	return w.client.FinalizePendingTxs(ctx, createdAfter, opts...)
}
