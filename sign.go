package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcutil/psbt"
)

func (a *arkClient) SignTransaction(ctx context.Context, tx string) (string, error) {
	if err := a.safeCheck(); err != nil {
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
	signingKeys, err := a.getKeys(ctx, scripts)
	if err != nil {
		return "", err
	}
	// Nothing to sign
	if len(signingKeys) == 0 {
		return tx, nil
	}

	return a.ArkClient.SignTransaction(ctx, tx, client.WithKeys(signingKeys))
}

func (a *arkClient) FinalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	return a.finalizePendingTxs(ctx, createdAfter)
}

func (a *arkClient) finalizePendingTxs(
	ctx context.Context, createdAfter *time.Time,
) ([]string, error) {
	contracts, err := a.contractManager.GetContracts(ctx)
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
		scripts = append(scripts, contract.Script)
		contractsByScript[contract.Script] = contract
	}

	resp, err := a.Indexer().GetVtxos(ctx, indexer.WithPendingOnly(), indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}
	// Nothing to do
	if len(resp.Vtxos) <= 0 {
		return nil, nil
	}

	vtxos := make([]clientTypes.VtxoWithTapTree, 0, len(resp.Vtxos))
	for _, vtxo := range resp.Vtxos {
		tapscripts, err := a.contractManager.GetTapscripts(ctx, contractsByScript[vtxo.Script])
		if err != nil {
			return nil, err
		}
		vtxos = append(vtxos, clientTypes.VtxoWithTapTree{
			Vtxo:       vtxo,
			Tapscripts: tapscripts,
		})
	}

	signingKeys, err := a.getSigningKeyRefs(ctx, vtxos, nil)
	if err != nil {
		return nil, err
	}

	opts := []client.SendOption{client.WithVtxos(vtxos), client.WithKeys(signingKeys)}
	return a.ArkClient.FinalizePendingTxs(ctx, createdAfter, opts...)
}
