package arksdk

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
)

type assetFeeTotals struct {
	Fees       uint64
	InputSats  uint64
	OutputSats uint64
	TotalDelta int64
}

func deriveAssetFeeTotals(
	inputs []client.TapscriptsVtxo,
	feeReceivers []types.Receiver,
	feeEstimator *arkfee.Estimator,
) (assetFeeTotals, error) {
	var totals assetFeeTotals

	fees, err := utils.CalculateFees(inputs, feeReceivers, feeEstimator)
	totals.Fees = fees

	if err != nil {
		return totals, err
	}

	for _, input := range inputs {
		totals.InputSats += input.Amount
	}

	for _, output := range feeReceivers {
		totals.OutputSats += output.Amount
	}

	totals.TotalDelta = int64(totals.OutputSats) + int64(totals.Fees) - int64(totals.InputSats)
	return totals, nil
}

func (a *arkClient) selectAssetFunds(
	ctx context.Context,
) ([]client.TapscriptsVtxo, map[string]types.Receiver, error) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	spendableVtxos, err := a.getVtxos(ctx, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, offchainAddr := range offchainAddrs {
		for _, v := range spendableVtxos {
			vtxoAddr, err := v.Address(a.SignerPubKey, a.Network)
			if err != nil {
				return nil, nil, err
			}

			if vtxoAddr == offchainAddr.Address {
				vtxos = append(vtxos, client.TapscriptsVtxo{
					Vtxo:       v,
					Tapscripts: offchainAddr.Tapscripts,
				})
			}
		}
	}

	filteredVtxos := make([]client.TapscriptsVtxo, 0)
	for _, v := range vtxos {
		if len(v.Assets) > 0 {
			filteredVtxos = append(filteredVtxos, v)
		}
	}

	outputs := make(map[string]types.Receiver)

	uniqueVtxos := make(map[types.Outpoint]client.TapscriptsVtxo)

	for _, vtxo := range filteredVtxos {
		for _, asst := range vtxo.Assets {
			assetID := asst.AssetId
			assetAmount := asst.Amount
			if _, ok := outputs[assetID]; ok {
				outputs[assetID].Assets[0].Amount += assetAmount
			} else {
				outputs[assetID] = types.Receiver{
					To: offchainAddrs[0].Address,
					Assets: []types.Asset{
						{
							AssetId: assetID,
							Amount:  assetAmount,
						},
					},
				}
			}

			if _, ok := uniqueVtxos[vtxo.Outpoint]; !ok {
				uniqueVtxos[vtxo.Outpoint] = vtxo
				r := outputs[assetID]
				r.Amount += vtxo.Amount
				outputs[assetID] = r
			}
		}

	}

	return filteredVtxos, outputs, nil

}
