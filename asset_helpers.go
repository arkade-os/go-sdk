package arksdk

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/go-sdk/client"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/types"
)

func appendDustReceivers(dst []types.Receiver, src []types.Receiver, dust uint64) []types.Receiver {
	for _, r := range src {
		dst = append(dst, types.Receiver{
			To:     r.To,
			Amount: dust,
		})
	}
	return dst
}

func buildAssetDustOutputs(
	assetOutputMap map[string][]types.Receiver,
	dust uint64,
) []types.Receiver {
	outputs := make([]types.Receiver, 0)
	for _, outputList := range assetOutputMap {
		outputs = appendDustReceivers(outputs, outputList, dust)
	}
	return outputs
}

type assetFeeTotals struct {
	Fees       uint64
	InputSats  uint64
	OutputSats uint64
	TotalDelta int64
}

func deriveAssetFeeTotals(
	inputs []client.TapscriptsVtxo,
	feeReceivers []types.Receiver,
	dust uint64,
	feeEstimator *arkfee.Estimator,
) (assetFeeTotals, error) {
	var totals assetFeeTotals

	fees, err := utils.CalculateFees(inputs, feeReceivers, feeEstimator)
	if err != nil {
		return totals, err
	}

	for _, input := range inputs {
		totals.InputSats += input.Amount
	}

	totals.Fees = fees
	totals.OutputSats = uint64(len(feeReceivers)) * dust
	totals.TotalDelta = int64(totals.OutputSats) + int64(totals.Fees) - int64(totals.InputSats)
	return totals, nil
}

// func selectSatsForAssetDelta(
// 	vtxos []client.TapscriptsVtxo,
// 	totalDelta int64,
// 	dust uint64,
// 	opts CoinSelectOptions,
// 	changeAddr string,
// 	feeEstimator *arkfee.Estimator,
// ) ([]client.TapscriptsVtxo, uint64, error) {
// 	selectedSatsCoins := make([]client.TapscriptsVtxo, 0)
// 	satsChangeAmount := uint64(0)

// 	var err error

// 	if totalDelta > 0 {
// 		_, selectedSatsCoins, satsChangeAmount, err = utils.CoinSelectNormal(
// 			nil, vtxos, uint64(totalDelta), dust, opts.WithoutExpirySorting, feeEstimator,
// 		)
// 		if err != nil {
// 			return nil, 0, err
// 		}
// 	} else if totalDelta < 0 {
// 		delta := -totalDelta
// 		changeFee, err := utils.CalculateFees(
// 			nil,
// 			[]types.Receiver{{To: changeAddr, Amount: uint64(delta)}},
// 			feeEstimator,
// 		)
// 		if err != nil {
// 			return nil, 0, err
// 		}
// 		if delta-int64(changeFee) > 0 {
// 			satsChangeAmount = uint64(delta) - changeFee
// 		}
// 	}

// 	return selectedSatsCoins, satsChangeAmount, nil
// }

func (a *arkClient) selectAssetFunds(
	ctx context.Context,
	outputs map[string][]types.Receiver,
	opts CoinSelectOptions,
) ([]client.TapscriptsVtxo, map[string][]types.Receiver, error) {
	_, offchainAddrs, _, _, err := a.wallet.GetAddresses(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(offchainAddrs) <= 0 {
		return nil, nil, fmt.Errorf("no offchain addresses found")
	}

	vtxos := make([]client.TapscriptsVtxo, 0)
	spendableVtxos, err := a.getVtxos(ctx, &opts)
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
		if v.Assets != nil {
			filteredVtxos = append(filteredVtxos, v)
		}
	}

	if outputs == nil {
		outputs = make(map[string][]types.Receiver)

		for _, vtxo := range filteredVtxos {
			for _, asst := range vtxo.Assets {
				assetID := asst.AssetId
				assetAmount := asst.Amount
				if receivers, ok := outputs[assetID]; ok {
					receivers[0].Amount += assetAmount
					outputs[assetID] = receivers
				} else {
					outputs[assetID] = []types.Receiver{{
						To:     offchainAddrs[0].Address,
						Amount: assetAmount,
					}}
				}
			}
		}

		return filteredVtxos, outputs, nil
	}

	selectedCoins := make(map[types.Outpoint]client.TapscriptsVtxo, 0)

	for assetID, receivers := range outputs {
		assetVtxos := make(map[types.Outpoint]client.TapscriptsVtxo, 0)
		for _, v := range filteredVtxos {
			for _, asset := range v.Assets {
				if asset.AssetId == assetID {
					assetVtxos[v.Outpoint] = v
					break
				}
			}
		}

		assetAmount := uint64(0)
		for _, r := range receivers {
			assetAmount += r.Amount
		}

		assetVtxosList := make([]client.TapscriptsVtxo, 0, len(assetVtxos))
		for _, v := range assetVtxos {
			assetVtxosList = append(assetVtxosList, v)
		}

		selectedAssetVtxos, changeAmount, err := utils.CoinSelectAsset(
			assetVtxosList, assetAmount, assetID, a.Dust, opts.WithoutExpirySorting,
		)
		if err != nil {
			return nil, nil, err
		}

		for _, v := range selectedAssetVtxos {
			selectedCoins[v.Outpoint] = v
		}

		if changeAmount > 0 {
			changeReceiver := types.Receiver{
				To:     offchainAddrs[0].Address,
				Amount: changeAmount,
			}
			outputs[assetID] = append(outputs[assetID], changeReceiver)
		}
	}

	selectedCoinsList := make([]client.TapscriptsVtxo, 0, len(selectedCoins))
	for _, v := range selectedCoins {
		selectedCoinsList = append(selectedCoinsList, v)
	}

	return selectedCoinsList, outputs, nil
}
