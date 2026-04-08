package arksdk

import (
	"fmt"
	"math"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

func getOffchainBalanceDetails(amountByExpiration map[int64]uint64) (int64, []VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(details, VtxoDetails{
			ExpiryTime: fancyTime,
			Amount:     amount,
		})
	}
	return nextExpiration, details
}

func getFancyTimeExpiration(nextExpiration int64) string {
	if nextExpiration == 0 {
		return ""
	}

	fancyTimeExpiration := ""
	t := time.Unix(nextExpiration, 0)
	if t.Before(time.Now().Add(48 * time.Hour)) {
		// print the duration instead of the absolute time
		until := time.Until(t)
		seconds := math.Abs(until.Seconds())
		minutes := math.Abs(until.Minutes())
		hours := math.Abs(until.Hours())

		if hours < 1 {
			if minutes < 1 {
				fancyTimeExpiration = fmt.Sprintf("%d seconds", int(seconds))
			} else {
				fancyTimeExpiration = fmt.Sprintf("%d minutes", int(minutes))
			}
		} else {
			fancyTimeExpiration = fmt.Sprintf("%d hours", int(hours))
		}
	} else {
		fancyTimeExpiration = t.Format(time.RFC3339)
	}
	return fancyTimeExpiration
}

func findVtxosSpentInSettlement(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.SettledBy == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func findVtxosSpent(vtxos []types.Vtxo, id string) []types.Vtxo {
	var result []types.Vtxo
	leftVtxos := make([]types.Vtxo, 0)
	for _, v := range vtxos {
		if v.ArkTxid == id {
			result = append(result, v)
		} else {
			leftVtxos = append(leftVtxos, v)
		}
	}
	// Update the given list with only the left vtxos.
	copy(vtxos, leftVtxos)
	return result
}

func reduceVtxosAmount(vtxos []types.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []types.Vtxo, vtxo types.Vtxo) []types.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSettledBy(vtxos []types.Vtxo, commitmentTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Preconfirmed || len(v.CommitmentTxids) != 1 {
			continue
		}
		if v.CommitmentTxids[0] == commitmentTxid {
			result = append(result, v)
		}
	}
	return result
}

func findVtxosResultedFromSpentBy(vtxos []types.Vtxo, spentByTxid string) []types.Vtxo {
	var result []types.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []types.Vtxo, spentByVtxos []types.Vtxo) types.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return types.Vtxo{}
}

func toOutputScript(onchainAddress string, network arklib.Network) ([]byte, error) {
	netParams := toBitcoinNetwork(network)
	rcvAddr, err := btcutil.DecodeAddress(onchainAddress, &netParams)
	if err != nil {
		return nil, err
	}

	return txscript.PayToAddrScript(rcvAddr)
}

func toOnchainAddress(arkAddress string, network arklib.Network) (string, error) {
	netParams := toBitcoinNetwork(network)

	decodedAddr, err := arklib.DecodeAddressV0(arkAddress)
	if err != nil {
		return "", err
	}

	witnessProgram := schnorr.SerializePubKey(decodedAddr.VtxoTapKey)

	addr, err := btcutil.NewAddressTaproot(witnessProgram, &netParams)
	if err != nil {
		return "", err
	}

	return addr.String(), nil
}

func toBitcoinNetwork(net arklib.Network) chaincfg.Params {
	switch net.Name {
	case arklib.Bitcoin.Name:
		return chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		return chaincfg.TestNet3Params
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		return arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		return chaincfg.RegressionNetParams
	default:
		return chaincfg.MainNetParams
	}
}

func networkFromString(net string) arklib.Network {
	switch net {
	case arklib.Bitcoin.Name:
		return arklib.Bitcoin
	case arklib.BitcoinTestNet.Name:
		return arklib.BitcoinTestNet
	//case arklib.BitcoinTestNet4.Name: //TODO uncomment once supported
	//	return chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		return arklib.BitcoinSigNet
	case arklib.BitcoinMutinyNet.Name:
		return arklib.BitcoinMutinyNet
	case arklib.BitcoinRegTest.Name:
		return arklib.BitcoinRegTest
	default:
		return arklib.Bitcoin
	}
}
