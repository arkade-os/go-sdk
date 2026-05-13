package arksdk

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/arkd/pkg/client-lib/wallet"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/wallet/hdwallet"
	filewalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/file"
	inmemorywalletstore "github.com/arkade-os/go-sdk/wallet/hdwallet/store/inmemory"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func newDefaultHDWallet(datadir string) (wallet.WalletService, error) {
	walletStore := inmemorywalletstore.NewStore()
	if len(datadir) > 0 {
		var err error
		walletStore, err = filewalletstore.NewStore(datadir)
		if err != nil {
			return nil, err
		}
	}
	hdWallet, err := hdwallet.NewService(walletStore)
	if err != nil {
		return nil, fmt.Errorf("failed to setup wallet: %s", err)
	}
	return hdWallet, nil
}

func getOffchainBalanceDetails(amountByExpiration map[int64]uint64) (int64, []types.VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]types.VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(details, types.VtxoDetails{
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

func findVtxosSpentInSettlement(
	vtxos []clientTypes.Vtxo,
	vtxo clientTypes.Vtxo,
) []clientTypes.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []clientTypes.Vtxo, id string) []clientTypes.Vtxo {
	var result []clientTypes.Vtxo
	leftVtxos := make([]clientTypes.Vtxo, 0)
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

func findVtxosSpent(vtxos []clientTypes.Vtxo, id string) []clientTypes.Vtxo {
	var result []clientTypes.Vtxo
	leftVtxos := make([]clientTypes.Vtxo, 0)
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

func reduceVtxosAmount(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []clientTypes.Vtxo, vtxo clientTypes.Vtxo) []clientTypes.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSettledBy(
	vtxos []clientTypes.Vtxo,
	commitmentTxid string,
) []clientTypes.Vtxo {
	var result []clientTypes.Vtxo
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

func findVtxosResultedFromSpentBy(vtxos []clientTypes.Vtxo, spentByTxid string) []clientTypes.Vtxo {
	var result []clientTypes.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []clientTypes.Vtxo, spentByVtxos []clientTypes.Vtxo) clientTypes.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return clientTypes.Vtxo{}
}

func toOnchainAddress(arkAddress string, network arklib.Network) string {
	netParams := toBitcoinNetwork(network)

	// nolint
	decodedAddr, _ := arklib.DecodeAddressV0(arkAddress)
	witnessProgram := schnorr.SerializePubKey(decodedAddr.VtxoTapKey)
	// nolint
	addr, _ := btcutil.NewAddressTaproot(witnessProgram, &netParams)
	return addr.String()
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

// utxoReplacement represents a mapping from an old UTXO outpoint to its
// replacement outpoint after an RBF (Replace-By-Fee) transaction.
type utxoReplacement struct {
	from clientTypes.Outpoint
	to   clientTypes.Outpoint
}

// matchReplacementOutputs maps stored UTXOs from a replaced transaction to the
// corresponding outputs in the replacement transaction by matching on script
// (pkScript). This correctly handles cases where Bitcoin Core's bumpfee
// reorders outputs, which would break a naive index-based mapping.
func matchReplacementOutputs(
	storedUtxos []clientTypes.Utxo,
	replacementTxid string,
	replacementTx *wire.MsgTx,
) []utxoReplacement {
	replacements := make([]utxoReplacement, 0, len(storedUtxos))
	// Track which new outputs have been matched to avoid double-mapping.
	matched := make(map[uint32]bool)

	for _, stored := range storedUtxos {
		for newIdx, txOut := range replacementTx.TxOut {
			if matched[uint32(newIdx)] {
				continue
			}
			if hex.EncodeToString(txOut.PkScript) == stored.Script {
				replacements = append(replacements, utxoReplacement{
					from: stored.Outpoint,
					to: clientTypes.Outpoint{
						Txid: replacementTxid,
						VOut: uint32(newIdx),
					},
				})
				matched[uint32(newIdx)] = true
				break
			}
		}
	}
	return replacements
}
