package arksdk

import (
	"encoding/hex"
	"fmt"
	"math"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	hdidentity "github.com/arkade-os/go-sdk/identity"
	identitystore "github.com/arkade-os/go-sdk/identity/store"
	"github.com/arkade-os/go-sdk/identity/store/file"
	"github.com/arkade-os/go-sdk/identity/store/inmemory"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/wire"
)

func newDefaultHDIdentity(datadir string) (identity.Identity, error) {
	store, err := newHDIdentityStore(datadir)
	if err != nil {
		return nil, err
	}
	identity, err := hdidentity.NewIdentity(store)
	if err != nil {
		return nil, fmt.Errorf("failed to setup identity: %s", err)
	}
	return identity, nil
}

func newHDIdentityStore(datadir string) (identitystore.IdentityStore, error) {
	if len(datadir) > 0 {
		return identityfilestore.NewStore(datadir)
	}
	return identityinmemorystore.NewStore(), nil
}

func getOffchainBalanceDetails(
	amountByExpiration map[int64]uint64,
) (int64, []clientwallet.VtxoDetails) {
	nextExpiration := int64(0)
	details := make([]clientwallet.VtxoDetails, 0)
	for timestamp, amount := range amountByExpiration {
		if nextExpiration == 0 || timestamp < nextExpiration {
			nextExpiration = timestamp
		}

		fancyTime := time.Unix(timestamp, 0).Format(time.RFC3339)
		details = append(details, clientwallet.VtxoDetails{
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
	vtxos []clienttypes.Vtxo,
	vtxo clienttypes.Vtxo,
) []clienttypes.Vtxo {
	if vtxo.Preconfirmed {
		return nil
	}
	return findVtxosSettled(vtxos, vtxo.CommitmentTxids[0])
}

func findVtxosSettled(vtxos []clienttypes.Vtxo, id string) []clienttypes.Vtxo {
	var result []clienttypes.Vtxo
	leftVtxos := make([]clienttypes.Vtxo, 0)
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

func findVtxosSpent(vtxos []clienttypes.Vtxo, id string) []clienttypes.Vtxo {
	var result []clienttypes.Vtxo
	leftVtxos := make([]clienttypes.Vtxo, 0)
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

func reduceVtxosAmount(vtxos []clienttypes.Vtxo) uint64 {
	var total uint64
	for _, v := range vtxos {
		total += v.Amount
	}
	return total
}

func findVtxosSpentInPayment(vtxos []clienttypes.Vtxo, vtxo clienttypes.Vtxo) []clienttypes.Vtxo {
	return findVtxosSpent(vtxos, vtxo.Txid)
}

func findVtxosResultedFromSettledBy(
	vtxos []clienttypes.Vtxo,
	commitmentTxid string,
) []clienttypes.Vtxo {
	var result []clienttypes.Vtxo
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

func findVtxosResultedFromSpentBy(vtxos []clienttypes.Vtxo, spentByTxid string) []clienttypes.Vtxo {
	var result []clienttypes.Vtxo
	for _, v := range vtxos {
		if v.Txid == spentByTxid {
			result = append(result, v)
		}
	}
	return result
}

func getVtxo(usedVtxos []clienttypes.Vtxo, spentByVtxos []clienttypes.Vtxo) clienttypes.Vtxo {
	if len(usedVtxos) > 0 {
		return usedVtxos[0]
	} else if len(spentByVtxos) > 0 {
		return spentByVtxos[0]
	}
	return clienttypes.Vtxo{}
}

func groupSpentVtxosByTx(
	spentVtxos []clienttypes.Vtxo, oldSpendableVtxoMap map[clienttypes.Outpoint]clienttypes.Vtxo,
) (
	map[string]map[clienttypes.Outpoint]string,
	map[string]map[clienttypes.Outpoint]string,
) {
	// Spent vtxos include swept and redeemed, let's make sure to update only vtxos
	// that were previously spendable.
	vtxosToSpend := make(map[string]map[clienttypes.Outpoint]string)
	vtxosToSettle := make(map[string]map[clienttypes.Outpoint]string)

	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			continue
		}

		if vtxo.SettledBy != "" {
			if _, ok := vtxosToSettle[vtxo.SettledBy]; !ok {
				vtxosToSettle[vtxo.SettledBy] = make(map[clienttypes.Outpoint]string)
			}
			vtxosToSettle[vtxo.SettledBy][vtxo.Outpoint] = vtxo.SpentBy
			continue
		}

		if _, ok := vtxosToSpend[vtxo.ArkTxid]; !ok {
			vtxosToSpend[vtxo.ArkTxid] = make(map[clienttypes.Outpoint]string)
		}
		vtxosToSpend[vtxo.ArkTxid][vtxo.Outpoint] = vtxo.SpentBy
	}

	return vtxosToSpend, vtxosToSettle
}

func toOnchainAddress(arkAddress string, network arklib.Network) string {
	netParams := utils.ToBitcoinNetwork(network)

	// nolint
	decodedAddr, _ := arklib.DecodeAddressV0(arkAddress)
	witnessProgram := schnorr.SerializePubKey(decodedAddr.VtxoTapKey)
	// nolint
	addr, _ := btcutil.NewAddressTaproot(witnessProgram, &netParams)
	return addr.String()
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
	from clienttypes.Outpoint
	to   clienttypes.Outpoint
}

// matchReplacementOutputs maps stored UTXOs from a replaced transaction to the
// corresponding outputs in the replacement transaction by matching on script
// (pkScript). This correctly handles cases where Bitcoin Core's bumpfee
// reorders outputs, which would break a naive index-based mapping.
func matchReplacementOutputs(
	storedUtxos []clienttypes.Utxo,
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
					to: clienttypes.Outpoint{
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
