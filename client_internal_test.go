package arksdk

import (
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestGroupSpentVtxosByTx(t *testing.T) {
	t.Parallel()

	t.Run("groups offchain and settled vtxos and ignores unknown outpoints", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clientTypes.Outpoint{Txid: "tx1", VOut: 0}
		outpoint2 := clientTypes.Outpoint{Txid: "tx2", VOut: 1}
		outpoint3 := clientTypes.Outpoint{Txid: "tx3", VOut: 2}
		missingOutpoint := clientTypes.Outpoint{Txid: "missing", VOut: 3}

		oldSpendable := map[clientTypes.Outpoint]clientTypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
		}

		spentVtxos := []clientTypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-1",
				SpentBy:  "checkpoint-txid-2",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-txid-1",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx-ignored",
				SettledBy: "commitment-txid-ignored",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"arktx-checkpoint-1": {
				outpoint1: "checkpoint-txid-1",
				outpoint2: "checkpoint-txid-2",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"commitment-txid-1": {
				outpoint3: "forfeit",
			},
		}, vtxosToSettle)
	})

	t.Run("creates multiple groups and prioritizes settled entries", func(t *testing.T) {
		t.Parallel()

		outpoint1 := clientTypes.Outpoint{Txid: "tx10", VOut: 0}
		outpoint2 := clientTypes.Outpoint{Txid: "tx11", VOut: 1}
		outpoint3 := clientTypes.Outpoint{Txid: "tx12", VOut: 2}
		outpoint4 := clientTypes.Outpoint{Txid: "tx13", VOut: 3}
		missingOutpoint := clientTypes.Outpoint{Txid: "tx14", VOut: 1}

		oldSpendable := map[clientTypes.Outpoint]clientTypes.Vtxo{
			outpoint1: {Outpoint: outpoint1},
			outpoint2: {Outpoint: outpoint2},
			outpoint3: {Outpoint: outpoint3},
			outpoint4: {Outpoint: outpoint4},
		}

		spentVtxos := []clientTypes.Vtxo{
			{
				Outpoint: outpoint1,
				ArkTxid:  "arktx-checkpoint-a",
				SpentBy:  "checkpoint-a-1",
			},
			{
				Outpoint: outpoint2,
				ArkTxid:  "arktx-checkpoint-b",
				SpentBy:  "checkpoint-b-1",
			},
			{
				Outpoint:  outpoint3,
				SettledBy: "commitment-a",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  outpoint4,
				ArkTxid:   "arktx-should-be-ignored",
				SettledBy: "commitment-b",
				SpentBy:   "forfeit",
			},
			{
				Outpoint:  missingOutpoint,
				ArkTxid:   "arktx",
				SettledBy: "commitment",
				SpentBy:   "forfeit",
			},
		}

		vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendable)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"arktx-checkpoint-a": {
				outpoint1: "checkpoint-a-1",
			},
			"arktx-checkpoint-b": {
				outpoint2: "checkpoint-b-1",
			},
		}, vtxosToSpend)

		require.Equal(t, map[string]map[clientTypes.Outpoint]string{
			"commitment-a": {
				outpoint3: "forfeit",
			},
			"commitment-b": {
				outpoint4: "forfeit",
			},
		}, vtxosToSettle)
	})
}
