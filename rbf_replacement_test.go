package arksdk

import (
	"encoding/hex"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

func TestMatchReplacementOutputs(t *testing.T) {
	t.Parallel()

	boardingScript := "512057e233fb803c0db0fe3d3aa0d6ea9b53028fb34e245980991d0971d48c39da21"
	changeScript := "512010a0fefd8dd80db429bf780471f71fcb6959cfe27c60d724a40971aa50c71480"

	decodePkScript := func(t *testing.T, hexStr string) []byte {
		t.Helper()
		b, err := hex.DecodeString(hexStr)
		require.NoError(t, err)
		return b
	}

	t.Run("same output order preserves mapping", func(t *testing.T) {
		t.Parallel()

		oldTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newTxid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

		storedUtxos := []clientTypes.Utxo{
			{
				Outpoint: clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				Script:   boardingScript,
				Amount:   1_000_000,
			},
		}

		// Replacement tx with same output order: [change@0, boarding@1]
		replacementTx := &wire.MsgTx{
			TxOut: []*wire.TxOut{
				{Value: 98_000_000, PkScript: decodePkScript(t, changeScript)},
				{Value: 1_000_000, PkScript: decodePkScript(t, boardingScript)},
			},
		}

		replacements := matchReplacementOutputs(storedUtxos, newTxid, replacementTx)
		require.Len(t, replacements, 1)
		require.Equal(t, clientTypes.Outpoint{Txid: oldTxid, VOut: 1}, replacements[0].From)
		require.Equal(t, clientTypes.Outpoint{Txid: newTxid, VOut: 1}, replacements[0].To)
	})

	t.Run("reordered outputs maps to correct index", func(t *testing.T) {
		t.Parallel()

		oldTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newTxid := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

		// Original tx had: [change@0, boarding@1]
		// So the stored UTXO is at vout=1
		storedUtxos := []clientTypes.Utxo{
			{
				Outpoint: clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				Script:   boardingScript,
				Amount:   1_000_000,
			},
		}

		// Replacement tx reordered: [boarding@0, change@1]
		replacementTx := &wire.MsgTx{
			TxOut: []*wire.TxOut{
				{Value: 1_000_000, PkScript: decodePkScript(t, boardingScript)},
				{Value: 97_500_000, PkScript: decodePkScript(t, changeScript)},
			},
		}

		replacements := matchReplacementOutputs(storedUtxos, newTxid, replacementTx)
		require.Len(t, replacements, 1)

		// The boarding output moved from index 1 to index 0.
		// The replacement must map (oldTxid, 1) → (newTxid, 0), NOT (newTxid, 1).
		require.Equal(t, clientTypes.Outpoint{Txid: oldTxid, VOut: 1}, replacements[0].From)
		require.Equal(t, clientTypes.Outpoint{Txid: newTxid, VOut: 0}, replacements[0].To,
			"should match by script, not by output index")
	})

	t.Run("no match when boarding output removed from replacement tx", func(t *testing.T) {
		t.Parallel()

		oldTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newTxid := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

		storedUtxos := []clientTypes.Utxo{
			{
				Outpoint: clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				Script:   boardingScript,
				Amount:   1_000_000,
			},
		}

		// Replacement tx has only the change output (boarding was absorbed into fees)
		otherScript := "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		replacementTx := &wire.MsgTx{
			TxOut: []*wire.TxOut{
				{Value: 97_000_000, PkScript: decodePkScript(t, otherScript)},
			},
		}

		replacements := matchReplacementOutputs(storedUtxos, newTxid, replacementTx)
		require.Empty(t, replacements, "should not match if script is not found")
	})

	t.Run("multiple stored utxos matched correctly", func(t *testing.T) {
		t.Parallel()

		oldTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newTxid := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

		scriptA := "5120aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		scriptB := "5120bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

		storedUtxos := []clientTypes.Utxo{
			{
				Outpoint: clientTypes.Outpoint{Txid: oldTxid, VOut: 0},
				Script:   scriptA,
				Amount:   500_000,
			},
			{
				Outpoint: clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				Script:   scriptB,
				Amount:   500_000,
			},
		}

		// Replacement tx has outputs swapped
		replacementTx := &wire.MsgTx{
			TxOut: []*wire.TxOut{
				{Value: 500_000, PkScript: decodePkScript(t, scriptB)},
				{Value: 500_000, PkScript: decodePkScript(t, scriptA)},
			},
		}

		replacements := matchReplacementOutputs(storedUtxos, newTxid, replacementTx)
		require.Len(t, replacements, 2)

		fromTo := make(map[clientTypes.Outpoint]clientTypes.Outpoint)
		for _, r := range replacements {
			fromTo[r.From] = r.To
		}

		// scriptA: old vout=0 → new vout=1
		require.Equal(t,
			clientTypes.Outpoint{Txid: newTxid, VOut: 1},
			fromTo[clientTypes.Outpoint{Txid: oldTxid, VOut: 0}],
		)
		// scriptB: old vout=1 → new vout=0
		require.Equal(t,
			clientTypes.Outpoint{Txid: newTxid, VOut: 0},
			fromTo[clientTypes.Outpoint{Txid: oldTxid, VOut: 1}],
		)
	})
}
