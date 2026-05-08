package store_test

import (
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestRbfReplacementWithReorderedOutputs verifies that after an RBF
// replacement where output indices change, the UTXO store correctly
// tracks the new outpoint. This is the scenario that caused
// INVALID_PSBT_INPUT errors in production: bumpfee reorders outputs,
// so old_vout=1 may correspond to new_vout=0.
func TestRbfReplacementWithReorderedOutputs(t *testing.T) {
	tests := []struct {
		name   string
		config store.Config
	}{
		{
			name:   "kv",
			config: store.Config{AppDataStoreType: types.KVStore},
		},
		{
			name:   "sql",
			config: store.Config{AppDataStoreType: types.SQLStore, BaseDir: t.TempDir()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			svc, err := store.NewStore(tt.config)
			require.NoError(t, err)
			defer svc.Close()

			utxoStore := svc.UtxoStore()

			// Drain events to prevent blocking.
			go func() {
				for range utxoStore.GetEventChannel() {
				}
			}()

			boardingScript := "512057e233fb803c0db0fe3d3aa0d6ea9b53028fb34e245980991d0971d48c39da21"
			oldTxid := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			newTxid := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

			// Simulate: original tx has boarding output at vout=1.
			boardingUtxo := clientTypes.Utxo{
				Outpoint:   clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				Script:     boardingScript,
				Amount:     1_000_000,
				Tapscripts: []string{"tapscript_leaf_a", "tapscript_leaf_b"},
				Tx:         "020000000001...",
				Delay:      arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: 30},
			}

			count, err := utxoStore.AddUtxos(ctx, []clientTypes.Utxo{boardingUtxo})
			require.NoError(t, err)
			require.Equal(t, 1, count)

			// After RBF, boarding output moved to vout=0 in the replacement tx.
			// Use ReplaceUtxo with the CORRECT new outpoint (vout=0).
			err = utxoStore.ReplaceUtxo(
				ctx,
				clientTypes.Outpoint{Txid: oldTxid, VOut: 1},
				clientTypes.Outpoint{Txid: newTxid, VOut: 0},
			)
			require.NoError(t, err)

			// Old outpoint should no longer exist.
			oldUtxos, err := utxoStore.GetUtxos(ctx, []clientTypes.Outpoint{
				{Txid: oldTxid, VOut: 1},
			})
			require.NoError(t, err)
			require.Empty(t, oldUtxos, "old outpoint should be deleted after replacement")

			// New outpoint should exist with correct metadata.
			newUtxos, err := utxoStore.GetUtxos(ctx, []clientTypes.Outpoint{
				{Txid: newTxid, VOut: 0},
			})
			require.NoError(t, err)
			require.Len(t, newUtxos, 1)

			replaced := newUtxos[0]
			require.Equal(t, newTxid, replaced.Txid)
			require.Equal(t, uint32(0), replaced.VOut)
			require.Equal(t, boardingScript, replaced.Script)
			require.Equal(t, uint64(1_000_000), replaced.Amount)
			require.Equal(t, boardingUtxo.Tapscripts, replaced.Tapscripts)
			require.Equal(t, boardingUtxo.Delay, replaced.Delay)

			// The replaced UTXO should be spendable (not marked as spent).
			spendable, spent, err := utxoStore.GetAllUtxos(ctx)
			require.NoError(t, err)
			require.Len(t, spendable, 1)
			require.Empty(t, spent)
			require.Equal(t, newTxid, spendable[0].Txid)
			require.Equal(t, uint32(0), spendable[0].VOut)
		})
	}
}
