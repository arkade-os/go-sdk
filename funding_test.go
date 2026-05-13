package arksdk

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestGetOffchainBalanceClassifiesRecoverableVtxos(t *testing.T) {
	ctx := t.Context()

	w, err := NewWallet(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(w.(*wallet).store.Close)

	now := time.Now()
	defaultExpiry := now.Add(time.Hour)
	pastExpiry := now.Add(-(5 * time.Minute))
	vtxos := []clienttypes.Vtxo{
		// Unspent leaf
		balanceTestVtxo(t, 1_000, defaultExpiry, nil),
		//u Unspent precomfirmed
		balanceTestVtxo(t, 2_000, defaultExpiry, func(v *clienttypes.Vtxo) {
			v.Preconfirmed = true
		}),
		// Swept and not spent, recoverable
		balanceTestVtxo(t, 3_000, pastExpiry, func(v *clienttypes.Vtxo) {
			v.Swept = true
		}),
		// Expired but not swept, ie. server did not broadcasted the sweep tx yet
		balanceTestVtxo(t, 4_000, pastExpiry, nil),
		// Sub-dust, recoverable
		balanceTestVtxo(t, 200, defaultExpiry, func(v *clienttypes.Vtxo) {
			v.Swept = true
		}),
		// Swept and spent, ignore
		balanceTestVtxo(t, 5_000, pastExpiry, func(v *clienttypes.Vtxo) {
			v.Swept = true
			v.Spent = true
		}),
		// Unrolled, ignore
		balanceTestVtxo(t, 6_000, defaultExpiry, func(v *clienttypes.Vtxo) {
			v.Unrolled = true
		}),
		balanceTestVtxo(t, 7_000, defaultExpiry, func(v *clienttypes.Vtxo) {
			v.Preconfirmed = true
			v.Assets = []clienttypes.Asset{
				{
					AssetId: "test",
					Amount:  1_000,
				},
				{
					AssetId: "test-2",
					Amount:  2_000,
				},
			}
		}),
	}

	count, err := w.Store().VtxoStore().AddVtxos(ctx, vtxos)
	require.NoError(t, err)
	require.Equal(t, len(vtxos), count)

	balance, assetsBalance, err := w.(*wallet).getOffchainBalance(ctx)
	require.NoError(t, err)
	require.NotNil(t, balance)
	require.NotEmpty(t, assetsBalance)

	require.Equal(t, int(17_200), int(balance.Total))
	require.Equal(t, int(1_000), int(balance.Settled))
	require.Equal(t, int(9_000), int(balance.Preconfirmed))
	require.Equal(t, int(7_200), int(balance.Recoverable))
	require.Equal(t, int(1_000), int(assetsBalance["test"]))
	require.Equal(t, int(2_000), int(assetsBalance["test-2"]))
}

func balanceTestVtxo(
	t *testing.T, amount uint64, expiresAt time.Time, mutate func(*clienttypes.Vtxo),
) clienttypes.Vtxo {
	t.Helper()

	txid := make([]byte, 32)
	_, err := rand.Read(txid)
	require.NoError(t, err)

	commitmentTxid := make([]byte, 32)
	_, err = rand.Read(commitmentTxid)
	require.NoError(t, err)

	vtxo := clienttypes.Vtxo{
		Outpoint: clienttypes.Outpoint{
			Txid: hex.EncodeToString(txid),
			VOut: 0,
		},
		Amount:          amount,
		CommitmentTxids: []string{hex.EncodeToString(commitmentTxid)},
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
	}

	if mutate != nil {
		mutate(&vtxo)
	}

	return vtxo
}
