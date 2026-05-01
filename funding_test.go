package arksdk

import (
	"fmt"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestGetOffchainBalanceClassifiesRecoverableVtxos(t *testing.T) {
	ctx := t.Context()

	c, err := NewArkClient("")
	require.NoError(t, err)
	client := c.(*arkClient)
	t.Cleanup(client.store.Close)

	now := time.Now()
	vtxos := []clientTypes.Vtxo{
		//unspent
		balanceTestVtxo(0, 1_000, now.Add(time.Hour), nil),
		//precomfirmed
		balanceTestVtxo(1, 2_000, now.Add(time.Hour), func(v *clientTypes.Vtxo) {
			v.Preconfirmed = true
		}),
		// swept and not spent, recoverable
		balanceTestVtxo(2, 3_000, now.Add(-time.Hour), func(v *clientTypes.Vtxo) {
			v.Swept = true
		}),
		//expired but not swept for some reason eg. arkd bug, recoverable
		balanceTestVtxo(3, 4_000, now.Add(-time.Minute), nil),
		// dust, recoverable
		balanceTestVtxo(6, 200, now.Add(-time.Hour), func(v *clientTypes.Vtxo) {
			v.Swept = true
		}),
		//swept and spent, non-recoverable
		balanceTestVtxo(4, 5_000, now.Add(-time.Minute), func(v *clientTypes.Vtxo) {
			v.Swept = true
			v.Spent = true
		}),
		//unrolled/spent, non-recoverable
		balanceTestVtxo(5, 6_000, now.Add(time.Hour), func(v *clientTypes.Vtxo) {
			v.Unrolled = true
		}),
	}

	count, err := client.store.VtxoStore().AddVtxos(ctx, vtxos)
	require.NoError(t, err)
	require.Equal(t, len(vtxos), count)

	balance, err := client.getOffchainBalance(ctx)
	require.NoError(t, err)

	require.Equal(t, uint64(10_200), balance.total)
	require.Equal(t, uint64(1_000), balance.settled)
	require.Equal(t, uint64(2_000), balance.preconfirmed)
	require.Equal(t, uint64(7_200), balance.recoverable)
}

func balanceTestVtxo(
	index uint32, amount uint64, expiresAt time.Time, mutate func(*clientTypes.Vtxo),
) clientTypes.Vtxo {
	vtxo := clientTypes.Vtxo{
		Outpoint: clientTypes.Outpoint{
			Txid: fmt.Sprintf("%064x", index+1),
			VOut: index,
		},
		Amount:          amount,
		CommitmentTxids: []string{fmt.Sprintf("%064x", index+100)},
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
	}

	if mutate != nil {
		mutate(&vtxo)
	}

	return vtxo
}
