package arksdk

import (
	"fmt"
	"testing"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

func TestSettlementBatches(t *testing.T) {
	t.Parallel()

	t.Run("below limit keeps one batch", func(t *testing.T) {
		t.Parallel()

		utxos := testSettlementUtxos(1)
		vtxos := testSettlementVtxos(3)

		batches := settlementBatches(utxos, vtxos)

		require.Len(t, batches, 1)
		require.Equal(t, utxos, batches[0].utxos)
		require.Equal(t, vtxos, batches[0].vtxos)
	})

	t.Run("limit equal to total input count keeps one batch", func(t *testing.T) {
		t.Parallel()

		utxos := testSettlementUtxos(10)
		vtxos := testSettlementVtxos(40)

		batches := settlementBatches(utxos, vtxos)

		require.Len(t, batches, 1)
		requireBatchesWithinLimit(t, batches)
		require.Equal(t, utxos, batches[0].utxos)
		require.Equal(t, vtxos, batches[0].vtxos)
	})

	t.Run("limit splits by total inputs", func(t *testing.T) {
		t.Parallel()

		utxos := testSettlementUtxos(40)
		vtxos := testSettlementVtxos(65)

		batches := settlementBatches(utxos, vtxos)

		require.Len(t, batches, 3)
		requireBatchesWithinLimit(t, batches)
		require.Equal(t, utxos, batches[0].utxos)
		require.Empty(t, batches[1].utxos)
		require.Empty(t, batches[2].utxos)
		require.Equal(t, vtxos[:10], batches[0].vtxos)
		require.Equal(t, vtxos[10:60], batches[1].vtxos)
		require.Equal(t, vtxos[60:], batches[2].vtxos)
	})

	t.Run("mixed batch fills remaining limit with vtxos", func(t *testing.T) {
		t.Parallel()

		utxos := testSettlementUtxos(45)
		vtxos := testSettlementVtxos(10)

		batches := settlementBatches(utxos, vtxos)

		require.Len(t, batches, 2)
		requireBatchesWithinLimit(t, batches)
		require.Equal(t, utxos, batches[0].utxos)
		require.Equal(t, vtxos[:5], batches[0].vtxos)
		require.Empty(t, batches[1].utxos)
		require.Equal(t, vtxos[5:], batches[1].vtxos)
	})

	t.Run("utxo only settlement obeys limit", func(t *testing.T) {
		t.Parallel()

		utxos := testSettlementUtxos(105)

		batches := settlementBatches(utxos, nil)

		require.Len(t, batches, 3)
		requireBatchesWithinLimit(t, batches)
		require.Equal(t, utxos[:50], batches[0].utxos)
		require.Equal(t, utxos[50:100], batches[1].utxos)
		require.Equal(t, utxos[100:], batches[2].utxos)
		require.Empty(t, batches[0].vtxos)
		require.Empty(t, batches[1].vtxos)
		require.Empty(t, batches[2].vtxos)
	})
}

func requireBatchesWithinLimit(t *testing.T, batches []settlementBatch) {
	t.Helper()

	for _, batch := range batches {
		require.LessOrEqual(t, len(batch.utxos)+len(batch.vtxos), maxCoinsPerBatch)
	}
}

func testSettlementVtxos(count int) []clientTypes.VtxoWithTapTree {
	vtxos := make([]clientTypes.VtxoWithTapTree, count)
	for i := range vtxos {
		vtxos[i] = clientTypes.VtxoWithTapTree{
			Vtxo: clientTypes.Vtxo{
				Outpoint: clientTypes.Outpoint{
					Txid: fmt.Sprintf("vtxo-%d", i),
					VOut: uint32(i),
				},
			},
		}
	}
	return vtxos
}

func testSettlementUtxos(count int) []clientTypes.Utxo {
	utxos := make([]clientTypes.Utxo, count)
	for i := range utxos {
		utxos[i] = clientTypes.Utxo{
			Outpoint: clientTypes.Outpoint{
				Txid: fmt.Sprintf("utxo-%d", i),
				VOut: uint32(i),
			},
		}
	}
	return utxos
}
