package arksdk

import (
	"fmt"
	"testing"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

// findAssetAmount returns the Amount declared for assetId in the receiver's
// Assets slice, or 0 if absent. Test helper for the asset-receiver assertions.
func findAssetAmount(assets []clienttypes.Asset, assetID string) uint64 {
	for _, a := range assets {
		if a.AssetId == assetID {
			return a.Amount
		}
	}
	return 0
}

func vtxoWith(amount uint64, assets ...clienttypes.Asset) clienttypes.VtxoWithTapTree {
	return clienttypes.VtxoWithTapTree{
		Vtxo: clienttypes.Vtxo{Amount: amount, Assets: assets},
	}
}

func vtxoWithScript(
	script string, amount uint64, assets ...clienttypes.Asset,
) clienttypes.VtxoWithTapTree {
	return clienttypes.VtxoWithTapTree{
		Vtxo: clienttypes.Vtxo{Script: script, Amount: amount, Assets: assets},
	}
}

// --- buildConsolidatedReceiver ---------------------------------------------

// TestConsolidatedReceiverShape verifies the SINGLE consolidated receiver: a
// migration batch always produces exactly one Receiver whose Amount is the sum
// of EVERY input's sats and whose Assets declare every distinct assetId summed
// across all inputs. Pure-sats batches declare no Assets; a sub-dust total is
// floored to dust.
func TestConsolidatedReceiverShape(t *testing.T) {
	const dust = uint64(330)

	t.Run("pure sats: exact sum, no assets", func(t *testing.T) {
		r := buildConsolidatedReceiver([]clienttypes.VtxoWithTapTree{
			vtxoWith(1000), vtxoWith(2000),
		}, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		require.Equal(t, uint64(3000), r.Amount)
		require.Nil(t, r.Assets, "a pure-sats batch declares no assets")
	})

	t.Run("nil/empty batch is dust-floored sats receiver", func(t *testing.T) {
		r := buildConsolidatedReceiver(nil, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		require.Equal(t, dust, r.Amount, "empty batch floors to dust")
		require.Nil(t, r.Assets)
	})

	t.Run("mixed pure-sats + multiple assets => one receiver, all summed", func(t *testing.T) {
		// A heterogeneous batch: a big pure-sats vtxo, two vtxos of asset aaa,
		// one of asset bbb, and one multi-asset vtxo carrying aaa AND ccc. The
		// consolidated receiver must declare ALL assetIds (aaa, bbb, ccc) summed
		// across every input, with Amount = the sum of EVERY carrier's sats.
		batch := []clienttypes.VtxoWithTapTree{
			vtxoWith(50000), // pure sats
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 500}),
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 300}),
			vtxoWith(330, clienttypes.Asset{AssetId: "bbb", Amount: 1000}),
			vtxoWith(330,
				clienttypes.Asset{AssetId: "aaa", Amount: 200},
				clienttypes.Asset{AssetId: "ccc", Amount: 7},
			),
		}

		r := buildConsolidatedReceiver(batch, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		// Amount = sum of ALL sats carriers (50000 + 330*4).
		require.Equal(t, uint64(50000+330*4), r.Amount,
			"consolidated Amount must be the sum of every input's sats")

		// Exactly one entry per distinct assetId, each summed across all inputs.
		require.Len(t, r.Assets, 3, "one entry per distinct assetId")
		require.Equal(t, uint64(500+300+200), findAssetAmount(r.Assets, "aaa"),
			"aaa summed across the two single-asset vtxos and the multi-asset vtxo")
		require.Equal(t, uint64(1000), findAssetAmount(r.Assets, "bbb"))
		require.Equal(t, uint64(7), findAssetAmount(r.Assets, "ccc"))

		// Assets are sorted by assetId for a deterministic output.
		require.Equal(t, "aaa", r.Assets[0].AssetId)
		require.Equal(t, "bbb", r.Assets[1].AssetId)
		require.Equal(t, "ccc", r.Assets[2].AssetId)
	})

	t.Run("multi-asset single vtxo: all its assets declared on one receiver", func(t *testing.T) {
		r := buildConsolidatedReceiver([]clienttypes.VtxoWithTapTree{
			vtxoWith(330,
				clienttypes.Asset{AssetId: "bbb", Amount: 200},
				clienttypes.Asset{AssetId: "aaa", Amount: 100},
			),
		}, "addr", dust)
		require.Len(t, r.Assets, 2, "both assets of the vtxo must be declared")
		require.Equal(t, uint64(100), findAssetAmount(r.Assets, "aaa"))
		require.Equal(t, uint64(200), findAssetAmount(r.Assets, "bbb"))
		require.Equal(t, uint64(330), r.Amount, "single carrier => Amount == its sats")
	})

	t.Run("asset carrier sats are summed, never dropped to a flat dust", func(t *testing.T) {
		r := buildConsolidatedReceiver([]clienttypes.VtxoWithTapTree{
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 500}),
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 300}),
		}, "addr1", dust)
		// Carrier sum: 330 + 330 = 660 (NOT a flat 330 — that would lose 330 sats).
		require.Equal(t, uint64(660), r.Amount,
			"consolidated Amount must be the SUM of carrier sats, not a flat dust")
		require.Len(t, r.Assets, 1)
		require.Equal(t, uint64(800), findAssetAmount(r.Assets, "aaa"))
	})

	t.Run("sub-dust total floored to dust", func(t *testing.T) {
		r := buildConsolidatedReceiver([]clienttypes.VtxoWithTapTree{
			vtxoWith(0, clienttypes.Asset{AssetId: "aaa", Amount: 5}),
		}, "addr1", dust)
		require.Equal(t, dust, r.Amount, "sub-dust total must be floored to dust")
		require.Len(t, r.Assets, 1)
	})
}

func TestWithMigrationOutput(t *testing.T) {
	receiver := clienttypes.Receiver{
		To:     "addr1",
		Amount: 3000,
		Assets: []clienttypes.Asset{{AssetId: "asset1", Amount: 7}},
	}

	t.Run("adds self receiver when client-lib returns no change outputs", func(t *testing.T) {
		res := withMigrationOutput(clientwallet.OffchainTxRes{}, receiver)

		require.Len(t, res.Outputs, 1)
		require.Equal(t, receiver, res.Outputs[0])
	})

	t.Run("does not duplicate receiver already present", func(t *testing.T) {
		res := withMigrationOutput(clientwallet.OffchainTxRes{
			Outputs: []clienttypes.Receiver{receiver},
		}, receiver)

		require.Len(t, res.Outputs, 1)
		require.Equal(t, receiver, res.Outputs[0])
	})
}

// --- migration input cap ---------------------------------------------------

// TestMigrationInputCapBatchesAllByValue verifies the per-transaction input cap:
// when the ToMigrate set exceeds the default cap, every vtxo is still included in
// this reconcile pass, split into capped batches ordered by sats value descending.
func TestMigrationInputCapBatchesAllByValue(t *testing.T) {
	// Build defaultMaxMigrationInputs+5 vtxos with strictly increasing sats values so
	// the top-by-value selection is unambiguous.
	const extra = 5
	total := defaultMaxMigrationInputs + extra
	all := make([]clienttypes.VtxoWithTapTree, 0, total)
	for i := 0; i < total; i++ {
		all = append(all, vtxoWithScript(
			fmt.Sprintf("s%d", i), uint64(1000+i), // value increases with i
		))
	}

	batches := migrationBatches(all, defaultMaxMigrationInputs)

	expectedBatches := (total + defaultMaxMigrationInputs - 1) / defaultMaxMigrationInputs
	require.Len(t, batches, expectedBatches, "all inputs are drained across capped batches")
	require.Len(t, batches[0], defaultMaxMigrationInputs, "first batch is capped")
	require.Len(t, batches[len(batches)-1], total%defaultMaxMigrationInputs,
		"last batch carries the remainder")

	// The first batch must be the defaultMaxMigrationInputs highest-value vtxos
	// (values total-1 .. extra), and the final batch the lowest-value ones
	// (values 1000 .. 1000+extra-1).
	firstBatchValues := map[uint64]bool{}
	for _, v := range batches[0] {
		firstBatchValues[v.Amount] = true
	}
	for i := extra; i < total; i++ {
		require.True(t, firstBatchValues[uint64(1000+i)],
			"high-value vtxo %d must be in the first batch", 1000+i)
	}
	lastBatch := batches[len(batches)-1]
	for _, v := range lastBatch {
		require.Less(t, v.Amount, uint64(1000+len(lastBatch)),
			"only the lowest-value vtxos are in the final batch")
	}
}

func TestMigrationInputCapUsesConfiguredLimit(t *testing.T) {
	const cap = 3
	all := []clienttypes.VtxoWithTapTree{
		vtxoWith(10), vtxoWith(50), vtxoWith(20), vtxoWith(40), vtxoWith(30),
	}

	batches := migrationBatches(all, cap)

	require.Len(t, batches, 2)
	require.Len(t, batches[0], cap)
	require.Len(t, batches[1], 2)
	require.Equal(t, uint64(50), batches[0][0].Amount)
	require.Equal(t, uint64(40), batches[0][1].Amount)
	require.Equal(t, uint64(30), batches[0][2].Amount)
	require.Equal(t, uint64(20), batches[1][0].Amount)
	require.Equal(t, uint64(10), batches[1][1].Amount)
}

func TestMigrationInputLimitDefault(t *testing.T) {
	require.Equal(t, defaultMaxMigrationInputs, (&wallet{}).migrationInputLimit())
	require.Equal(t, 7, (&wallet{maxMigrationInputs: 7}).migrationInputLimit())
	require.Len(t, migrationBatches([]clienttypes.VtxoWithTapTree{
		vtxoWith(1),
	}, 0), 1)
}

// TestMigrationInputCapNoTruncationUnderCap verifies that a set at or below the
// cap is migrated in a single sorted batch.
func TestMigrationInputCapNoTruncationUnderCap(t *testing.T) {
	all := []clienttypes.VtxoWithTapTree{
		vtxoWith(300), vtxoWith(100), vtxoWith(200),
	}
	batches := migrationBatches(all, defaultMaxMigrationInputs)
	require.Len(t, batches, 1, "a sub-cap set migrates in one batch")
	require.Len(t, batches[0], 3, "a sub-cap set migrates in full")
	// Still sorted highest-value first.
	require.Equal(t, uint64(300), batches[0][0].Amount)
	require.Equal(t, uint64(200), batches[0][1].Amount)
	require.Equal(t, uint64(100), batches[0][2].Amount)
}
