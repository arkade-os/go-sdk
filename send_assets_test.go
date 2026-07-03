package arksdk

import (
	"fmt"
	"testing"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/stretchr/testify/require"
)

// --- buildConsolidatedReceiver ---------------------------------------------

// TestConsolidatedReceiverShape covers sats, assets, sorting, and dust floor.
func TestBuildReceiverForMigration(t *testing.T) {
	const dust = uint64(330)

	t.Run("pure sats: exact sum, no assets", func(t *testing.T) {
		r := buildReceiverForMigration([]clienttypes.VtxoWithTapTree{
			vtxoWith(1000), vtxoWith(2000),
		}, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		require.Equal(t, uint64(3000), r.Amount)
		require.Nil(t, r.Assets, "pure-sats inputs declare no assets")
	})

	t.Run("nil/empty input set is dust-floored sats receiver", func(t *testing.T) {
		r := buildReceiverForMigration(nil, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		require.Equal(t, dust, r.Amount, "empty input set floors to dust")
		require.Nil(t, r.Assets)
	})

	t.Run("mixed pure-sats + multiple assets => one receiver, all summed", func(t *testing.T) {
		inputs := []clienttypes.VtxoWithTapTree{
			vtxoWith(50000), // pure sats
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 500}),
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 300}),
			vtxoWith(330, clienttypes.Asset{AssetId: "bbb", Amount: 1000}),
			vtxoWith(330,
				clienttypes.Asset{AssetId: "aaa", Amount: 200},
				clienttypes.Asset{AssetId: "ccc", Amount: 7},
			),
		}

		r := buildReceiverForMigration(inputs, "addr1", dust)
		require.Equal(t, "addr1", r.To)
		require.Equal(t, uint64(50000+330*4), r.Amount,
			"consolidated Amount must be the sum of every input's sats")

		require.Len(t, r.Assets, 3, "one entry per distinct assetId")
		require.Equal(t, uint64(500+300+200), findAssetAmount(r.Assets, "aaa"),
			"aaa summed across the two single-asset vtxos and the multi-asset vtxo")
		require.Equal(t, uint64(1000), findAssetAmount(r.Assets, "bbb"))
		require.Equal(t, uint64(7), findAssetAmount(r.Assets, "ccc"))

		require.Equal(t, "aaa", r.Assets[0].AssetId)
		require.Equal(t, "bbb", r.Assets[1].AssetId)
		require.Equal(t, "ccc", r.Assets[2].AssetId)
	})

	t.Run("multi-asset single vtxo: all its assets declared on one receiver", func(t *testing.T) {
		r := buildReceiverForMigration([]clienttypes.VtxoWithTapTree{
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
		r := buildReceiverForMigration([]clienttypes.VtxoWithTapTree{
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 500}),
			vtxoWith(330, clienttypes.Asset{AssetId: "aaa", Amount: 300}),
		}, "addr1", dust)
		require.Equal(t, uint64(660), r.Amount,
			"consolidated Amount must be the SUM of carrier sats, not a flat dust")
		require.Len(t, r.Assets, 1)
		require.Equal(t, uint64(800), findAssetAmount(r.Assets, "aaa"))
	})

	t.Run("sub-dust total floored to dust", func(t *testing.T) {
		r := buildReceiverForMigration([]clienttypes.VtxoWithTapTree{
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

// --- migration input chunks -------------------------------------------------

// TestMigrationInputCapChunksAllByValue verifies capped, sorted chunks.
func TestMigrationInputCapChunksAllByValue(t *testing.T) {
	const extra = 5
	total := defaultMaxMigrationInputs + extra
	all := make([]clienttypes.VtxoWithTapTree, 0, total)
	for i := 0; i < total; i++ {
		all = append(all, vtxoWithScript(
			fmt.Sprintf("s%d", i), uint64(1000+i), // value increases with i
		))
	}

	chunks := migrationChunks(all, defaultMaxMigrationInputs)

	expectedChunks := (total + defaultMaxMigrationInputs - 1) / defaultMaxMigrationInputs
	require.Len(t, chunks, expectedChunks, "all inputs are drained across capped chunks")
	require.Len(t, chunks[0], defaultMaxMigrationInputs, "first chunk is capped")
	require.Len(t, chunks[len(chunks)-1], total%defaultMaxMigrationInputs,
		"last chunk carries the remainder")

	firstChunkValues := map[uint64]bool{}
	for _, v := range chunks[0] {
		firstChunkValues[v.Amount] = true
	}
	for i := extra; i < total; i++ {
		require.True(t, firstChunkValues[uint64(1000+i)],
			"high-value vtxo %d must be in the first chunk", 1000+i)
	}
	lastChunk := chunks[len(chunks)-1]
	for _, v := range lastChunk {
		require.Less(t, v.Amount, uint64(1000+len(lastChunk)),
			"only the lowest-value vtxos are in the final chunk")
	}
}

func TestMigrationInputCapUsesConfiguredLimit(t *testing.T) {
	const cap = 3
	all := []clienttypes.VtxoWithTapTree{
		vtxoWith(10), vtxoWith(50), vtxoWith(20), vtxoWith(40), vtxoWith(30),
	}

	chunks := migrationChunks(all, cap)

	require.Len(t, chunks, 2)
	require.Len(t, chunks[0], cap)
	require.Len(t, chunks[1], 2)
	require.Equal(t, uint64(50), chunks[0][0].Amount)
	require.Equal(t, uint64(40), chunks[0][1].Amount)
	require.Equal(t, uint64(30), chunks[0][2].Amount)
	require.Equal(t, uint64(20), chunks[1][0].Amount)
	require.Equal(t, uint64(10), chunks[1][1].Amount)
}

// TestMigrationInputCapNoTruncationUnderCap verifies sub-cap chunking.
func TestMigrationInputCapNoTruncationUnderCap(t *testing.T) {
	all := []clienttypes.VtxoWithTapTree{
		vtxoWith(300), vtxoWith(100), vtxoWith(200),
	}
	chunks := migrationChunks(all, defaultMaxMigrationInputs)
	require.Len(t, chunks, 1, "a sub-cap set migrates in one chunk")
	require.Len(t, chunks[0], 3, "a sub-cap set migrates in full")
	require.Equal(t, uint64(300), chunks[0][0].Amount)
	require.Equal(t, uint64(200), chunks[0][1].Amount)
	require.Equal(t, uint64(100), chunks[0][2].Amount)
}

// findAssetAmount returns assetID's receiver amount, or 0 if absent.
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
