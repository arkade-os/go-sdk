package arksdk

import (
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

// TestDeriveAssetsFromPacket verifies that GetTransactionHistory's derived
// Assets field aggregates AssetPacket outputs by asset id, in first-seen
// order, deriving issuance ids from the txid + group index.
func TestDeriveAssetsFromPacket(t *testing.T) {
	t.Parallel()

	t.Run("nil packet returns nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, deriveAssetsFromPacket(nil, ""))
	})

	t.Run("empty packet returns nil", func(t *testing.T) {
		t.Parallel()
		require.Nil(t, deriveAssetsFromPacket(asset.Packet{}, ""))
	})

	t.Run("single group single output", func(t *testing.T) {
		t.Parallel()
		pkt := mustBuildPacket(t, []testGroup{
			{id: testAssetId(t, 1), outs: []uint64{100}},
		})
		got := deriveAssetsFromPacket(pkt, "")
		require.Len(t, got, 1)
		require.Equal(t, testAssetId(t, 1).String(), got[0].AssetId)
		require.Equal(t, uint64(100), got[0].Amount)
	})

	t.Run("multi-output group sums", func(t *testing.T) {
		t.Parallel()
		pkt := mustBuildPacket(t, []testGroup{
			{id: testAssetId(t, 1), outs: []uint64{50, 75, 25}},
		})
		got := deriveAssetsFromPacket(pkt, "")
		require.Len(t, got, 1)
		require.Equal(t, uint64(150), got[0].Amount)
	})

	t.Run("multiple asset ids preserve first-seen order", func(t *testing.T) {
		t.Parallel()
		pkt := mustBuildPacket(t, []testGroup{
			{id: testAssetId(t, 7), outs: []uint64{10}},
			{id: testAssetId(t, 3), outs: []uint64{20}},
			{id: testAssetId(t, 7), outs: []uint64{30}}, // same id as first group, should merge
		})
		got := deriveAssetsFromPacket(pkt, "")
		require.Len(t, got, 2)
		require.Equal(t, testAssetId(t, 7).String(), got[0].AssetId)
		require.Equal(t, uint64(40), got[0].Amount) // 10 + 30
		require.Equal(t, testAssetId(t, 3).String(), got[1].AssetId)
		require.Equal(t, uint64(20), got[1].Amount)
	})

	t.Run("issuance group derives id from txid and group index", func(t *testing.T) {
		t.Parallel()

		txid := testTxid(t, 9)
		pkt := mustBuildPacket(t, []testGroup{
			{id: nil, outs: []uint64{12, 8}},
		})

		got := deriveAssetsFromPacket(pkt, txid)
		require.Len(t, got, 1)
		derived, err := asset.NewAssetId(txid, 0)
		require.NoError(t, err)
		require.Equal(t, derived.String(), got[0].AssetId)
		require.Equal(t, uint64(20), got[0].Amount)
	})
}

// testGroup is a minimal test shape for building asset.Packet instances.
type testGroup struct {
	id   *asset.AssetId
	outs []uint64
}

// mustBuildPacket assembles an asset.Packet from simple group descriptions.
// It constructs groups using a single fake non-nil AssetInput so that the
// reissuance/burn invariants in asset.NewAssetGroup don't reject them.
func mustBuildPacket(t *testing.T, groups []testGroup) asset.Packet {
	t.Helper()
	out := make([]asset.AssetGroup, 0, len(groups))
	for i, g := range groups {
		outputs := make([]asset.AssetOutput, 0, len(g.outs))
		for j, amt := range g.outs {
			o, err := asset.NewAssetOutput(uint16(j), amt)
			require.NoError(t, err)
			outputs = append(outputs, *o)
		}
		var inputs []asset.AssetInput
		if g.id != nil {
			// Build one matching input per output to satisfy input/output sum
			// invariants enforced by asset.NewAssetGroup for non-issuance groups.
			inputs = make([]asset.AssetInput, 0, len(g.outs))
			for k, amt := range g.outs {
				in, err := asset.NewAssetInput(uint16(100+i*10+k), amt)
				require.NoError(t, err)
				inputs = append(inputs, *in)
			}
		}
		grp, err := asset.NewAssetGroup(g.id, nil, inputs, outputs, nil)
		require.NoError(t, err)
		out = append(out, *grp)
	}
	return asset.Packet(out)
}

// testAssetId fabricates a deterministic non-nil asset id from an index so
// that tests can distinguish multiple ids without pulling chain state.
func testAssetId(t *testing.T, index uint16) *asset.AssetId {
	t.Helper()
	h := chainhash.Hash{}
	h[0] = byte(index)
	id, err := asset.NewAssetId(h.String(), index)
	require.NoError(t, err)
	return id
}

func testTxid(t *testing.T, seed byte) string {
	t.Helper()
	h := chainhash.Hash{}
	h[0] = seed
	return h.String()
}

// TestPersistIssuedAssets_NilStore confirms that the convenience method
// tolerates a nil store (no panic), which matters when tests inject a
// minimal arkClient without a real store attached.
func TestPersistIssuedAssets_NilStore(t *testing.T) {
	t.Parallel()
	c := &arkClient{}
	// Should not panic.
	c.persistIssuedAssets(t.Context(), nil, nil, nil)
	c.persistIssuedAssets(
		t.Context(),
		[]asset.AssetId{*testAssetId(t, 1)},
		clientTypes.NewControlAsset{},
		nil,
	)
}
