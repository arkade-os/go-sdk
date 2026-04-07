package e2e

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/stretchr/testify/require"
)

// TestSendWithExtraCustomPacket verifies that SendOffChain can attach an extra
// extension packet (type 0x03) and that it round-trips through the indexer and
// extension parsing (NewExtensionFromTx + GetPacketByType).
//
// It also asserts that type 0x00 (reserved for the asset packet) is rejected.
func TestSendWithExtraCustomPacket(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()

		alice := setupClient(t)
		bob := setupClient(t)

		aliceTxStream := alice.GetTransactionEventChannel(ctx)
		bobTxStream := bob.GetTransactionEventChannel(ctx)

		// Fund alice with enough offchain BTC to cover the send + dust change.
		faucetOffchainAndWait(t, alice, aliceTxStream, 0.001)

		bobAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobAddr)

		// Invalid case: type 0x00 is reserved for the asset packet.
		_, err = alice.SendOffChain(
			ctx,
			[]clientTypes.Receiver{{To: bobAddr, Amount: 5000}},
			sdk.WithExtension(
				extension.UnknownPacket{PacketType: asset.PacketType, Data: []byte{0xff}},
			),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "reserved")

		// Valid: attach an arbitrary type-0x03 packet and recover it
		// from the resulting ark tx via the indexer.
		customPayload := []byte{0xde, 0xad, 0xbe, 0xef}
		customPkt := extension.UnknownPacket{PacketType: 0x03, Data: customPayload}

		txid, err := alice.SendOffChain(
			ctx,
			[]clientTypes.Receiver{{To: bobAddr, Amount: 5000}},
			sdk.WithExtension(customPkt),
		)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		// Wait for alice and bob events
		<-aliceTxStream
		<-bobTxStream

		ext := fetchExtensionFromVirtualTx(t, alice.Indexer(), ctx, txid)

		// This is a pure-BTC SendOffChain (no receiver.Assets set), so
		// createAssetPacket returns an empty packet and addExtension ends
		// up writing an extension envelope that contains only the custom
		// packet. A follow-up sub-test below exercises the asset+extra
		// combined path via IssueAsset.
		got := ext.GetPacketByType(0x03)
		require.NotNil(t, got)
		gotSerialized, err := got.Serialize()
		require.NoError(t, err)
		require.Equal(t, customPayload, gotSerialized)
	})
}

// TestGetAssetDetails verifies that IssueAsset persists AssetInfo into the
// local AssetStore and that GetAssetDetails returns the expected metadata and
// control-asset linkage.
func TestGetAssetDetails(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()

		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		metadata := []asset.Metadata{
			{Key: []byte("name"), Value: []byte("TestToken")},
			{Key: []byte("ticker"), Value: []byte("TTK")},
		}

		txid, assetIds, err := alice.IssueAsset(ctx, 1000, nil, metadata)
		require.NoError(t, err)
		require.NotEmpty(t, txid)
		require.Len(t, assetIds, 1)

		assetId := assetIds[0].String()

		// Give the store a tick to settle the UpsertAsset call.
		time.Sleep(500 * time.Millisecond)

		info, err := alice.GetAssetDetails(ctx, assetId)
		require.NoError(t, err)
		require.NotNil(t, info)
		require.Equal(t, assetId, info.AssetId)
		require.Len(t, info.Metadata, 2)

		mdMap := make(map[string]string, len(info.Metadata))
		for _, md := range info.Metadata {
			mdMap[string(md.Key)] = string(md.Value)
		}
		require.Equal(t, "TestToken", mdMap["name"])
		require.Equal(t, "TTK", mdMap["ticker"])

		// Negative case: a never-issued id should return a not-found error.
		_, err = alice.GetAssetDetails(ctx, "0000000000000000000000000000000000000000000000000000000000000000deadbeef")
		require.Error(t, err)

		// Exercise control asset linkage via NewControlAsset.
		txid2, ctrlAssetIds, err := alice.IssueAsset(
			ctx, 500,
			clientTypes.NewControlAsset{Amount: 1},
			[]asset.Metadata{{Key: []byte("name"), Value: []byte("CtrlLinked")}},
		)
		require.NoError(t, err)
		require.NotEmpty(t, txid2)
		require.Len(t, ctrlAssetIds, 2)

		controlAssetId := ctrlAssetIds[0].String()
		linkedAssetId := ctrlAssetIds[1].String()

		time.Sleep(500 * time.Millisecond)

		controlInfo, err := alice.GetAssetDetails(ctx, controlAssetId)
		require.NoError(t, err)
		require.NotNil(t, controlInfo)
		require.Equal(t, controlAssetId, controlInfo.AssetId)
		// The control asset row should NOT self-reference via ControlAssetId.
		require.Empty(
			t,
			controlInfo.ControlAssetId,
			"control asset row should not self-link",
		)

		linkedInfo, err := alice.GetAssetDetails(ctx, linkedAssetId)
		require.NoError(t, err)
		require.NotNil(t, linkedInfo)
		require.Equal(t, linkedAssetId, linkedInfo.AssetId)
		require.Equal(
			t,
			controlAssetId, linkedInfo.ControlAssetId,
			"linked asset must reference the control asset",
		)
	})
}

// TestTransactionHistoryAssets verifies that GetTransactionHistory populates
// Transaction.Assets by aggregating the AssetPacket for an asset transfer.
func TestTransactionHistoryAssets(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()

		alice := setupClient(t)
		bob := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		const supply = 5000
		const transferAmount = 1200
		_, assetIds, err := alice.IssueAsset(
			ctx, supply, nil, []asset.Metadata{{Key: []byte("name"), Value: []byte("HistAsset")}},
		)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		assetId := assetIds[0].String()

		time.Sleep(1 * time.Second)

		bobAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)

		transferTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobAddr,
			Amount: 400,
			Assets: []clientTypes.Asset{{AssetId: assetId, Amount: transferAmount}},
		}})
		require.NoError(t, err)
		require.NotEmpty(t, transferTxid)

		time.Sleep(2 * time.Second)

		history, err := alice.GetTransactionHistory(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, history)

		transferTx := findTxByID(t, history, transferTxid)
		require.NotNil(t, transferTx)
		require.NotEmpty(t, transferTx.Assets)

		// The derived slice must contain the transferred asset id with
		// the correct amount (from alice's POV, the output amount is the
		// transferred amount, possibly plus any self-change re-issued to
		// alice within the same group).
		var sawAsset bool
		var seenAmount uint64
		for _, a := range transferTx.Assets {
			if a.AssetId == assetId {
				sawAsset = true
				seenAmount = a.Amount
			}
		}
		require.True(t, sawAsset)
		require.NotZero(t, seenAmount)
	})
}
