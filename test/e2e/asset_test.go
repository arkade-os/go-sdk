package e2e

import (
	"sync"
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestAssetTransfer tests the transfer of an asset between alice and bob.
// then they both settle their funds.
func TestAssetTransferAndRenew(t *testing.T) {
	ctx := t.Context()
	const supply = 5_000
	const transferAmount = 1_200

	alice := setupClient(t)
	bob := setupClient(t)

	wg := &sync.WaitGroup{}
	wg.Go(func() {
		faucetOffchain(t, alice, 0.002)
	})
	wg.Go(func() {
		faucetOffchain(t, bob, 0.001)
	})
	wg.Wait()

	txid, assetIds, err := alice.IssueAsset(ctx, supply, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIds, 1)

	assetId := assetIds[0].String()

	assetVtxos := listVtxosWithAsset(t, alice, assetId)
	require.Len(t, assetVtxos, 1)
	require.Len(t, assetVtxos[0].Assets, 1)
	require.Equal(t, supply, int(assetVtxos[0].Assets[0].Amount))
	require.Equal(t, assetId, assetVtxos[0].Assets[0].AssetId)
	require.Equal(t, txid, assetVtxos[0].Txid)

	_, bobAddr, _, err := bob.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	_, err = alice.SendOffChain(
		ctx, []types.Receiver{
			{To: bobAddr, Amount: 400, Assets: []types.Asset{
				{AssetId: assetId, Amount: transferAmount},
			}},
		},
	)
	require.NoError(t, err)

	// Allow some time for bob to receive the vtxo from indexer
	time.Sleep(2 * time.Second)

	receiverAssetVtxos := listVtxosWithAsset(t, bob, assetId)
	require.Len(t, receiverAssetVtxos, 1)
	require.Len(t, receiverAssetVtxos[0].Assets, 1)
	require.Equal(t, transferAmount, int(receiverAssetVtxos[0].Assets[0].Amount))
	require.Equal(t, assetId, receiverAssetVtxos[0].Assets[0].AssetId)

	receiverBalance, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.NotNil(t, receiverBalance)
	require.NotNil(t, receiverBalance.AssetBalances)

	assetBalance, ok := receiverBalance.AssetBalances[assetId]
	require.True(t, ok)
	require.Equal(t, int(assetBalance), int(transferAmount))

	var aliceErr, bobErr error
	wg = &sync.WaitGroup{}
	wg.Go(func() {
		_, aliceErr = alice.Settle(ctx)
	})
	wg.Go(func() {
		_, bobErr = bob.Settle(ctx)
	})

	wg.Wait()
	require.NoError(t, aliceErr)
	require.NoError(t, bobErr)
}

func TestIssuance(t *testing.T) {
	t.Run("without control asset", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		_, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
	})

	t.Run("with new control asset", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		_, assetIds, err := alice.IssueAsset(ctx, 1, types.NewControlAsset{Amount: 1}, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 2)

		controlAssetId := assetIds[0].String()
		assetId := assetIds[1].String()
		require.NotEqual(t, controlAssetId, assetId)
	})

	t.Run("with existing control asset", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		// issue control asset
		_, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		controlAssetId := assetIds[0].String()

		// issue another asset	 with existing control asset
		_, assetIds2, err := alice.IssueAsset(
			ctx,
			1,
			types.ExistingControlAsset{ID: controlAssetId},
			nil,
		)
		require.NoError(t, err)
		require.Len(t, assetIds2, 1)

		require.NotEqual(t, assetIds[0].String(), assetIds2[0].String())
	})
}

// TestAssetReissuance makes issue an asset with a control asset and then reissue it.
func TestAssetReissuance(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t)
	faucetOffchain(t, alice, 0.01)

	// issue an asset with a control asset
	_, assetIds, err := alice.IssueAsset(ctx, 1, types.NewControlAsset{Amount: 1}, nil)
	require.NoError(t, err)
	require.Len(t, assetIds, 2)

	controlAssetId := assetIds[0].String()
	assetId := assetIds[1].String()
	require.NotEqual(t, controlAssetId, assetId)

	controlVtxos := listVtxosWithAsset(t, alice, controlAssetId)
	require.Len(t, controlVtxos, 1)
	require.Len(
		t,
		controlVtxos[0].Assets,
		2,
	) // should hold both the control asset and the issued asset
	require.Equal(t, controlAssetId, controlVtxos[0].Assets[0].AssetId)
	require.Equal(t, uint64(1), controlVtxos[0].Assets[0].Amount)
	require.Equal(t, assetId, controlVtxos[0].Assets[1].AssetId)
	require.Equal(t, uint64(1), controlVtxos[0].Assets[1].Amount)

	_, err = alice.ReissueAsset(ctx, controlAssetId, assetId, 1000)
	require.NoError(t, err)

	assetVtxos := listVtxosWithAsset(t, alice, assetId)
	require.Len(t, assetVtxos, 2)
}

func TestAssetBurn(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t)
	faucetOffchain(t, alice, 0.01)

	_, assetIds, err := alice.IssueAsset(ctx, 5000, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIds, 1)
	assetId := assetIds[0].String()

	assetVtxos := listVtxosWithAsset(t, alice, assetId)
	require.Len(t, assetVtxos, 1)
	require.Len(t, assetVtxos[0].Assets, 1)
	require.Equal(t, uint64(5000), assetVtxos[0].Assets[0].Amount)

	_, err = alice.BurnAsset(ctx, assetId, 1500)
	require.NoError(t, err)

	assetVtxos = listVtxosWithAsset(t, alice, assetId)
	require.Len(t, assetVtxos, 1)
	require.Len(t, assetVtxos[0].Assets, 1)
	require.Equal(t, uint64(3500), assetVtxos[0].Assets[0].Amount)
}

func listVtxosWithAsset(t *testing.T, client arksdk.ArkClient, assetID string) []types.Vtxo {
	vtxos, err := client.ListSpendableVtxos(t.Context())
	require.NoError(t, err)

	assetVtxos := make([]types.Vtxo, 0, len(vtxos))

	for _, vtxo := range vtxos {
		for _, asset := range vtxo.Assets {
			if asset.AssetId == assetID {
				assetVtxos = append(assetVtxos, vtxo)
				break
			}
		}
	}

	return assetVtxos
}
