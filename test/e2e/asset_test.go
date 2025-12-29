package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestAssetLifecycleWithStatefulClient(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)
	receiver := setupClient(t)

	// Fund issuer so they can pay for asset creation and transfer.
	faucetOffchain(t, issuer, 0.002)

	const supply uint64 = 5_000
	createParams := types.AssetCreationParams{
		Quantity:    supply,
		MetadataMap: map[string]string{"name": "Test Asset", "symbol": "TST"},
	}

	_, assetIds, err := issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: createParams}})
	require.NoError(t, err)

	time.Sleep(5 * time.Second) // Wait for server indexer

	issuerAssetVtxo, err := getAssetVtxo(ctx, issuer, assetIds[0], supply)
	require.NoError(t, err)

	require.EqualValues(t, supply, issuerAssetVtxo.Asset.Amount)

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferAmount uint64 = 1_200
	_, err = issuer.SendAsset(ctx, []types.AssetReceiver{{
		Receiver: types.Receiver{
			To:     receiverOffchainAddr,
			Amount: transferAmount,
		},
		AssetId: assetIds[0],
	}})
	require.NoError(t, err)

	receiverAssetVtxo, err := getAssetVtxo(ctx, receiver, assetIds[0], transferAmount)
	require.NoError(t, err)
	require.EqualValues(t, transferAmount, receiverAssetVtxo.Asset.Amount)

	receiverBalance, err := receiver.Balance(ctx, false)
	require.NoError(t, err)
	// Verify receiver balance
	assetBalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetIds[0]]
	require.True(t, ok)
	require.GreaterOrEqual(t, int(assetBalance.TotalAmount), int(transferAmount))

	// Final Settlement
	_, err = issuer.Settle(ctx)
	require.NoError(t, err)
	_, err = receiver.Settle(ctx)
	require.NoError(t, err)
}

func TestMultiAssetTransfer(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)
	receiver := setupClient(t)

	// Fund issuer so they can pay for asset creation and transfer.
	faucetOffchain(t, issuer, 0.005)

	const assetASupply uint64 = 3_000
	assetAParams := types.AssetCreationParams{
		Quantity:    assetASupply,
		MetadataMap: map[string]string{"name": "Multi Asset A", "symbol": "MA"},
	}
	_, assetIds, err := issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: assetAParams}})
	require.NoError(t, err)

	assetIdA := assetIds[0]

	time.Sleep(2 * time.Second) // Wait for server indexer

	const assetBSupply uint64 = 4_000
	assetBParams := types.AssetCreationParams{
		Quantity:    assetBSupply,
		MetadataMap: map[string]string{"name": "Multi Asset B", "symbol": "MB"},
	}
	_, assetIds, err = issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: assetBParams}})
	require.NoError(t, err)

	assetIdB := assetIds[0]

	time.Sleep(5 * time.Second) // Wait for server indexer

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferA uint64 = 1_200
	const transferB uint64 = 1_700
	arkTxid, err := issuer.SendAsset(ctx, []types.AssetReceiver{
		{
			Receiver: types.Receiver{
				To:     receiverOffchainAddr,
				Amount: transferA,
			},
			AssetId: assetIdA,
		},
		{
			Receiver: types.Receiver{
				To:     receiverOffchainAddr,
				Amount: transferB,
			},
			AssetId: assetIdB,
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, arkTxid)

	receiverAssetAVtxo, err := getAssetVtxo(ctx, receiver, assetIdA, transferA)
	require.NoError(t, err)
	require.EqualValues(t, transferA, receiverAssetAVtxo.Asset.Amount)

	receiverAssetBVtxo, err := getAssetVtxo(ctx, receiver, assetIdB, transferB)
	require.NoError(t, err)
	require.EqualValues(t, transferB, receiverAssetBVtxo.Asset.Amount)

	receiverBalance, err := receiver.Balance(ctx, false)
	require.NoError(t, err)

	assetABalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetIdA]
	require.True(t, ok)
	require.GreaterOrEqual(t, int(assetABalance.TotalAmount), int(transferA))

	assetBBalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetIdB]
	require.True(t, ok)
	require.GreaterOrEqual(t, int(assetBBalance.TotalAmount), int(transferB))

	_, err = issuer.Settle(ctx)
	require.NoError(t, err)
	_, err = receiver.Settle(ctx)
	require.NoError(t, err)
}

func TestAssetModification(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)

	// Fund issuer
	faucetOffchain(t, issuer, 0.01)

	// 1. Create Control Asset (regular asset used for control)
	controlAssetParams := types.AssetCreationParams{
		Quantity:    1,
		MetadataMap: map[string]string{"name": "Control Token", "desc": "Controls other assets"},
	}
	_, assetIds, err := issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: controlAssetParams}})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	controlAssetId := assetIds[0]

	controlVtxo, err := getAssetVtxo(ctx, issuer, controlAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), controlVtxo.Asset.Amount)

	targetAssetParams := types.AssetCreationParams{
		Quantity:       5000,
		ControlAssetId: controlVtxo.Asset.AssetId,
		MetadataMap:    map[string]string{"name": "Target Asset", "symbol": "TGT"},
	}
	_, assetIds, err = issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: targetAssetParams}})
	require.NoError(t, err)

	targetAssetId := assetIds[0]

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(5000), targetAssetVtxo.Asset.Amount)

	time.Sleep(2 * time.Second)

	// Settle to ensure everything is stable
	_, err = issuer.Settle(ctx)
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	const mintAmount uint64 = 1000
	newMetadata := map[string]string{"name": "Target Asset v2", "symbol": "TGT2"}

	_, err = issuer.ModifyAsset(ctx, controlAssetId, targetAssetId, mintAmount, newMetadata)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	assetResponse, err := issuer.GetAsset(ctx, targetAssetId)
	require.NoError(t, err)

	value, ok := assetResponse.Asset.Metadata["symbol"]

	require.True(t, ok)
	require.Equal(t, "TGT2", value)
	require.Equal(t, assetResponse.Asset.Quantity, uint64(6000)) // Original 5000 + 1000 minted

	_, err = getAssetVtxo(ctx, issuer, targetAssetId, mintAmount)
	require.NoError(t, err)

	immutableParams := types.AssetCreationParams{
		Quantity:       1000,
		Immutable:      true,
		MetadataMap:    map[string]string{"name": "Immutable", "fixed": "true"},
		ControlAssetId: controlAssetId,
	}
	_, assetIds, err = issuer.CreateAssets(ctx, []types.AssetCreationRequest{{Params: immutableParams}})
	require.NoError(t, err)

	immutableAssetId := assetIds[0]

	time.Sleep(2 * time.Second)
	_, err = issuer.ModifyAsset(ctx, controlAssetId, immutableAssetId, 100, map[string]string{"fixed": "false"})
	require.NoError(t, err)

	immutableResp, err := issuer.GetAsset(ctx, immutableAssetId)
	require.NoError(t, err)

	value, ok = immutableResp.Asset.Metadata["fixed"]

	require.True(t, ok)
	require.Equal(t, "false", value)
}

func getAssetVtxo(ctx context.Context, client arksdk.ArkClient, assetID string, amount uint64) (types.Vtxo, error) {
	vtxos, err := client.ListSpendableVtxos(ctx)
	if err != nil {
		return types.Vtxo{}, err
	}

	for _, vtxo := range vtxos {
		if vtxo.Asset != nil && vtxo.Asset.AssetId == assetID {
			if amount == 0 || vtxo.Asset.Amount >= amount {
				return vtxo, nil
			}
		}
	}

	return types.Vtxo{}, fmt.Errorf("no suitable vtxo found for asset %s", assetID)
}
