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

func TestAssetLifecycle(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)
	receiver := setupClient(t)

	// Fund issuer so they can pay for asset creation and transfer.
	faucetOffchain(t, issuer, 0.002)

	// Fund receiver so they can pay for settlement.
	faucetOffchain(t, receiver, 0.001)

	const supply uint64 = 5_000
	createParams := types.AssetCreationParams{
		Quantity:    supply,
		MetadataMap: map[string]string{"name": "Test Asset", "symbol": "TST"},
	}

	_, assetIds, err := issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: createParams},
	)

	require.NoError(t, err)

	time.Sleep(5 * time.Second) // Wait for server indexer

	issuerAssetVtxo, err := getAssetVtxo(ctx, issuer, assetIds[0], supply)
	require.NoError(t, err)

	require.EqualValues(t, supply, issuerAssetVtxo.Assets[0].Amount)

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferAmount uint64 = 1_200
	_, err = issuer.SendAsset(
		ctx,
		[]types.Receiver{{
			To:     receiverOffchainAddr,
			Amount: transferAmount,
		}},
		assetIds[0],
	)
	require.NoError(t, err)

	// Allow some time for the indexer to process the transfer
	time.Sleep(5 * time.Second)

	receiverAssetVtxo, err := getAssetVtxo(ctx, receiver, assetIds[0], transferAmount)
	require.NoError(t, err)
	require.EqualValues(t, transferAmount, receiverAssetVtxo.Assets[0].Amount)

	receiverBalance, err := receiver.Balance(ctx)
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

func TestAssetReissuance(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)

	// Fund issuer
	faucetOffchain(t, issuer, 0.01)

	// 1. Create Control Asset (regular asset used for control)
	controlAssetParams := types.AssetCreationParams{
		Quantity:    1,
		MetadataMap: map[string]string{"name": "Control Token", "desc": "Controls other assets"},
	}
	_, assetIds, err := issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: controlAssetParams},
	)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	controlAssetId := assetIds[0]

	controlVtxo, err := getAssetVtxo(ctx, issuer, controlAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), controlVtxo.Assets[0].Amount)

	targetAssetParams := types.AssetCreationParams{
		Quantity:       5000,
		ControlAssetId: controlVtxo.Assets[0].AssetId,
		MetadataMap:    map[string]string{"name": "Target Asset", "symbol": "TGT"},
	}
	_, assetIds, err = issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: targetAssetParams},
	)
	require.NoError(t, err)

	targetAssetId := assetIds[0]

	time.Sleep(2 * time.Second)

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(5000), targetAssetVtxo.Assets[0].Amount)

	const mintAmount uint64 = 1000

	_, err = issuer.ReissueAsset(ctx, controlAssetId, targetAssetId, mintAmount)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	_, err = getAssetVtxo(ctx, issuer, targetAssetId, mintAmount)
	require.NoError(t, err)

	assetResponse, err := issuer.GetAsset(ctx, targetAssetId)
	require.NoError(t, err)

	require.Equal(t, assetResponse.Quantity, uint64(6000)) // Original 5000 + 1000 minted

	_, err = getAssetVtxo(ctx, issuer, targetAssetId, mintAmount)
	require.NoError(t, err)
}

func TestAssetBurn(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)

	// Fund issuer
	faucetOffchain(t, issuer, 0.01)

	// 1. Create Control Asset (regular asset used for control)
	controlAssetParams := types.AssetCreationParams{
		Quantity:    1,
		MetadataMap: map[string]string{"name": "Control Token", "desc": "Controls other assets"},
	}
	_, assetIds, err := issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: controlAssetParams},
	)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	controlAssetId := assetIds[0]

	controlVtxo, err := getAssetVtxo(ctx, issuer, controlAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), controlVtxo.Assets[0].Amount)

	targetAssetParams := types.AssetCreationParams{
		Quantity:       5000,
		ControlAssetId: controlVtxo.Assets[0].AssetId,
		MetadataMap:    map[string]string{"name": "Target Asset", "symbol": "TGT"},
	}
	_, assetIds, err = issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: targetAssetParams},
	)
	require.NoError(t, err)

	targetAssetId := assetIds[0]

	time.Sleep(2 * time.Second)

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(5000), targetAssetVtxo.Assets[0].Amount)

	const burnAmount uint64 = 1500

	_, err = issuer.BurnAsset(ctx, controlAssetId, targetAssetId, burnAmount)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	assetResponse, err := issuer.GetAsset(ctx, targetAssetId)
	require.NoError(t, err)

	require.Equal(t, assetResponse.Quantity, uint64(3500)) // Original 5000 - 1500 burned
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
	_, assetIds, err := issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: controlAssetParams},
	)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	controlAssetId := assetIds[0]

	controlVtxo, err := getAssetVtxo(ctx, issuer, controlAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), controlVtxo.Assets[0].Amount)

	targetAssetParams := types.AssetCreationParams{
		Quantity:       5000,
		ControlAssetId: controlVtxo.Assets[0].AssetId,
		MetadataMap:    map[string]string{"name": "Target Asset", "symbol": "TGT"},
	}
	_, assetIds, err = issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: targetAssetParams},
	)
	require.NoError(t, err)

	targetAssetId := assetIds[0]

	time.Sleep(2 * time.Second)

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId, 0)
	require.NoError(t, err)

	require.Equal(t, uint64(5000), targetAssetVtxo.Assets[0].Amount)

	newMetadata := map[string]string{"name": "Target Asset v2", "symbol": "TGT2"}

	_, err = issuer.ModifyAssetMetadata(ctx, controlAssetId, targetAssetId, newMetadata)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	assetResponse, err := issuer.GetAsset(ctx, targetAssetId)
	require.NoError(t, err)

	value, ok := assetResponse.Metadata["symbol"]

	require.True(t, ok)
	require.Equal(t, "TGT2", value)

	immutableParams := types.AssetCreationParams{
		Quantity:       1000,
		Immutable:      true,
		MetadataMap:    map[string]string{"name": "Immutable", "fixed": "true"},
		ControlAssetId: controlAssetId,
	}

	_, assetIds, err = issuer.CreateAsset(
		ctx,
		types.AssetCreationRequest{Params: immutableParams},
	)
	require.NoError(t, err)

	immutableAssetId := assetIds[0]

	time.Sleep(2 * time.Second)
	_, err = issuer.ModifyAssetMetadata(
		ctx,
		controlAssetId,
		immutableAssetId,
		map[string]string{"fixed": "false"},
	)
	require.NoError(t, err)

	immutableResp, err := issuer.GetAsset(ctx, immutableAssetId)
	require.NoError(t, err)

	value, ok = immutableResp.Metadata["fixed"]

	require.True(t, ok)
	require.Equal(t, "true", value)
}

func getAssetVtxo(
	ctx context.Context,
	client arksdk.ArkClient,
	assetID string,
	amount uint64,
) (types.Vtxo, error) {
	vtxos, err := client.ListSpendableVtxos(ctx)
	if err != nil {
		return types.Vtxo{}, err
	}

	for _, vtxo := range vtxos {
		if len(vtxo.Assets) > 0 && vtxo.Assets[0].AssetId == assetID {
			if amount == 0 || vtxo.Assets[0].Amount >= amount {
				return vtxo, nil
			}
		}
	}

	return types.Vtxo{}, fmt.Errorf("no suitable vtxo found for asset %s", assetID)
}
