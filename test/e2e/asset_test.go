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

	_, err := issuer.CreateAsset(ctx, []types.AssetCreationRequest{{Params: createParams}})
	require.NoError(t, err)

	issuerAssetVtxo := waitForAssetVtxo(t, ctx, issuer, nil)
	issuerAssetAmount, ok := assetAmountForVout(issuerAssetVtxo)
	require.True(t, ok)
	require.EqualValues(t, supply, issuerAssetAmount)

	// Allow server event handler to process the new VTXOs from CreateAsset
	time.Sleep(2 * time.Second)

	assetID := issuerAssetVtxo.Asset.AssetId
	fmt.Printf("This is asset id %s\n", assetID.ToString())

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferAmount uint64 = 1_200
	_, err = issuer.SendAsset(ctx, []types.AssetReceiver{{
		Receiver: types.Receiver{
			To:     receiverOffchainAddr,
			Amount: transferAmount,
		},
		AssetId: assetID.ToString(),
	}})
	require.NoError(t, err)

	receiverAssetVtxo := waitForAssetVtxo(t, ctx, receiver, func(v types.Vtxo) bool {
		return v.Asset.AssetId == assetID
	})
	receiverAmount, ok := assetAmountForVout(receiverAssetVtxo)
	require.True(t, ok)
	require.EqualValues(t, transferAmount, receiverAmount)

	receiverBalance, err := receiver.Balance(ctx, false)
	require.NoError(t, err)
	assetHex := assetID.ToString()
	// Verify receiver balance
	assetBalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetHex]
	require.True(t, ok)
	require.GreaterOrEqual(t, int(assetBalance.TotalAmount), int(transferAmount))

	// Final Settlement
	_, err = issuer.Settle(ctx)
	require.NoError(t, err)
	_, err = receiver.Settle(ctx)
	require.NoError(t, err)
}

func TestAssetModification(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)

	// Fund issuer
	faucetOffchain(t, issuer, 0.002)

	// 1. Create Control Asset (regular asset used for control)
	controlAssetParams := types.AssetCreationParams{
		Quantity:    1,
		MetadataMap: map[string]string{"name": "Control Token", "desc": "Controls other assets"},
	}
	_, err := issuer.CreateAsset(ctx, []types.AssetCreationRequest{{Params: controlAssetParams}})
	require.NoError(t, err)

	controlAssetVtxo := waitForAssetVtxo(t, ctx, issuer, nil)
	require.NotNil(t, controlAssetVtxo)
	controlAssetID := controlAssetVtxo.Asset.AssetId

	time.Sleep(2 * time.Second)

	targetAssetParams := types.AssetCreationParams{
		Quantity:       5000,
		ControlAssetId: controlAssetID.ToString(),
		MetadataMap:    map[string]string{"name": "Target Asset", "symbol": "TGT"},
	}
	_, err = issuer.CreateAsset(ctx, []types.AssetCreationRequest{{Params: targetAssetParams}})
	require.NoError(t, err)

	targetAssetVtxo := waitForAssetVtxo(t, ctx, issuer, func(v types.Vtxo) bool {
		return v.Asset.ControlAssetId != nil && *v.Asset.ControlAssetId == controlAssetID && v.Asset.AssetId != controlAssetID
	})
	require.NotNil(t, targetAssetVtxo)
	targetAssetID := targetAssetVtxo.Asset.AssetId

	println(targetAssetID.ToString())

	time.Sleep(2 * time.Second)
	// Settle to ensure everything is stable
	_, err = issuer.Settle(ctx)
	require.NoError(t, err)
	time.Sleep(2 * time.Second)

	const mintAmount uint64 = 1000
	newMetadata := map[string]string{"name": "Target Asset v2", "desc": "Upgraded"}

	_, err = issuer.ModifyAsset(ctx, controlAssetID.ToString(), targetAssetID.ToString(), mintAmount, newMetadata)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	modifiedVtxo := waitForAssetVtxo(t, ctx, issuer, func(v types.Vtxo) bool {
		if v.Asset.AssetId != targetAssetID {
			return false
		}
		// Check for new metadata
		for _, m := range v.Asset.Metadata {
			if m.Key == "desc" && m.Value == "Upgraded" {
				return true
			}
		}
		return false
	})
	require.NotNil(t, modifiedVtxo)

	modifiedAssetAmount, ok := assetAmountForVout(modifiedVtxo)
	require.True(t, ok)
	require.EqualValues(t, mintAmount, modifiedAssetAmount) // Check Asset Amount

	// Verify Metadata via Indexer Endpoint
	time.Sleep(2 * time.Second) // Wait for indexer to index the new state (if necessary)

	assetResp, err := issuer.GetAsset(ctx, targetAssetID.ToString())
	require.NoError(t, err)
	require.Equal(t, targetAssetID.ToString(), assetResp.Asset.Id)

	// Check metadata
	foundUpgraded := false
	for _, m := range assetResp.Asset.Metadata {
		if val, ok := m["key"]; ok && val == "desc" {
			if val2, ok2 := m["value"]; ok2 && val2 == "Upgraded" {
				foundUpgraded = true
				break
			}
		}
	}
	require.True(t, foundUpgraded, "Indexer metadata should contain 'desc': 'Upgraded'")

	_, err = issuer.Settle(ctx)
	require.NoError(t, err)

	_, err = issuer.ModifyAsset(ctx, "", targetAssetID.ToString(), 100, map[string]string{"foo": "bar"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "control asset id is required")

	immutableParams := types.AssetCreationParams{
		Quantity:    1000,
		Immutable:   true,
		MetadataMap: map[string]string{"name": "Immutable", "fixed": "true"},
	}
	_, err = issuer.CreateAsset(ctx, []types.AssetCreationRequest{{Params: immutableParams}})
	require.NoError(t, err)

	immutableVtxo := waitForAssetVtxo(t, ctx, issuer, func(v types.Vtxo) bool {
		for _, m := range v.Asset.Metadata {
			if m.Key == "name" && m.Value == "Immutable" {
				return true
			}
		}
		return false
	})
	require.NotNil(t, immutableVtxo)
	immutableID := immutableVtxo.Asset.AssetId

	time.Sleep(2 * time.Second)
	_, err = issuer.ModifyAsset(ctx, controlAssetID.ToString(), immutableID.ToString(), 100, map[string]string{"fixed": "false"})
	require.NoError(t, err)

	immutableResp, err := issuer.GetAsset(ctx, immutableID.ToString())
	require.NoError(t, err)

	fixedVal := ""
	for _, m := range immutableResp.Asset.Metadata {
		if val, ok := m["key"]; ok && val == "fixed" {
			fixedVal = m["value"]
		}
	}
	require.Equal(t, "true", fixedVal, "Immutable asset metadata should not change")
}

func waitForAssetVtxo(t *testing.T, ctx context.Context, client arksdk.ArkClient, matcher func(types.Vtxo) bool) types.Vtxo {
	t.Helper()

	var (
		found   types.Vtxo
		lastErr error
	)

	require.Eventually(t, func() bool {
		spendable, _, err := client.ListVtxos(ctx)
		if err != nil {
			lastErr = err
			return false
		}

		for _, v := range spendable {
			if v.Asset == nil {
				continue
			}
			if matcher == nil || matcher(v) {
				found = v
				return true
			}
		}

		return false
	}, 30*time.Second, 500*time.Millisecond)

	require.NoError(t, lastErr)
	return found
}

func assetAmountForVout(v types.Vtxo) (uint64, bool) {
	if v.Asset == nil {
		return 0, false
	}

	for _, out := range v.Asset.Outputs {
		if out.Vout == v.VOut {
			return out.Amount, true
		}
	}

	return 0, false
}
