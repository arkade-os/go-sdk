package e2e

import (
	"context"
	"encoding/hex"
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

	_, err := issuer.CreateAsset(ctx, createParams)
	require.NoError(t, err)

	issuerAssetVtxo := waitForAssetVtxo(t, ctx, issuer, nil)
	issuerAssetAmount, ok := assetAmountForVout(issuerAssetVtxo)
	require.True(t, ok)
	require.EqualValues(t, supply, issuerAssetAmount)

	assetID := issuerAssetVtxo.Asset.AssetId

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferAmount uint64 = 1_200
	_, err = issuer.SendAsset(ctx, assetID, []types.Receiver{{
		To:     receiverOffchainAddr,
		Amount: transferAmount,
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
	assetHex := hex.EncodeToString(assetID[:])
	assetBalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetHex]
	require.True(t, ok)
	require.GreaterOrEqual(t, int(assetBalance.TotalAmount), int(transferAmount))
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
