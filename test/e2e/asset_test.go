package e2e

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
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
	_, assetIds, err := issuer.IssueAsset(
		ctx,
		supply,
		0,
		[]asset.Metadata{{Key: []byte("name"), Value: []byte("Test Asset")}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, assetIds)

	time.Sleep(5 * time.Second) // Wait for server indexer

	issuerAssetVtxo, err := getAssetVtxo(ctx, issuer, assetIds[0].String(), supply)
	require.NoError(t, err)

	require.NotEmpty(t, issuerAssetVtxo.Assets)
	require.EqualValues(t, supply, issuerAssetVtxo.Assets[0].Amount)

	_, receiverOffchainAddr, _, err := receiver.Receive(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, receiverOffchainAddr)

	const transferAmount uint64 = 1_200
	_, err = issuer.SendAsset(
		ctx,
		receiverOffchainAddr,
		transferAmount,
		assetIds[0].String(),
	)
	require.NoError(t, err)

	// Allow some time for the indexer to process the transfer
	time.Sleep(5 * time.Second)

	receiverAssetVtxo, err := getAssetVtxo(ctx, receiver, assetIds[0].String(), transferAmount)
	require.NoError(t, err)
	require.EqualValues(t, transferAmount, receiverAssetVtxo.Assets[0].Amount)

	receiverBalance, err := receiver.Balance(ctx)
	require.NoError(t, err)
	// Verify receiver balance
	assetBalance, ok := receiverBalance.OffchainBalance.AssetBalances[assetIds[0].String()]
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
	_, assetIds, err := issuer.IssueAsset(
		ctx,
		1,
		0,
		[]asset.Metadata{{Key: []byte("name"), Value: []byte("Control Token")}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, assetIds)

	time.Sleep(2 * time.Second)

	controlAssetId := assetIds[0]

	controlVtxo, err := getAssetVtxo(ctx, issuer, controlAssetId.String(), 0)
	require.NoError(t, err)

	require.Equal(t, uint64(1), controlVtxo.Assets[0].Amount)

	_, assetIds, err = issuer.IssueAsset(
		ctx,
		5000,
		1,
		[]asset.Metadata{{Key: []byte("name"), Value: []byte("Target Asset")}},
	)
	require.NoError(t, err)
	require.NotEmpty(t, assetIds)

	targetAssetId := assetIds[0]

	time.Sleep(2 * time.Second)

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId.String(), 0)
	require.NoError(t, err)

	require.Equal(t, uint64(5000), targetAssetVtxo.Assets[0].Amount)

	const mintAmount uint64 = 1000

	_, err = issuer.ReissueAsset(ctx, controlAssetId.String(), targetAssetId.String(), mintAmount)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	_, err = getAssetVtxo(ctx, issuer, targetAssetId.String(), mintAmount)
	require.NoError(t, err)
}

func TestAssetBurn(t *testing.T) {
	ctx := context.Background()

	issuer := setupClient(t)

	// Fund issuer
	faucetOffchain(t, issuer, 0.01)

	_, issueAssetIds, err := issuer.IssueAsset(ctx, 5000, 0, nil)
	require.NoError(t, err)
	require.Len(t, issueAssetIds, 1)
	targetAssetId := issueAssetIds[0].String()

	time.Sleep(2 * time.Second)

	targetAssetVtxo, err := getAssetVtxo(ctx, issuer, targetAssetId, 0)
	require.NoError(t, err)
	require.Equal(t, uint64(5000), targetAssetVtxo.Assets[0].Amount)

	_, err = issuer.BurnAsset(ctx, targetAssetId, 1500)
	require.NoError(t, err)
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
		for _, asset := range vtxo.Assets {
			if asset.AssetId == assetID {
				if amount == 0 || asset.Amount >= amount {
					return vtxo, nil
				}
			}
		}
	}

	return types.Vtxo{}, fmt.Errorf("no suitable vtxo found for asset %s", assetID)
}
