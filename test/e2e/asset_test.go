package e2e

import (
	"sync"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

// TestAssetTransfer tests the transfer of an asset between alice and bob.
// then they both settle their funds.
func TestAssetTransferAndRenew(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()
		const supply = 5_000
		const transferAmount = 1_200

		alice := setupClient(t)
		bob := setupClient(t)
		aliceTxStream := alice.GetTransactionEventChannel(ctx)
		bobTxStream := bob.GetTransactionEventChannel(ctx)

		wg := &sync.WaitGroup{}
		wg.Go(func() {
			faucetOffchain(t, alice, 0.002)
		})
		wg.Go(func() {
			faucetOffchain(t, bob, 0.001)
		})
		wg.Wait()

		// wait for alice and bob to receive the faucet tx
		<-aliceTxStream
		<-bobTxStream

		txid, assetIds, err := alice.IssueAsset(ctx, supply, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)

		assetId := assetIds[0].String()

		txEvent := <-aliceTxStream
		require.Equal(t, types.TxsAdded, txEvent.Type)
		require.Len(t, txEvent.Txs, 1)
		tx := txEvent.Txs[0]
		require.Equal(t, txid, tx.TransactionKey.String())

		time.Sleep(time.Second)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		require.Equal(t, supply, int(assetVtxos[0].Assets[0].Amount))
		require.Equal(t, assetId, assetVtxos[0].Assets[0].AssetId)
		require.Equal(t, txid, assetVtxos[0].Txid)

		bobAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobAddr)

		_, err = alice.SendOffChain(
			ctx, []clientTypes.Receiver{
				{To: bobAddr, Amount: 400, Assets: []clientTypes.Asset{
					{AssetId: assetId, Amount: transferAmount},
				}},
			},
		)
		require.NoError(t, err)

		// bob and alice should get notified about the offchain send
		<-aliceTxStream
		<-bobTxStream

		time.Sleep(2 * time.Second) // wait for bob to index the vtxo

		receiverAssetVtxos := listVtxosWithAsset(t, bob, assetId)
		require.Len(t, receiverAssetVtxos, 1)
		require.Len(t, receiverAssetVtxos[0].Assets, 1)
		require.Equal(t, transferAmount, int(receiverAssetVtxos[0].Assets[0].Amount))
		require.Equal(t, assetId, receiverAssetVtxos[0].Assets[0].AssetId)

		bobBalance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.NotNil(t, bobBalance.AssetBalances)

		assetBalance, ok := bobBalance.AssetBalances[assetId]
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

		aliceTxEvent := <-aliceTxStream
		require.Equal(t, types.TxsSettled, aliceTxEvent.Type)

		bobTxEvent := <-bobTxStream
		require.Equal(t, types.TxsSettled, bobTxEvent.Type)

		bobBalanceAfterSettle, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalanceAfterSettle)
		require.NotNil(t, bobBalanceAfterSettle.AssetBalances)

		assetBalanceAfterSettle, ok := bobBalanceAfterSettle.AssetBalances[assetId]
		require.True(t, ok)
		require.Equal(t, int(assetBalance), int(assetBalanceAfterSettle))
	})
}

func TestProveDustAmountAddedByDefault(t *testing.T) {
	setupClient := setupClientWithDatadir
	ctx := t.Context()

	alice := setupClient(t, "")
	bob := setupClient(t, "")

	faucetOffchain(t, alice, 0.002)

	_, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
	require.NoError(t, err)
	require.Len(t, assetIds, 1)

	assetId := assetIds[0].String()

	bobAddr, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddr)

	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{
		{
			To: bobAddr,
			Assets: []clientTypes.Asset{
				{AssetId: assetId, Amount: 1},
			},
		},
	})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	balance, err := bob.Balance(ctx)
	require.NoError(t, err)
	require.NotNil(t, balance)

	cfg, err := bob.GetConfigData(ctx)
	require.NoError(t, err)
	require.Equal(t, int(cfg.Dust), int(balance.OffchainBalance.Total))
}

func TestAssetIssuance(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		t.Run("without control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			faucetOffchain(t, alice, 0.01)

			vtxoStream := alice.GetVtxoEventChannel(ctx)

			txid, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
			require.NoError(t, err)
			require.Len(t, assetIds, 1)

			// should spent vtxo
			vtxoEvent := <-vtxoStream
			require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
			require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
			vtxo := findVtxoWithTxid(vtxoEvent.Vtxos, txid, 0)
			require.NotNil(t, vtxo)
			require.Len(t, vtxo.Assets, 1)
			require.Equal(t, assetIds[0].String(), vtxo.Assets[0].AssetId)
			require.Equal(t, 1, int(vtxo.Assets[0].Amount))

			// should add vtxo with the new asset
			vtxoEvent = <-vtxoStream
			require.Equal(t, types.VtxosSpent, vtxoEvent.Type)
		})

		t.Run("with new control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			faucetOffchain(t, alice, 0.01)

			vtxoStream := alice.GetVtxoEventChannel(ctx)

			txid, assetIds, err := alice.IssueAsset(
				ctx,
				1,
				clientTypes.NewControlAsset{Amount: 1},
				nil,
			)
			require.NoError(t, err)
			require.Len(t, assetIds, 2)

			controlAssetId := assetIds[0].String()
			assetId := assetIds[1].String()
			require.NotEqual(t, controlAssetId, assetId)

			// should spent vtxo
			vtxoEvent := <-vtxoStream
			require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
			require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
			vtxo := findVtxoWithTxid(vtxoEvent.Vtxos, txid, 0)
			require.NotNil(t, vtxo)
			require.Len(t, vtxo.Assets, 2) // both control asset and the issued asset

			// should add vtxo with the new assets
			vtxoEvent = <-vtxoStream
			require.Equal(t, types.VtxosSpent, vtxoEvent.Type)
		})

		t.Run("with existing control asset", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			faucetOffchain(t, alice, 0.01)

			vtxoStream := alice.GetVtxoEventChannel(ctx)

			// issue control asset
			txid1, assetIds, err := alice.IssueAsset(ctx, 1, nil, nil)
			require.NoError(t, err)
			require.Len(t, assetIds, 1)
			controlAssetId := assetIds[0].String()

			// should spent vtxo
			vtxoEvent := <-vtxoStream
			require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
			require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
			vtxo := findVtxoWithTxid(vtxoEvent.Vtxos, txid1, 0)
			require.NotNil(t, vtxo)
			require.Len(t, vtxo.Assets, 1)
			require.Equal(t, controlAssetId, vtxo.Assets[0].AssetId)

			// should add vtxo with the control asset
			vtxoEvent = <-vtxoStream
			require.Equal(t, types.VtxosSpent, vtxoEvent.Type)

			// issue another asset	 with existing control asset
			txid2, assetIds2, err := alice.IssueAsset(
				ctx,
				1,
				clientTypes.ExistingControlAsset{ID: controlAssetId},
				nil,
			)
			require.NoError(t, err)
			require.Len(t, assetIds2, 1)

			require.NotEqual(t, assetIds[0].String(), assetIds2[0].String())

			// should spent vtxo (with control asset)
			vtxoEvent = <-vtxoStream
			require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
			require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
			vtxo = findVtxoWithTxid(vtxoEvent.Vtxos, txid2, 0)
			require.NotNil(t, vtxo)
			require.Len(t, vtxo.Assets, 2) // both control asset and the new issued asset

			// should add vtxo with the new asset and control asset
			vtxoEvent = <-vtxoStream
			require.Equal(t, types.VtxosSpent, vtxoEvent.Type)
		})
	})
}

// TestAssetReissuance makes issue an asset with a control asset and then reissue it.
func TestAssetReissuance(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()

		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		vtxoStream := alice.GetVtxoEventChannel(ctx)

		// issue an asset with a control asset
		txid1, assetIds, err := alice.IssueAsset(
			ctx,
			1,
			clientTypes.NewControlAsset{Amount: 1},
			nil,
		)
		require.NoError(t, err)
		require.Len(t, assetIds, 2)

		controlAssetId := assetIds[0].String()
		assetId := assetIds[1].String()
		require.NotEqual(t, controlAssetId, assetId)

		// should spent vtxo
		vtxoEvent := <-vtxoStream
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
		vtxo := findVtxoWithTxid(vtxoEvent.Vtxos, txid1, 0)
		require.NotNil(t, vtxo)
		require.Len(t, vtxo.Assets, 2) // both control asset and the issued asset

		// should add vtxo with the new assets
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosSpent, vtxoEvent.Type)

		controlVtxos := listVtxosWithAsset(t, alice, controlAssetId)
		require.Len(t, controlVtxos, 1)
		require.Len(
			t,
			controlVtxos[0].Assets,
			2,
		) // should hold both the control asset and the issued asset
		require.Equal(t, controlAssetId, controlVtxos[0].Assets[0].AssetId)
		require.Equal(t, 1, int(controlVtxos[0].Assets[0].Amount))
		require.Equal(t, assetId, controlVtxos[0].Assets[1].AssetId)
		require.Equal(t, 1, int(controlVtxos[0].Assets[1].Amount))

		time.Sleep(2 * time.Second) // wait for the vtxo to be indexed

		txid2, err := alice.ReissueAsset(ctx, assetId, 1000)
		require.NoError(t, err)

		// should spent vtxo (with control asset and the asset)
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
		vtxo = findVtxoWithTxid(vtxoEvent.Vtxos, txid2, 0)
		require.NotNil(t, vtxo)
		require.Len(t, vtxo.Assets, 2) // both control asset and the reissued asset

		// should add vtxo with reissued asset
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosSpent, vtxoEvent.Type)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 2)
	})
}

func TestAssetBurn(t *testing.T) {
	runForEachStoreBackend(t, func(t *testing.T, backend testStoreBackend) {
		setupClient := backend.setupClient

		ctx := t.Context()

		alice := setupClient(t)
		faucetOffchain(t, alice, 0.01)

		vtxoStream := alice.GetVtxoEventChannel(ctx)

		txid1, assetIds, err := alice.IssueAsset(ctx, 5000, nil, nil)
		require.NoError(t, err)
		require.Len(t, assetIds, 1)
		assetId := assetIds[0].String()

		// should spent vtxo
		vtxoEvent := <-vtxoStream
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 2) // 2 because of the change
		vtxo := findVtxoWithTxid(vtxoEvent.Vtxos, txid1, 0)
		require.NotNil(t, vtxo)
		require.Len(t, vtxo.Assets, 1)
		require.Equal(t, assetId, vtxo.Assets[0].AssetId)
		require.Equal(t, 5000, int(vtxo.Assets[0].Amount))

		// should add vtxo with the new asset
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosSpent, vtxoEvent.Type)

		assetVtxos := listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		require.Equal(t, 5000, int(assetVtxos[0].Assets[0].Amount))

		txid2, err := alice.BurnAsset(ctx, assetId, 1500)
		require.NoError(t, err)

		// should spent vtxo (with the asset)
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 2)
		vtxo = findVtxoWithTxid(vtxoEvent.Vtxos, txid2, 0)
		require.NotNil(t, vtxo)
		require.Len(t, vtxo.Assets, 1)
		require.Equal(t, assetId, vtxo.Assets[0].AssetId)
		require.Equal(t, 3500, int(vtxo.Assets[0].Amount))

		// should add vtxo with the burned asset
		vtxoEvent = <-vtxoStream
		require.Equal(t, types.VtxosSpent, vtxoEvent.Type)

		assetVtxos = listVtxosWithAsset(t, alice, assetId)
		require.Len(t, assetVtxos, 1)
		require.Len(t, assetVtxos[0].Assets, 1)
		require.Equal(t, 3500, int(assetVtxos[0].Assets[0].Amount))
	})
}

func listVtxosWithAsset(t *testing.T, client sdk.ArkClient, assetID string) []clientTypes.Vtxo {
	vtxos, _, err := client.ListVtxos(t.Context())
	require.NoError(t, err)

	assetVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))

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

func findVtxoWithTxid(vtxos []clientTypes.Vtxo, txid string, vout uint32) *clientTypes.Vtxo {
	for _, vtxo := range vtxos {
		if vtxo.Txid == txid && vtxo.VOut == vout {
			return &vtxo
		}
	}
	return nil
}
