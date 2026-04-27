package e2e

import (
	"errors"
	"testing"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

const onchainFee = 400

func TestCollaborativeExit(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		// In this test Alice sends to Bob's onchain address by producing a (VTXO) change
		t.Run("with change", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t, "")
			bob := setupClient(t, "")

			// Faucet Alice
			aliceFaucetAddr, err := alice.NewOffchainAddress(ctx)
			require.NoError(t, err)
			faucetOffchain(t, alice, aliceFaucetAddr, 0.001)

			aliceBalance, err := alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)

			bobBalance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			bobUtxoCh := bob.GetUtxoEventChannel(ctx)

			// Send to Bob's onchain address
			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.NoError(t, err)

			// next event received by bob utxo channel should be the added event
			// related to the collaborative exit
			bobUtxoEvent := <-bobUtxoCh
			require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, 21000, int(bobUtxo.Amount))
			require.False(t, bobUtxo.IsConfirmed())

			// generate block to confirm the commitment transaction
			require.NoError(t, generateBlocks(1))

			// next event received by bob utxo channel should be the confirmed event
			// related to the commitment transaction
			bobUtxoEvent = <-bobUtxoCh
			require.Equal(t, types.UtxosConfirmed, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobConfirmedUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, bobUtxo.Outpoint, bobConfirmedUtxo.Outpoint)
			require.Equal(t, 21000, int(bobConfirmedUtxo.Amount))
			require.True(t, bobConfirmedUtxo.IsConfirmed())

			prevTotalBalance := int(aliceBalance.OffchainBalance.Total)
			aliceBalance, err = alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Less(t, int(aliceBalance.OffchainBalance.Total), prevTotalBalance)

			bobBalance, err = bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)
			require.Equal(t, 21000, int(bobBalance.OnchainBalance.SpendableAmount))
		})

		// In this test Alice sends all to Bob'c onchain address without (VTXO) change
		t.Run("without change", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t, "")
			bob := setupClient(t, "")

			// Faucet Alice
			aliceFaucetAddr, err := alice.NewOffchainAddress(ctx)
			require.NoError(t, err)
			faucetOffchain(t, alice, aliceFaucetAddr, 0.00021)

			aliceBalance, err := alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			bobUtxoCh := bob.GetUtxoEventChannel(ctx)

			// Send all to Bob's onchain address
			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.NoError(t, err)

			// next event received by bob utxo channel should be the added event
			// related to the collaborative exit
			bobUtxoEvent := <-bobUtxoCh
			require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, 21000, int(bobUtxo.Amount))
			require.False(t, bobUtxo.IsConfirmed())

			// generate block to confirm the commitment transaction
			require.NoError(t, generateBlocks(1))

			// next event received by bob utxo channel should be the confirmed event
			// related to the commitment transaction
			bobUtxoEvent = <-bobUtxoCh
			require.Equal(t, types.UtxosConfirmed, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobConfirmedUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, bobUtxo.Outpoint, bobConfirmedUtxo.Outpoint)
			require.Equal(t, 21000, int(bobConfirmedUtxo.Amount))
			require.True(t, bobConfirmedUtxo.IsConfirmed())

			aliceBalance, err = alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Zero(t, int(aliceBalance.OffchainBalance.Total))
			require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

			bobBalance, err = bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Equal(t, 21000, int(bobBalance.OnchainBalance.SpendableAmount))
		})
	})

	t.Run("invalid", func(t *testing.T) {
		// In this test Alice funds her boarding address without settling and tries to join a batch
		// funding Bob's onchain address. The server should reject the request
		t.Run("with boarding inputs", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t, "")
			bob := setupClient(t, "")

			aliceBoardingAddr, err := alice.NewBoardingAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceBoardingAddr)

			aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceOffchainAddr)

			bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			faucetOffchain(t, alice, aliceOffchainAddr, 0.00021)
			aliceUtxoCh := alice.GetUtxoEventChannel(ctx)
			faucetOnchain(t, aliceBoardingAddr, 0.001)

			// wait for Alice's boarding UTXO to be detected before calling CollaborativeExit
			aliceUtxoEvent := <-aliceUtxoCh
			require.Equal(t, types.UtxosAdded, aliceUtxoEvent.Type)

			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.Error(t, err)

			require.ErrorContains(t, err, "include onchain inputs and outputs")
		})
	})
}

func TestUnilateralExit(t *testing.T) {
	// In this test Alice owns a leaf VTXO and unrolls it onchain
	t.Run("leaf vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
		aliceUtxoCh := alice.GetUtxoEventChannel(ctx)

		aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		vtxoToUnroll := faucetOffchain(t, alice, aliceOffchainAddr, 0.00021)
		aliceVtxoEvent := <-aliceVtxoCh
		require.Equal(t, types.VtxosAdded, aliceVtxoEvent.Type)

		aliceOnchainAddr, err := alice.NewOnchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceOnchainAddr)

		// Faucet onchain addr to cover network fees for the unroll.
		faucetOnchain(t, aliceOnchainAddr, 0.0001)

		// next event received by alice utxo channel should be the added event
		// related to the faucet
		aliceUtxoEvent := <-aliceUtxoCh
		require.Equal(t, types.UtxosAdded, aliceUtxoEvent.Type)
		require.Len(t, aliceUtxoEvent.Utxos, 1)
		aliceUtxo := aliceUtxoEvent.Utxos[0]
		require.Equal(t, 10000, int(aliceUtxo.Amount))

		for {
			err = alice.Unroll(ctx)
			if err == nil {
				err = generateBlocks(1)
				require.NoError(t, err)
				time.Sleep(5 * time.Second)
				continue
			}

			if errors.Is(err, client.ErrWaitingForConfirmation) {
				require.NoError(t, generateBlocks(1))
				continue
			}

			require.ErrorContains(t, err, "no vtxos to unroll")
			break
		}

		_, spent, err := alice.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spent)
		require.Len(t, spent, 1)
		require.Equal(t, vtxoToUnroll.Outpoint, spent[0].Outpoint)
		require.True(t, spent[0].Unrolled)

		err = generateBlocks(10)
		require.NoError(t, err)

		time.Sleep(20 * time.Second)

		// Use a separate HD wallet to observe the onchain receive after CompleteUnroll.
		bob := setupClient(t, "")
		bobUtxoCh := bob.GetUtxoEventChannel(ctx)

		bobOnchainAddr, err := bob.NewBoardingAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOnchainAddr)

		txid, err := alice.CompleteUnroll(ctx, bobOnchainAddr)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		select {
		case bobUtxoEvent := <-bobUtxoCh:
			require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
			require.Len(t, bobUtxoEvent.Utxos, 1)

			bobUtxo := bobUtxoEvent.Utxos[0]
			require.Less(t, int(bobUtxo.Amount), 21000)
			require.GreaterOrEqual(t, int(bobUtxo.Amount), 21000-onchainFee)
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for UtxosAdded on onchain address")
		}
	})

	// In this test Bob receives from Alice a VTXO offchain and unrolls it onchain
	t.Run("preconfirmed vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t, "")

		aliceFaucetAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		faucetOffchain(t, alice, aliceFaucetAddr, 0.001)

		bob := setupClient(t, "")
		bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOnchainAddr)
		bobOffchainAddr, err := bob.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOffchainAddr)

		bobBalance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, bobBalance.OffchainBalance.Total)
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)
		_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobOffchainAddr,
			Amount: 21000,
		}})
		require.NoError(t, err)

		bobVtxoEvent := <-bobVtxoCh
		require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		vtxoToUnroll := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 21000, int(vtxoToUnroll.Amount))

		bobUtxoCh := bob.GetUtxoEventChannel(ctx)
		faucetOnchain(t, bobOnchainAddr, 0.0001)

		bobUtxoEvent := <-bobUtxoCh
		require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
		require.Len(t, bobUtxoEvent.Utxos, 1)
		bobUtxo := bobUtxoEvent.Utxos[0]
		require.Equal(t, 10000, int(bobUtxo.Amount))

		for {
			err = bob.Unroll(ctx)
			if err == nil {
				err = generateBlocks(1)
				require.NoError(t, err)
				time.Sleep(5 * time.Second)
				continue
			}

			if errors.Is(err, client.ErrWaitingForConfirmation) {
				require.NoError(t, generateBlocks(1))
				continue
			}

			require.ErrorContains(t, err, "no vtxos to unroll")
			break
		}

		_, spent, err := bob.ListVtxos(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, spent)
		require.Len(t, spent, 1)
		require.Equal(t, vtxoToUnroll.Outpoint, spent[0].Outpoint)
		require.True(t, spent[0].Unrolled)

		err = generateBlocks(10)
		require.NoError(t, err)

		time.Sleep(20 * time.Second)

		carol := setupClient(t, "")
		carolUtxoCh := carol.GetUtxoEventChannel(ctx)

		carolOnchainAddr, err := carol.NewBoardingAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, carolOnchainAddr)

		txid, err := bob.CompleteUnroll(ctx, carolOnchainAddr)
		require.NoError(t, err)
		require.NotEmpty(t, txid)

		select {
		case carolUtxoEvent := <-carolUtxoCh:
			require.Equal(t, types.UtxosAdded, carolUtxoEvent.Type)
			require.Len(t, carolUtxoEvent.Utxos, 1)

			carolUtxo := carolUtxoEvent.Utxos[0]
			require.Less(t, int(carolUtxo.Amount), 21000)
			require.GreaterOrEqual(t, int(carolUtxo.Amount), 21000-onchainFee)
		case <-time.After(15 * time.Second):
			t.Fatal("timed out waiting for UtxosAdded on onchain address")
		}
	})
}
