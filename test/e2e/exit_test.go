package e2e

import (
	"errors"
	"testing"
	"time"

	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestCollaborativeExit(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		// In this test Alice sends to Bob's onchain address by producing a (VTXO) change
		t.Run("with change", func(t *testing.T) {
			ctx := t.Context()
			alice := setupClient(t)
			bob := setupClient(t)

			// Faucet Alice
			faucetOffchain(t, alice, 0.001)

			aliceBalance, err := alice.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, aliceBalance)
			require.Greater(t, int(aliceBalance.OffchainBalance.Total), 0)

			bobBalance, err := bob.Balance(ctx)
			require.NoError(t, err)
			require.NotNil(t, bobBalance)
			require.Zero(t, int(bobBalance.OffchainBalance.Total))
			require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

			bobOnchainAddr, _, _, err := bob.Receive(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			bobUtxoCh := bob.GetUtxoEventChannel(ctx)

			// Send to Bob's onchain address
			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.NoError(t, err)

			// next event received by bob utxo channel should be the added event
			// related to the collaborative exit
			bobUtxoEvent := <-bobUtxoCh
			require.Equal(t, bobUtxoEvent.Type, types.UtxosAdded)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, 21000, int(bobUtxo.Amount))
			require.False(t, bobUtxo.IsConfirmed())

			// generate block to confirm the commitment transaction
			require.NoError(t, generateBlocks(1))

			// next event received by bob utxo channel should be the confirmed event
			// related to the commitment transaction
			bobUtxoEvent = <-bobUtxoCh
			require.Equal(t, bobUtxoEvent.Type, types.UtxosConfirmed)
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
			alice := setupClient(t)
			bob := setupClient(t)

			// Faucet Alice
			faucetOffchain(t, alice, 0.00021)

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

			bobOnchainAddr, _, _, err := bob.Receive(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, bobOnchainAddr)

			bobUtxoCh := bob.GetUtxoEventChannel(ctx)

			// Send all to Bob's onchain address
			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.NoError(t, err)

			// next event received by bob utxo channel should be the added event
			// related to the collaborative exit
			bobUtxoEvent := <-bobUtxoCh
			require.Equal(t, bobUtxoEvent.Type, types.UtxosAdded)
			require.Len(t, bobUtxoEvent.Utxos, 1)
			bobUtxo := bobUtxoEvent.Utxos[0]
			require.Equal(t, 21000, int(bobUtxo.Amount))
			require.False(t, bobUtxo.IsConfirmed())

			// generate block to confirm the commitment transaction
			require.NoError(t, generateBlocks(1))

			// next event received by bob utxo channel should be the confirmed event
			// related to the commitment transaction
			bobUtxoEvent = <-bobUtxoCh
			require.Equal(t, bobUtxoEvent.Type, types.UtxosConfirmed)
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
			alice := setupClient(t)
			bob := setupClient(t)

			_, _, aliceBoardingAddr, err := alice.Receive(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceBoardingAddr)

			bobOnchainAddr, _, _, err := bob.Receive(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, aliceBoardingAddr)

			faucetOffchain(t, alice, 0.00021)
			faucetOnchain(t, aliceBoardingAddr, 0.001)
			time.Sleep(5 * time.Second)

			_, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 21000)
			require.Error(t, err)

			require.ErrorContains(t, err, "include onchain inputs and outputs")
		})
	})
}

func TestUnilateralExit(t *testing.T) {
	t.Parallel()

	// In this test Alice owns a leaf VTXO and unrolls it onchain
	t.Run("leaf vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)

		vtxoToUnroll := faucetOffchain(t, alice, 0.00021)

		aliceOnchainAddr, _, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, aliceOnchainAddr)

		aliceUtxoCh := alice.GetUtxoEventChannel(ctx)

		// Faucet onchain addr to cover network fees for the unroll.
		faucetOnchain(t, aliceOnchainAddr, 0.0001)

		// next event received by alice utxo channel should be the added event
		// related to the faucet
		aliceUtxoEvent := <-aliceUtxoCh
		require.Equal(t, aliceUtxoEvent.Type, types.UtxosAdded)
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

			if errors.Is(err, arksdk.ErrWaitingForConfirmation) {
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
	})

	// In this test Bob receives from Alice a VTXO offchain and unrolls it onchain
	t.Run("preconfirmed vtxo", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)

		faucetOffchain(t, alice, 0.001)

		bob := setupClient(t)
		bobOnchainAddr, bobOffchainAddr, _, err := bob.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, bobOnchainAddr)
		require.NotEmpty(t, bobOffchainAddr)

		bobBalance, err := bob.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, bobBalance.OffchainBalance.Total)
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)

		bobVtxoCh := bob.GetVtxoEventChannel(ctx)
		// Alice sends to Bob
		_, err = alice.SendOffChain(ctx, false, []types.Receiver{{
			To:     bobOffchainAddr,
			Amount: 21000,
		}})
		require.NoError(t, err)

		// next event received by bob vtxo channel should be the added event
		// related to the offchain send
		bobVtxoEvent := <-bobVtxoCh
		require.Equal(t, bobVtxoEvent.Type, types.VtxosAdded)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		vtxoToUnroll := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 21000, int(vtxoToUnroll.Amount))

		bobUtxoCh := bob.GetUtxoEventChannel(ctx)

		// Fund Bob's onchain wallet to cover network fees for the unroll
		faucetOnchain(t, bobOnchainAddr, 0.0001)

		// next event received by bob utxo channel should be the added event
		// related to the faucet
		bobUtxoEvent := <-bobUtxoCh
		require.Equal(t, bobUtxoEvent.Type, types.UtxosAdded)
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

			if errors.Is(err, arksdk.ErrWaitingForConfirmation) {
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
	})
}
