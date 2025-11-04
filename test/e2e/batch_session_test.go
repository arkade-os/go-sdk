package e2e

import (
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestBatchSession(t *testing.T) {
	// In this test Alice and Bob onboard their funds in the same commitment tx and then
	// refresh their vtxos together in another commitment tx
	t.Run("refresh vtxos", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		bob := setupClient(t)

		_, _, aliceBoardingAddr, err := alice.Receive(ctx)
		require.NoError(t, err)
		_, _, bobBoardingAddr, err := bob.Receive(ctx)
		require.NoError(t, err)

		aliceUtxoCh := alice.GetUtxoEventChannel(ctx)
		bobUtxoCh := bob.GetUtxoEventChannel(ctx)

		receiveWg := &sync.WaitGroup{}
		receiveWg.Add(2)

		var aliceConfirmedUtxo, bobConfirmedUtxo types.Utxo
		go func() {
			defer receiveWg.Done()
			event := <-aliceUtxoCh
			aliceConfirmedUtxo = event.Utxos[0]
		}()

		go func() {
			defer receiveWg.Done()
			event := <-bobUtxoCh
			bobConfirmedUtxo = event.Utxos[0]
		}()

		// Faucet Alice and Bob boarding addresses
		faucetOnchain(t, aliceBoardingAddr, 0.00021)
		faucetOnchain(t, bobBoardingAddr, 0.00021)

		receiveWg.Wait()

		require.Equal(t, 21000, int(aliceConfirmedUtxo.Amount))
		require.Equal(t, 21000, int(bobConfirmedUtxo.Amount))

		aliceBalance, err := alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.Zero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, aliceBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(aliceBalance.OnchainBalance.LockedAmount[0].Amount))

		bobBalance, err := bob.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, int(bobBalance.OffchainBalance.Total))
		require.Empty(t, int(bobBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, bobBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(bobBalance.OnchainBalance.LockedAmount[0].Amount))

		// first alice and bob join the same batch to complete their onboarding

		wg := &sync.WaitGroup{}
		wg.Add(4)

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		var aliceVtxo, bobVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range aliceVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				aliceVtxo = event.Vtxos[0]
				break
			}
		}()
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobVtxo = event.Vtxos[0]
				break
			}
		}()

		var aliceCommitmentTx, bobCommitmentTx string
		var aliceBatchErr, bobBatchErr error
		go func() {
			aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
			wg.Done()
		}()
		go func() {
			bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
			wg.Done()
		}()

		wg.Wait()

		require.Equal(t, 21000, int(aliceVtxo.Amount))
		require.Equal(t, 21000, int(bobVtxo.Amount))
		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		aliceBalance, err = alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.GreaterOrEqual(t, int(aliceBalance.OffchainBalance.Total), 21000)

		bobBalance, err = bob.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.GreaterOrEqual(t, int(bobBalance.OffchainBalance.Total), 21000)

		time.Sleep(2 * time.Second)

		// Alice and Bob refresh their VTXOs by joining another batch together
		wg.Add(4)

		var aliceRefreshVtxo, bobRefreshVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range aliceVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				aliceRefreshVtxo = event.Vtxos[0]
				break
			}
		}()
		go func() {
			defer wg.Done()
			for event := range bobVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				bobRefreshVtxo = event.Vtxos[0]
				break
			}
		}()

		go func() {
			aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
			wg.Done()
		}()
		go func() {
			bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
			wg.Done()
		}()

		wg.Wait()

		require.Equal(t, 21000, int(aliceRefreshVtxo.Amount))
		require.Equal(t, 21000, int(bobRefreshVtxo.Amount))
		require.NotEqual(t, aliceVtxo.Outpoint, aliceRefreshVtxo.Outpoint)
		require.NotEqual(t, bobVtxo.Outpoint, bobRefreshVtxo.Outpoint)
		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		aliceBalance, err = alice.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.GreaterOrEqual(t, int(aliceBalance.OffchainBalance.Total), 21000)
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

		bobBalance, err = bob.Balance(t.Context(), false)
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.GreaterOrEqual(t, int(bobBalance.OffchainBalance.Total), 21000)
		require.Zero(t, int(bobBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, bobBalance.OnchainBalance.LockedAmount)
	})

	// In this test Alice redeems 2 notes and then tries to redeem them again to ensure
	// they can be redeeemed only once
	t.Run("redeem notes", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)
		_, offchainAddr, _, err := alice.Receive(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		balance, err := alice.Balance(ctx, false)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		note1 := generateNote(t, 21000)
		note2 := generateNote(t, 2100)

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)

		wg := &sync.WaitGroup{}
		wg.Add(1)
		var aliceVtxo types.Vtxo
		go func() {
			defer wg.Done()
			for event := range aliceVtxoCh {
				if len(event.Vtxos) == 0 || event.Type != types.VtxosAdded {
					continue
				}
				aliceVtxo = event.Vtxos[0]
				break
			}
		}()

		commitmentTx, err := alice.RedeemNotes(ctx, []string{note1, note2})
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTx)

		wg.Wait()
		require.Equal(t, 21000+2100, int(aliceVtxo.Amount))

		balance, err = alice.Balance(ctx, false)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Greater(t, int(balance.OffchainBalance.Total), 21000)
		require.Empty(t, balance.OnchainBalance.LockedAmount)
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		_, err = alice.RedeemNotes(ctx, []string{note1})
		require.Error(t, err)
		_, err = alice.RedeemNotes(ctx, []string{note2})
		require.Error(t, err)
		_, err = alice.RedeemNotes(ctx, []string{note1, note2})
		require.Error(t, err)
	})
}
