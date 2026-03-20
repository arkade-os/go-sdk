package e2e

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
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

		aliceBoardingAddr, err := alice.NewBoardingAddress(ctx)
		require.NoError(t, err)
		bobBoardingAddr, err := bob.NewBoardingAddress(ctx)
		require.NoError(t, err)

		aliceUtxoCh := alice.GetUtxoEventChannel(ctx)
		bobUtxoCh := bob.GetUtxoEventChannel(ctx)

		// Faucet Alice and Bob boarding addresses
		faucetOnchain(t, aliceBoardingAddr, 0.00021)
		faucetOnchain(t, bobBoardingAddr, 0.00021)

		// next event received by bob and alice utxo channel should be the added events related to boarding inputs
		bobUtxoEvent := <-bobUtxoCh
		aliceUtxoEvent := <-aliceUtxoCh
		require.Equal(t, types.UtxosAdded, bobUtxoEvent.Type)
		require.Equal(t, types.UtxosAdded, aliceUtxoEvent.Type)
		require.Len(t, bobUtxoEvent.Utxos, 1)
		require.Len(t, aliceUtxoEvent.Utxos, 1)
		aliceConfirmedUtxo := aliceUtxoEvent.Utxos[0]
		bobConfirmedUtxo := bobUtxoEvent.Utxos[0]
		require.Equal(t, 21000, int(aliceConfirmedUtxo.Amount))
		require.Equal(t, 21000, int(bobConfirmedUtxo.Amount))

		aliceBalance, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.Zero(t, int(aliceBalance.OffchainBalance.Total))
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, aliceBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(aliceBalance.OnchainBalance.LockedAmount[0].Amount))

		bobBalance, err := bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.Zero(t, int(bobBalance.OffchainBalance.Total))
		require.Empty(t, int(bobBalance.OnchainBalance.SpendableAmount))
		require.NotEmpty(t, bobBalance.OnchainBalance.LockedAmount)
		require.NotZero(t, int(bobBalance.OnchainBalance.LockedAmount[0].Amount))

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)
		bobVtxoCh := bob.GetVtxoEventChannel(ctx)

		// first alice and bob join the same batch to complete their onboarding
		wg := &sync.WaitGroup{}
		wg.Add(2)
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

		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		// next event received by alice and bob vtxo channel should be the added events
		// related to new vtxos created by the batch
		aliceVtxoEvent := <-aliceVtxoCh
		bobVtxoEvent := <-bobVtxoCh
		require.Equal(t, types.VtxosAdded, aliceVtxoEvent.Type)
		require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
		require.Len(t, aliceVtxoEvent.Vtxos, 1)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		aliceVtxo := aliceVtxoEvent.Vtxos[0]
		bobVtxo := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 21000, int(aliceVtxo.Amount))
		require.Equal(t, 21000, int(bobVtxo.Amount))

		aliceBalance, err = alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.GreaterOrEqual(t, int(aliceBalance.OffchainBalance.Total), 21000)

		bobBalance, err = bob.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, bobBalance)
		require.GreaterOrEqual(t, int(bobBalance.OffchainBalance.Total), 21000)

		// next event received by bob and alice utxo channel should be the spent events
		// related to boarding inputs
		bobUtxoEvent = <-bobUtxoCh
		aliceUtxoEvent = <-aliceUtxoCh
		require.Equal(t, types.UtxosSpent, bobUtxoEvent.Type)
		require.Equal(t, types.UtxosSpent, aliceUtxoEvent.Type)
		require.Len(t, bobUtxoEvent.Utxos, 1)
		require.Len(t, aliceUtxoEvent.Utxos, 1)
		require.Equal(t, bobUtxoEvent.Utxos[0].Outpoint, bobConfirmedUtxo.Outpoint)
		require.Equal(t, aliceUtxoEvent.Utxos[0].Outpoint, aliceConfirmedUtxo.Outpoint)

		// Alice and Bob refresh their VTXOs by joining another batch together
		wg.Add(2)
		go func() {
			aliceCommitmentTx, aliceBatchErr = alice.Settle(ctx)
			wg.Done()
		}()
		go func() {
			bobCommitmentTx, bobBatchErr = bob.Settle(ctx)
			wg.Done()
		}()
		wg.Wait()

		require.NoError(t, aliceBatchErr)
		require.NoError(t, bobBatchErr)
		require.NotEmpty(t, aliceCommitmentTx)
		require.NotEmpty(t, bobCommitmentTx)
		require.Equal(t, aliceCommitmentTx, bobCommitmentTx)

		// the event channel should he notified about the new vtxos
		aliceVtxoEvent = <-aliceVtxoCh
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, types.VtxosAdded, aliceVtxoEvent.Type)
		require.Equal(t, types.VtxosAdded, bobVtxoEvent.Type)
		require.Len(t, aliceVtxoEvent.Vtxos, 1)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		aliceRefreshVtxo := aliceVtxoEvent.Vtxos[0]
		bobRefreshVtxo := bobVtxoEvent.Vtxos[0]
		require.Equal(t, 21000, int(aliceRefreshVtxo.Amount))
		require.Equal(t, 21000, int(bobRefreshVtxo.Amount))

		// the event channel should he notified about the spent vtxos
		aliceVtxoEvent = <-aliceVtxoCh
		bobVtxoEvent = <-bobVtxoCh
		require.Equal(t, types.VtxosSpent, aliceVtxoEvent.Type)
		require.Equal(t, types.VtxosSpent, bobVtxoEvent.Type)
		require.Len(t, aliceVtxoEvent.Vtxos, 1)
		require.Len(t, bobVtxoEvent.Vtxos, 1)
		require.Equal(t, aliceVtxoEvent.Vtxos[0].Outpoint, aliceVtxo.Outpoint)
		require.Equal(t, bobVtxoEvent.Vtxos[0].Outpoint, bobVtxo.Outpoint)

		aliceBalance, err = alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, aliceBalance)
		require.GreaterOrEqual(t, int(aliceBalance.OffchainBalance.Total), 21000)
		require.Zero(t, int(aliceBalance.OnchainBalance.SpendableAmount))
		require.Empty(t, aliceBalance.OnchainBalance.LockedAmount)

		bobBalance, err = bob.Balance(ctx)
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
		offchainAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		balance, err := alice.Balance(ctx)
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.Zero(t, balance.OffchainBalance.Total)
		require.Empty(t, balance.OnchainBalance.LockedAmount)
		require.Zero(t, int(balance.OnchainBalance.SpendableAmount))

		note1 := generateNote(t, 21000)
		note2 := generateNote(t, 2100)

		aliceVtxoCh := alice.GetVtxoEventChannel(ctx)

		commitmentTx, err := alice.RedeemNotes(ctx, []string{note1, note2})
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTx)

		// next event received by alice vtxo channel should be the added event
		// related to new vtxo created by the redemption
		aliceVtxoEvent := <-aliceVtxoCh
		require.Equal(t, types.VtxosAdded, aliceVtxoEvent.Type)
		require.Len(t, aliceVtxoEvent.Vtxos, 1)
		aliceVtxo := aliceVtxoEvent.Vtxos[0]
		require.Equal(t, 21000+2100, int(aliceVtxo.Amount))

		balance, err = alice.Balance(ctx)
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

		time.Sleep(5 * time.Second)
	})

	// In this test Alice onboards some onchain and joins a batch to complete the boarding plus
	// renews a vtxo and a recoverable (expired) vtxo
	t.Run("onboard and renew expired funds", func(t *testing.T) {
		ctx := t.Context()
		alice := setupClient(t)

		boardingAddr, err := alice.NewBoardingAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, boardingAddr)

		offchainAddr, err := alice.NewOffchainAddress(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, offchainAddr)

		// Send alice offchain funds
		vtxoCh := alice.GetVtxoEventChannel(ctx)
		faucetOffchain(t, alice, 0.00005)

		vtxoEvent := <-vtxoCh
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 1)
		require.Equal(t, 5000, int(vtxoEvent.Vtxos[0].Amount))

		decoded, err := arklib.DecodeAddressV0(offchainAddr)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		outScript, err := script.P2TRScript(decoded.VtxoTapKey)
		require.NoError(t, err)
		require.NotEmpty(t, outScript)

		opts := indexer.WithScripts([]string{hex.EncodeToString(outScript)})
		res, err := alice.Indexer().GetVtxos(t.Context(), opts)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Len(t, res.Vtxos, 1)
		require.False(t, res.Vtxos[0].Swept)

		// Make the offchain funds expire
		err = generateBlocks(21)
		require.NoError(t, err)

		// Give the time to the server to sweep the funds
		time.Sleep(10 * time.Second)

		res, err = alice.Indexer().GetVtxos(t.Context(), opts)
		require.NoError(t, err)
		require.NotNil(t, res)
		require.Len(t, res.Vtxos, 1)
		require.True(t, res.Vtxos[0].Swept)

		// Repeat the operation to have many funds that are going to be swept and renewed
		faucetOffchain(t, alice, 0.00003)

		vtxoEvent = <-vtxoCh
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 1)
		require.Equal(t, 3000, int(vtxoEvent.Vtxos[0].Amount))

		utxoCh := alice.GetUtxoEventChannel(ctx)

		faucetOnchain(t, boardingAddr, 0.00021)

		utxoEvent := <-utxoCh
		require.Equal(t, types.UtxosAdded, utxoEvent.Type)
		require.Len(t, utxoEvent.Utxos, 1)
		require.Equal(t, 21000, int(utxoEvent.Utxos[0].Amount))

		// first alice and bob join the same batch to complete their onboarding
		wg := &sync.WaitGroup{}
		var batchTx string
		var batchErr error
		wg.Go(func() {
			batchTx, batchErr = alice.Settle(ctx)
		})
		wg.Wait()
		require.NoError(t, batchErr)
		require.NotEmpty(t, batchTx)

		// next event received by alice and bob vtxo channel should be the added events
		// related to new vtxos created by the batch
		vtxoEvent = <-vtxoCh
		require.Equal(t, types.VtxosAdded, vtxoEvent.Type)
		require.Len(t, vtxoEvent.Vtxos, 1)
		vtxo := vtxoEvent.Vtxos[0]
		require.Equal(t, 29000, int(vtxo.Amount))

		balance, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.NotNil(t, balance)
		require.GreaterOrEqual(t, int(balance.OffchainBalance.Total), 29000)
	})
}
