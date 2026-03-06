package e2e

import (
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestTransactionHistory(t *testing.T) {
	ctx := t.Context()
	alice := setupClient(t)

	history, err := alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Empty(t, history)

	aliceOffchainAddr, err := alice.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceOffchainAddr)

	aliceBoardingAddr, err := alice.NewBoardingAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, aliceBoardingAddr)

	aliceTxChan := alice.GetTransactionEventChannel(ctx)
	utxoCh := alice.GetUtxoEventChannel(ctx)

	// Alice sends fund to boarding address
	faucetOnchain(t, aliceBoardingAddr, 0.00021)

	// should receive the utxo added event
	utxoEvent := <-utxoCh
	require.Equal(t, types.UtxosAdded, utxoEvent.Type)
	require.Len(t, utxoEvent.Utxos, 1)
	require.Equal(t, 21000, int(utxoEvent.Utxos[0].Amount))

	// should receive the boarding tx event
	event := <-aliceTxChan
	require.Equal(t, types.TxsAdded, event.Type)
	require.Len(t, event.Txs, 1)
	boardingTx := event.Txs[0]
	require.Equal(t, clientTypes.TxReceived, boardingTx.Type)
	require.Equal(t, 21000, int(boardingTx.Amount))
	require.Empty(t, boardingTx.Hex)
	require.NotEmpty(t, boardingTx.BoardingTxid)
	require.Empty(t, boardingTx.CommitmentTxid)
	require.Empty(t, boardingTx.ArkTxid)
	require.Empty(t, boardingTx.SettledBy)

	// verify history contains the boarding tx
	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 1)
	requireTxEqual(t, boardingTx, history[0], "")

	// Alice completes the boarding in a commitment tx
	commitmentTxid, err := alice.Settle(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)

	// should receive the boarding settled tx event
	event = <-aliceTxChan
	require.Equal(t, types.TxsSettled, event.Type)
	require.Len(t, event.Txs, 1)
	settledBoardingTx := event.Txs[0]
	require.NotEmpty(t, settledBoardingTx.SettledBy)
	require.Equal(t, clientTypes.TxReceived, settledBoardingTx.Type)
	require.Equal(t, 21000, int(settledBoardingTx.Amount))
	require.NotEmpty(t, settledBoardingTx.BoardingTxid)
	require.Empty(t, settledBoardingTx.CommitmentTxid)
	require.Empty(t, settledBoardingTx.ArkTxid)
	require.Equal(t, boardingTx.BoardingTxid, settledBoardingTx.BoardingTxid)
	require.Equal(t, settledBoardingTx.SettledBy, commitmentTxid)

	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 1)
	requireTxEqual(t, settledBoardingTx, history[0], commitmentTxid)

	// wait for the utxo to be detected as spent and settle again
	utxoEvent = <-utxoCh
	require.Equal(t, types.UtxosSpent, utxoEvent.Type)
	require.Len(t, utxoEvent.Utxos, 1)
	require.Equal(t, 21000, int(utxoEvent.Utxos[0].Amount))
	require.True(t, utxoEvent.Utxos[0].Spent)

	// alice refresh its vtxo
	commitmentRefreshTxid, err := alice.Settle(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentRefreshTxid)

	// check history didn't change, we should not see commitment refresh tx in history
	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 1)
	requireTxEqual(t, settledBoardingTx, history[0], "")

	// alice sends funds to bob
	bob := setupClient(t)
	bobTxChan := bob.GetTransactionEventChannel(ctx)

	bobOnchainAddr, err := bob.NewOnchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobOnchainAddr)

	bobAddress, err := bob.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, bobAddress)

	arkTxid, err := alice.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     bobAddress,
		Amount: 10000,
	}})
	require.NoError(t, err)

	time.Sleep(10 * time.Second)

	// should receive the ark tx event
	event = <-aliceTxChan
	require.Equal(t, types.TxsAdded, event.Type)
	require.Len(t, event.Txs, 1)
	offchainTx := event.Txs[0]
	require.Equal(t, clientTypes.TxSent, offchainTx.Type)
	require.Equal(t, arkTxid, offchainTx.ArkTxid)
	require.Empty(t, offchainTx.BoardingTxid)
	require.Empty(t, offchainTx.CommitmentTxid)
	require.Equal(t, 10000, int(offchainTx.Amount))
	require.NotEmpty(t, offchainTx.Hex)

	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 2)
	requireTxEqual(t, offchainTx, history[0], "")
	requireTxEqual(t, settledBoardingTx, history[1], "")

	event = <-bobTxChan

	require.Equal(t, types.TxsAdded, event.Type)
	require.Len(t, event.Txs, 1)
	offchainReceivedTx := event.Txs[0]
	require.Equal(t, clientTypes.TxReceived, offchainReceivedTx.Type)
	require.Equal(t, 10000, int(offchainReceivedTx.Amount))
	require.NotEmpty(t, offchainReceivedTx.Hex)
	require.Empty(t, offchainReceivedTx.BoardingTxid)
	require.Empty(t, offchainReceivedTx.CommitmentTxid)
	require.NotEmpty(t, offchainReceivedTx.ArkTxid)
	require.Empty(t, offchainReceivedTx.SettledBy)

	// verify history contains the offchain tx
	history, err = bob.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 1)
	requireTxEqual(t, offchainReceivedTx, history[0], "")

	// bob sends funds to alice
	arkTxid, err = bob.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     aliceOffchainAddr,
		Amount: 10000,
	}})
	require.NoError(t, err)

	// should receive the ark tx event
	event = <-aliceTxChan
	require.Equal(t, types.TxsAdded, event.Type)
	require.Len(t, event.Txs, 1)
	offchainReceivedTx = event.Txs[0]
	require.Equal(t, clientTypes.TxReceived, offchainReceivedTx.Type)
	require.Equal(t, arkTxid, offchainReceivedTx.ArkTxid)
	require.Empty(t, offchainReceivedTx.BoardingTxid)
	require.Empty(t, offchainReceivedTx.CommitmentTxid)
	require.Equal(t, 10000, int(offchainReceivedTx.Amount))
	require.NotEmpty(t, offchainReceivedTx.Hex)

	// check history matches
	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 3)
	requireTxEqual(t, offchainReceivedTx, history[0], "")
	requireTxEqual(t, offchainTx, history[1], "")
	requireTxEqual(t, settledBoardingTx, history[2], "")

	time.Sleep(5 * time.Second)

	commitmentTxid, err = alice.CollaborativeExit(ctx, bobOnchainAddr, 12000)
	require.NoError(t, err)
	require.NotEmpty(t, commitmentTxid)

	// should receive the offchain settled tx event
	event = <-aliceTxChan
	require.Equal(t, types.TxsAdded, event.Type)
	require.Len(t, event.Txs, 1)
	collabExitTx := event.Txs[0]
	require.Equal(t, clientTypes.TxSent, collabExitTx.Type)
	require.Equal(t, 12000, int(collabExitTx.Amount))
	require.Empty(t, collabExitTx.BoardingTxid)
	require.NotEmpty(t, collabExitTx.CommitmentTxid)
	require.Empty(t, collabExitTx.ArkTxid)

	// Give time to update also the other records
	time.Sleep(5 * time.Second)

	history, err = alice.GetTransactionHistory(ctx)
	require.NoError(t, err)
	require.Len(t, history, 4)

	requireTxEqual(t, collabExitTx, history[0], "")
	requireTxEqual(t, offchainReceivedTx, history[1], commitmentTxid)
	requireTxEqual(t, offchainTx, history[2], commitmentTxid)
	requireTxEqual(t, settledBoardingTx, history[3], "")
}

func requireTxEqual(t *testing.T, expected, actual clientTypes.Transaction, settledBy string) {
	require.Equal(t, expected.TransactionKey, actual.TransactionKey)
	require.Equal(t, expected.Type, actual.Type)
	require.Equal(t, expected.Amount, actual.Amount)
	require.Equal(t, expected.Hex, actual.Hex)
	require.Equal(t, expected.CreatedAt.Unix(), actual.CreatedAt.Unix())
	if settledBy != "" {
		require.Equal(t, settledBy, actual.SettledBy)
		return
	}
	require.Equal(t, expected.SettledBy, actual.SettledBy)
}
