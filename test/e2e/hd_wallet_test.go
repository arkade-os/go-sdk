package e2e_test

import (
	"testing"
	"time"

	client "github.com/arkade-os/arkd/pkg/client-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestHDWalletAddressMethodsAllocateFreshKeys(t *testing.T) {
	ctx := t.Context()

	hdWallet := setupClient(t, "")

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err := hdWallet.GetAddresses(ctx)
	require.NoError(t, err)
	require.Empty(t, onchainAddrs)
	require.Empty(t, offchainAddrs)
	require.Empty(t, boardingAddrs)
	require.Empty(t, redemptionAddrs)

	hdOffchain1, err := hdWallet.NewOffchainAddress(ctx)
	require.NoError(t, err)
	hdOffchain2, err := hdWallet.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEqual(t, hdOffchain1, hdOffchain2)

	hdBoarding1, err := hdWallet.NewBoardingAddress(ctx)
	require.NoError(t, err)
	hdBoarding2, err := hdWallet.NewBoardingAddress(ctx)
	require.NoError(t, err)
	require.NotEqual(t, hdBoarding1, hdBoarding2)

	hdOnchain1, err := hdWallet.NewOnchainAddress(ctx)
	require.NoError(t, err)
	hdOnchain2, err := hdWallet.NewOnchainAddress(ctx)
	require.NoError(t, err)
	require.NotEqual(t, hdOnchain1, hdOnchain2)

	onchainAddrs, offchainAddrs, boardingAddrs, redemptionAddrs, err = hdWallet.GetAddresses(ctx)
	require.NoError(t, err)
	require.Len(t, onchainAddrs, 2)
	require.Len(t, offchainAddrs, 2)
	require.Len(t, boardingAddrs, 2)
	require.Len(t, redemptionAddrs, 2)
	require.Contains(t, offchainAddrs, hdOffchain1)
	require.Contains(t, offchainAddrs, hdOffchain2)
	require.Contains(t, boardingAddrs, hdBoarding1)
	require.Contains(t, boardingAddrs, hdBoarding2)
	require.Contains(t, onchainAddrs, hdOnchain1)
	require.Contains(t, onchainAddrs, hdOnchain2)
}

func TestHDWalletRecoversFundsAtRestore(t *testing.T) {
	ctx := t.Context()

	aliceClientHD := setupClient(t, "")
	bobClientHD := setupClient(t, "")

	addresses := make([]string, 0, 22)
	for range 22 {
		addr, err := aliceClientHD.NewOffchainAddress(ctx)
		require.NoError(t, err)
		addresses = append(addresses, addr)
	}

	faucetOffchain(t, bobClientHD, 0.001)

	// Scenario 1: Alice is online and receives on a known HD address.
	_, err := bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     addresses[0],
		Amount: 15_000,
	}})
	require.NoError(t, err)

	spendable := waitForSpendableVtxos(t, aliceClientHD, 1, 15_000)
	require.ElementsMatch(t, []uint64{15_000}, vtxoAmounts(spendable))

	balance, err := aliceClientHD.Balance(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 15_000, balance.OffchainBalance.Total)

	seed, err := aliceClientHD.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	// Scenario 2: Alice goes offline and Bob sends to another pre-derived Alice address.
	aliceClientHD.Stop()
	aliceClientHD = nil

	_, err = bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     addresses[21],
		Amount: 16_000,
	}})
	require.NoError(t, err)

	// Scenario 3: Alice restores from seed and discovers all used keys on startup.
	aliceClientHD = setupClient(t, seed, sdk.WithGapLimit(50))

	restoredSpendable, restoredSpent, err := aliceClientHD.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, restoredSpent, 0)
	require.Len(t, restoredSpendable, 2)
	require.ElementsMatch(t, []uint64{15_000, 16_000}, vtxoAmounts(restoredSpendable))

	restoredBalance, err := aliceClientHD.Balance(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 31_000, restoredBalance.OffchainBalance.Total)

	nextAddr, err := aliceClientHD.NewOffchainAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, nextAddr)
	require.NotContains(t, addresses, nextAddr)

	bobAddr, err := bobClientHD.NewOffchainAddress(ctx)
	require.NoError(t, err)

	bobBalanceBefore, err := bobClientHD.Balance(ctx)
	require.NoError(t, err)

	_, err = aliceClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     bobAddr,
		Amount: 20_000,
	}})
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		bobBalanceAfter, err := bobClientHD.Balance(ctx)
		if err != nil {
			return false
		}

		return bobBalanceAfter.OffchainBalance.Total == bobBalanceBefore.OffchainBalance.Total+20_000
	}, 30*time.Second, 500*time.Millisecond)
}

func TestHDWalletDoesNotRecoverVtxoBeyondConfiguredGapLimit(t *testing.T) {
	ctx := t.Context()

	const gapLimit = uint32(5)

	aliceClientHD := setupClient(t, "", sdk.WithGapLimit(gapLimit))
	bobClientHD := setupClient(t, "")

	addresses := make([]string, 0, 11)
	for range 11 {
		addr, err := aliceClientHD.NewOffchainAddress(ctx)
		require.NoError(t, err)
		addresses = append(addresses, addr)
	}

	faucetOffchain(t, bobClientHD, 0.001)

	_, err := bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     addresses[0],
		Amount: 15_000,
	}})
	require.NoError(t, err)

	waitForSpendableVtxos(t, aliceClientHD, 1, 15_000)

	seed, err := aliceClientHD.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	aliceClientHD.Stop()
	aliceClientHD = nil

	_, err = bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
		To:     addresses[10],
		Amount: 16_000,
	}})
	require.NoError(t, err)

	aliceClientHD = setupClient(t, seed, sdk.WithGapLimit(gapLimit))

	restoredSpendable, restoredSpent, err := aliceClientHD.ListVtxos(ctx)
	require.NoError(t, err)
	require.Len(t, restoredSpent, 0)
	require.Len(t, restoredSpendable, 1)
	require.ElementsMatch(t, []uint64{15_000}, vtxoAmounts(restoredSpendable))

	restoredBalance, err := aliceClientHD.Balance(ctx)
	require.NoError(t, err)
	require.EqualValues(t, 15_000, restoredBalance.OffchainBalance.Total)
}

func TestHDWalletRestoresMixedOnchainAndOffchainState(t *testing.T) {
	ctx := t.Context()

	aliceClientHD := setupClient(t, "", sdk.WithoutAutoSettle())
	bobClientHD := setupClient(t, "", sdk.WithoutAutoSettle())

	offchainAddrs := make([]string, 0, 2)
	for range 2 {
		addr, err := aliceClientHD.NewOffchainAddress(ctx)
		require.NoError(t, err)
		offchainAddrs = append(offchainAddrs, addr)
	}

	boardingAddrs := make([]string, 0, 2)
	for range 2 {
		addr, err := aliceClientHD.NewBoardingAddress(ctx)
		require.NoError(t, err)
		boardingAddrs = append(boardingAddrs, addr)
	}

	seed, err := aliceClientHD.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	aliceClientHD.Stop()
	aliceClientHD = nil

	for range 4 {
		faucetOffchain(t, bobClientHD, 0.001)
	}

	offchainAmounts := []uint64{11_000, 12_000, 13_000, 14_000}
	for i, amount := range offchainAmounts {
		_, err := bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     offchainAddrs[i/2],
			Amount: amount,
		}})
		require.NoError(t, err)
	}

	boardingAmounts := []float64{0.00021, 0.00022}
	for i, amount := range boardingAmounts {
		faucetOnchain(t, boardingAddrs[i], amount)
	}

	require.NoError(t, generateBlocks(1))
	waitForExplorerHistory(t, bobClientHD, boardingAddrs)

	aliceClientHD = setupClient(t, seed, sdk.WithoutAutoSettle())

	const wantOffchainTotal = uint64(50_000)
	require.Eventually(t, func() bool {
		spendable, spent, err := aliceClientHD.ListVtxos(ctx)
		if err != nil {
			return false
		}

		return len(spent) == 0 && len(spendable) == 4 &&
			sumVtxoAmounts(spendable) == wantOffchainTotal
	}, 10*time.Second, 200*time.Millisecond)

	const wantOnchainSpendable = uint64(43_000)
	require.Eventually(t, func() bool {
		balance, err := aliceClientHD.Balance(ctx)
		if err != nil {
			return false
		}

		return balance.OffchainBalance.Total == wantOffchainTotal &&
			balance.OnchainBalance.SpendableAmount == wantOnchainSpendable
	}, 30*time.Second, 500*time.Millisecond)
}

func TestHDWalletEventStreams(t *testing.T) {
	t.Run("offchain transfer and settlement", func(t *testing.T) {
		ctx := t.Context()

		aliceClientHD := setupClient(t, "")
		bobClientHD := setupClient(t, "")

		faucetOffchain(t, aliceClientHD, 0.001)

		bobOffchainAddr, err := bobClientHD.NewOffchainAddress(ctx)
		require.NoError(t, err)

		bobVtxoCh := bobClientHD.GetVtxoEventChannel(ctx)

		_, err = aliceClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobOffchainAddr,
			Amount: 100,
		}})
		require.NoError(t, err)

		firstReceived := waitForVtxoEvent(
			t,
			bobVtxoCh,
			30*time.Second,
			func(event types.VtxoEvent) bool {
				return event.Type == types.VtxosAdded &&
					len(event.Vtxos) == 1 &&
					event.Vtxos[0].Amount == 100
			},
		)
		require.EqualValues(t, 100, firstReceived.Vtxos[0].Amount)

		_, err = aliceClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
			To:     bobOffchainAddr,
			Amount: 1000,
		}})
		require.NoError(t, err)

		secondReceived := waitForVtxoEvent(
			t,
			bobVtxoCh,
			30*time.Second,
			func(event types.VtxoEvent) bool {
				return event.Type == types.VtxosAdded &&
					len(event.Vtxos) == 1 &&
					event.Vtxos[0].Amount == 1000
			},
		)
		require.EqualValues(t, 1000, secondReceived.Vtxos[0].Amount)

		_, err = bobClientHD.Settle(ctx)
		require.NoError(t, err)

		settled := waitForVtxoEvent(t, bobVtxoCh, 30*time.Second, func(event types.VtxoEvent) bool {
			return event.Type == types.VtxosAdded &&
				len(event.Vtxos) == 1 &&
				event.Vtxos[0].Amount == 1100
		})
		require.EqualValues(t, 1100, settled.Vtxos[0].Amount)
	})

	t.Run("boarding receive and settlement", func(t *testing.T) {
		ctx := t.Context()

		aliceClientHD := setupClient(t, "", sdk.WithoutAutoSettle())

		boardingAddr, err := aliceClientHD.NewBoardingAddress(ctx)
		require.NoError(t, err)

		aliceUtxoCh := aliceClientHD.GetUtxoEventChannel(ctx)
		aliceTxCh := aliceClientHD.GetTransactionEventChannel(ctx)
		aliceVtxoCh := aliceClientHD.GetVtxoEventChannel(ctx)

		faucetOnchain(t, boardingAddr, 0.00021)

		addedUtxoEvent := waitForUtxoEvent(
			t,
			aliceUtxoCh,
			30*time.Second,
			func(event types.UtxoEvent) bool {
				return event.Type == types.UtxosAdded &&
					len(event.Utxos) == 1 &&
					event.Utxos[0].Amount == 21000
			},
		)
		require.EqualValues(t, 21000, addedUtxoEvent.Utxos[0].Amount)

		addedTxEvent := waitForTxEvent(
			t,
			aliceTxCh,
			30*time.Second,
			func(event types.TransactionEvent) bool {
				return event.Type == types.TxsAdded &&
					len(event.Txs) == 1 &&
					event.Txs[0].Amount == 21000 &&
					event.Txs[0].BoardingTxid != ""
			},
		)
		require.EqualValues(t, 21000, addedTxEvent.Txs[0].Amount)
		require.NotEmpty(t, addedTxEvent.Txs[0].BoardingTxid)

		commitmentTxid, err := aliceClientHD.Settle(ctx)
		require.NoError(t, err)
		require.NotEmpty(t, commitmentTxid)

		addedVtxoEvent := waitForVtxoEvent(
			t,
			aliceVtxoCh,
			30*time.Second,
			func(event types.VtxoEvent) bool {
				return event.Type == types.VtxosAdded &&
					len(event.Vtxos) == 1 &&
					event.Vtxos[0].Amount == 21000
			},
		)
		require.EqualValues(t, 21000, addedVtxoEvent.Vtxos[0].Amount)

		settledTxEvent := waitForTxEvent(
			t,
			aliceTxCh,
			30*time.Second,
			func(event types.TransactionEvent) bool {
				return event.Type == types.TxsSettled &&
					len(event.Txs) == 1 &&
					event.Txs[0].BoardingTxid == addedTxEvent.Txs[0].BoardingTxid &&
					event.Txs[0].SettledBy == commitmentTxid
			},
		)
		require.Equal(t, commitmentTxid, settledTxEvent.Txs[0].SettledBy)
		require.Equal(t, addedTxEvent.Txs[0].BoardingTxid, settledTxEvent.Txs[0].BoardingTxid)
	})
}

func waitForExplorerHistory(t *testing.T, client sdk.ArkClient, addresses []string) {
	t.Helper()

	require.Eventually(t, func() bool {
		explorer := client.Explorer()
		if explorer == nil {
			return false
		}

		for _, address := range addresses {
			txs, err := explorer.GetTxs(address)
			if err != nil || len(txs) == 0 {
				return false
			}
		}

		return true
	}, 30*time.Second, 500*time.Millisecond)
}

func waitForSpendableVtxos(
	t *testing.T, client sdk.ArkClient, wantCount int, wantTotal uint64,
) []clientTypes.Vtxo {
	t.Helper()

	var spendable []clientTypes.Vtxo
	require.Eventually(t, func() bool {
		var err error
		spendable, _, err = client.ListVtxos(t.Context())
		if err != nil {
			return false
		}

		return len(spendable) == wantCount && sumVtxoAmounts(spendable) == wantTotal
	}, 30*time.Second, 500*time.Millisecond)

	return spendable
}

func waitForVtxoEvent(
	t *testing.T,
	ch <-chan types.VtxoEvent,
	timeout time.Duration,
	match func(types.VtxoEvent) bool,
) types.VtxoEvent {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-ch:
			if match(event) {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for matching vtxo event")
		}
	}
}

func waitForUtxoEvent(
	t *testing.T,
	ch <-chan types.UtxoEvent,
	timeout time.Duration,
	match func(types.UtxoEvent) bool,
) types.UtxoEvent {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-ch:
			if match(event) {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for matching utxo event")
		}
	}
}

func waitForTxEvent(
	t *testing.T,
	ch <-chan types.TransactionEvent,
	timeout time.Duration,
	match func(types.TransactionEvent) bool,
) types.TransactionEvent {
	t.Helper()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case event := <-ch:
			if match(event) {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for matching tx event")
		}
	}
}

// TestHDWalletRecoversBoardingOnlyFundedKeys covers the case:
// a key whose ONLY activity is a boarding UTXO (never any offchain VTXO at
// the matching offchain script). After dumping the seed and restoring into a
// fresh client, discovery must still find the key so the boarding UTXO is reachable.
func TestHDWalletRecoversBoardingOnlyFundedKeys(t *testing.T) {
	ctx := t.Context()

	alice := setupClient(t, "", sdk.WithoutAutoSettle())

	boardingAddr, err := alice.NewBoardingAddress(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, boardingAddr)

	const boardingAmount = 0.00021
	faucetOnchain(t, boardingAddr, boardingAmount)
	require.NoError(t, generateBlocks(1))

	waitForExplorerHistory(t, alice, []string{boardingAddr})

	seed, err := alice.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	alice.Stop()

	restoredAlice := setupClient(t, seed, sdk.WithoutAutoSettle())

	// The restored wallet should re-discover the key that backs the funded
	// boarding address and surface the UTXO in its onchain balance.
	require.Eventually(t, func() bool {
		balance, err := restoredAlice.Balance(ctx)
		if err != nil {
			return false
		}
		return sumLockedAmounts(balance.OnchainBalance.LockedAmount) >= uint64(boardingAmount*1e8)
	}, 30*time.Second, 500*time.Millisecond,
		"restored wallet did not recover the boarding-only funded key")
}

func sumVtxoAmounts(vtxos []clientTypes.Vtxo) uint64 {
	var total uint64
	for _, vtxo := range vtxos {
		total += vtxo.Amount
	}

	return total
}

func vtxoAmounts(vtxos []clientTypes.Vtxo) []uint64 {
	amounts := make([]uint64, 0, len(vtxos))
	for _, vtxo := range vtxos {
		amounts = append(amounts, vtxo.Amount)
	}

	return amounts
}

func sumLockedAmounts(locked []client.LockedOnchainBalance) uint64 {
	var total uint64
	for _, utxo := range locked {
		total += utxo.Amount
	}

	return total
}
