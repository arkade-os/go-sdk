package e2e

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

	hdOnchainAddrs, hdOffchainAddrs, hdBoardingAddrs, hdRedemptionAddrs, err := hdWallet.GetAddresses(
		ctx,
	)
	require.NoError(t, err)
	require.Len(t, hdOnchainAddrs, 6)
	require.Len(t, hdOffchainAddrs, 6)
	require.Len(t, hdBoardingAddrs, 6)
	require.Len(t, hdRedemptionAddrs, 6)
	require.Contains(t, hdOffchainAddrs, hdOffchain1)
	require.Contains(t, hdOffchainAddrs, hdOffchain2)
	require.Contains(t, hdBoardingAddrs, hdBoarding1)
	require.Contains(t, hdBoardingAddrs, hdBoarding2)
	require.Contains(t, hdOnchainAddrs, hdOnchain1)
	require.Contains(t, hdOnchainAddrs, hdOnchain2)
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

	bobFaucetAddr, err := bobClientHD.NewOffchainAddress(ctx)
	require.NoError(t, err)
	faucetOffchain(t, bobClientHD, bobFaucetAddr, 0.001)

	// Scenario 1: Alice is online and receives on a known HD address.
	_, err = bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
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

	bobFaucetAddr, err := bobClientHD.NewOffchainAddress(ctx)
	require.NoError(t, err)
	faucetOffchain(t, bobClientHD, bobFaucetAddr, 0.001)

	_, err = bobClientHD.SendOffChain(ctx, []clientTypes.Receiver{{
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

	aliceClientHD := setupClient(t, "")
	bobClientHD := setupClient(t, "")

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

	onchainAddrs := make([]string, 0, 2)
	for range 2 {
		addr, err := aliceClientHD.NewOnchainAddress(ctx)
		require.NoError(t, err)
		onchainAddrs = append(onchainAddrs, addr)
	}

	_, _, _, redemptionAddrs, err := aliceClientHD.GetAddresses(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(redemptionAddrs), 6)

	seed, err := aliceClientHD.Dump(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, seed)

	aliceClientHD.Stop()
	aliceClientHD = nil

	bobFaucetAddr, err := bobClientHD.NewOffchainAddress(ctx)
	require.NoError(t, err)
	for range 4 {
		faucetOffchain(t, bobClientHD, bobFaucetAddr, 0.001)
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

	onchainAmounts := []float64{0.00011, 0.00012}
	for i, amount := range onchainAmounts {
		faucetOnchain(t, onchainAddrs[i], amount)
	}

	redemptionTargets := redemptionAddrs[:2]
	redemptionAmounts := []float64{0.00031, 0.00032}
	for i, amount := range redemptionAmounts {
		faucetOnchain(t, redemptionTargets[i], amount)
	}

	require.NoError(t, generateBlocks(1))
	waitForExplorerHistory(t, bobClientHD, append(
		append(append([]string{}, boardingAddrs...), onchainAddrs...),
		redemptionTargets...,
	))

	aliceClientHD = setupClient(t, seed)

	const wantOffchainTotal = uint64(50_000)
	require.Eventually(t, func() bool {
		spendable, spent, err := aliceClientHD.ListVtxos(ctx)
		if err != nil {
			return false
		}

		return len(spent) == 0 && len(spendable) == 4 &&
			sumVtxoAmounts(spendable) == wantOffchainTotal
	}, 30*time.Second, 500*time.Millisecond)

	const wantOnchainSpendable = uint64(23_000)
	const wantLockedOnchain = uint64(106_000)
	require.Eventually(t, func() bool {
		balance, err := aliceClientHD.Balance(ctx)
		if err != nil {
			return false
		}

		return balance.OffchainBalance.Total == wantOffchainTotal &&
			balance.OnchainBalance.SpendableAmount == wantOnchainSpendable &&
			sumLockedAmounts(balance.OnchainBalance.LockedAmount) == wantLockedOnchain
	}, 60*time.Second, 500*time.Millisecond)
}

func TestHDWalletEventStreams(t *testing.T) {
	t.Run("offchain transfer and settlement", func(t *testing.T) {
		ctx := t.Context()

		aliceClientHD := setupClient(t, "")
		bobClientHD := setupClient(t, "")

		aliceFaucetAddr, err := aliceClientHD.NewOffchainAddress(ctx)
		require.NoError(t, err)
		faucetOffchain(t, aliceClientHD, aliceFaucetAddr, 0.001)

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

		aliceClientHD := setupClient(t, "")

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
