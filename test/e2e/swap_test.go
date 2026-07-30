package e2e_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	sdk "github.com/arkade-os/go-sdk"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/swap"
	"github.com/arkade-os/go-sdk/swap/boltz"
	swapstore "github.com/arkade-os/go-sdk/swap/store"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightningnetwork/lnd/input"
	"github.com/stretchr/testify/require"
)

const (
	boltzUrl   = "http://127.0.0.1:9001"
	boltzWsUrl = "http://127.0.0.1:9004"

	// boltz-fulmine REST API (used by Boltz for internal operations)
	boltzFulmineUrl = "http://127.0.0.1:7003/api/v1"
)

// TestSubmarineSwap exercises the Ark-to-Lightning submarine swap flow using real Boltz:
// alice pays a Lightning invoice by funding a VHTLC that Boltz claims to settle the invoice.
func TestSubmarineSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice := setupClient(t, "")
	faucetOffchain(t, alice, 0.001) // 100,000 sats

	manager := setupSwapManager(t, alice)

	invoice, rHash, err := lndAddInvoiceWithHash(5000)
	require.NoError(t, err)
	require.NotEmpty(t, invoice)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	t.Cleanup(cancel)

	swapResult, err := manager.SubmarineSwap(ctx, invoice)
	require.NoError(t, err)
	require.NotNil(t, swapResult)
	require.NotEmpty(t, swapResult.Id)
	require.Equal(t, int(swap.SwapStatusSuccess), swapResult.Status)

	// The redeem txid is not asserted: Boltz may settle the invoice without notifying the
	// vhtlc claim tx over the websocket.
	awaitPersistedSwap(t, manager, swapResult.Id, swap.SwapStatusSuccess)

	// The point of the swap is paying the Lightning invoice: verify it's actually settled.
	state, err := lndInvoiceState(rHash)
	require.NoError(t, err)
	require.Equal(t, "SETTLED", state)
}

// TestReverseSwap exercises the Lightning-to-Ark reverse swap flow using real Boltz:
// alice requests an invoice from Boltz, LND pays it, Boltz funds a VHTLC that alice claims
// in background. The completion is observed through the persisted swap.
func TestReverseSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice := setupClient(t, "")
	// Alice needs some initial funds for the VHTLC fee overhead
	faucetOffchain(t, alice, 0.001) // 100,000 sats

	manager := setupSwapManager(t, alice)

	balanceBefore, err := alice.Balance(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	t.Cleanup(cancel)

	swapResult, err := manager.ReverseSwap(ctx, 4000)
	require.NoError(t, err)
	require.NotEmpty(t, swapResult.Id)
	require.NotNil(t, swapResult.LNSwap)
	require.NotEmpty(t, swapResult.LNSwap.Invoice)

	// The LN payment settles only once alice claims the VHTLC revealing the preimage.
	require.NoError(t, lndPayInvoice(swapResult.LNSwap.Invoice))

	persisted := awaitPersistedSwap(t, manager, swapResult.Id, swap.SwapStatusSuccess)
	require.NotEmpty(t, persisted.RedeemTxid)

	// The point of the swap is receiving offchain funds: verify the balance increased.
	balanceAfter, err := alice.Balance(t.Context())
	require.NoError(t, err)
	require.Greater(t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
		"alice should have received the swapped funds offchain")
}

// TestCircularSwap exercises a self-pay circular swap using real Boltz and LND: alice creates
// a reverse swap to receive from Lightning, then pays its invoice with a submarine swap. This
// exercises both send and receive paths in a single flow.
func TestCircularSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice := setupClient(t, "")
	faucetOffchain(t, alice, 0.002) // 200,000 sats (needs enough for both send + receive fees)

	manager := setupSwapManager(t, alice)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	t.Cleanup(cancel)

	reverseSwap, err := manager.ReverseSwap(ctx, 3000)
	require.NoError(t, err)
	require.NotEmpty(t, reverseSwap.Id)
	require.NotNil(t, reverseSwap.LNSwap)
	require.NotEmpty(t, reverseSwap.LNSwap.Invoice)

	payResult, err := manager.SubmarineSwap(ctx, reverseSwap.LNSwap.Invoice)
	require.NoError(t, err)
	require.NotNil(t, payResult)
	require.Equal(t, int(swap.SwapStatusSuccess), payResult.Status)

	persisted := awaitPersistedSwap(t, manager, reverseSwap.Id, swap.SwapStatusSuccess)
	require.NotEmpty(t, persisted.RedeemTxid)
}

// TestConcurrentSwaps exercises multiple simultaneous swap operations to test the swap
// manager's concurrency. It runs parallel submarine and reverse swaps.
func TestConcurrentSwaps(t *testing.T) {
	// SubmarineSwap returns a nil error also when the swap fails and is refunded or times out:
	// the status of the returned swaps must be checked explicitly.
	t.Run("distinct submarine swaps", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.002) // enough for two submarine swaps

		manager := setupSwapManager(t, alice)

		invoice1, err := lndAddInvoice(2000)
		require.NoError(t, err)
		require.NotEmpty(t, invoice1)
		invoice2, err := lndAddInvoice(2000)
		require.NoError(t, err)
		require.NotEmpty(t, invoice2)

		results := make(chan swapResult, 2)
		invoices := []string{invoice1, invoice2}
		for i := range invoices {
			invoice := invoices[i]
			go func(invoice string) {
				ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
				defer cancel()
				s, err := manager.SubmarineSwap(ctx, invoice)
				results <- swapResult{swap: s, err: err}
			}(invoice)
		}

		for i := 0; i < 2; i++ {
			res := <-results
			require.NoError(t, res.err, fmt.Sprintf("submarine swap %d should succeed", i+1))
			require.NotNil(t, res.swap)
			require.Equal(t, int(swap.SwapStatusSuccess), res.swap.Status)
		}
	})

	t.Run("submarine and reverse swaps", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.002)

		manager := setupSwapManager(t, alice)

		invoiceAmount := 2001
		invoice, err := lndAddInvoice(invoiceAmount)
		require.NoError(t, err)
		require.NotEmpty(t, invoice)

		submarineResults := make(chan swapResult, 1)
		reverseResults := make(chan swapResult, 1)

		// Submarine swap (Ark -> LN)
		go func() {
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
			defer cancel()
			s, err := manager.SubmarineSwap(ctx, invoice)
			submarineResults <- swapResult{swap: s, err: err}
		}()

		// Reverse swap (LN -> Ark)
		go func() {
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
			defer cancel()
			reverseSwap, err := manager.ReverseSwap(ctx, uint64(invoiceAmount))
			if err == nil {
				err = lndPayInvoice(reverseSwap.LNSwap.Invoice)
			}
			reverseResults <- swapResult{swap: reverseSwap, err: err}
		}()

		submarineRes := <-submarineResults
		require.NoError(t, submarineRes.err)
		require.NotNil(t, submarineRes.swap)
		require.Equal(t, int(swap.SwapStatusSuccess), submarineRes.swap.Status)

		reverseRes := <-reverseResults
		require.NoError(t, reverseRes.err)
		require.NotNil(t, reverseRes.swap)
		awaitPersistedSwap(t, manager, reverseRes.swap.Id, swap.SwapStatusSuccess)
	})

	t.Run("distinct reverse swaps", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.002)

		manager := setupSwapManager(t, alice)

		results := make(chan swapResult, 2)
		for range 2 {
			go func() {
				ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
				defer cancel()
				reverseSwap, err := createReverseSwapWithRetry(ctx, manager, 2002)
				if err == nil {
					err = lndPayInvoice(reverseSwap.LNSwap.Invoice)
				}
				results <- swapResult{swap: reverseSwap, err: err}
			}()
		}

		for i := 0; i < 2; i++ {
			res := <-results
			require.NoError(t, res.err, fmt.Sprintf("reverse swap %d should succeed", i+1))
			require.NotNil(t, res.swap)
			awaitPersistedSwap(t, manager, res.swap.Id, swap.SwapStatusSuccess)
		}
	})
}

// TestRefundSubmarineSwap tests the cooperative refund path for an underfunded submarine swap.
//
// Flow:
//  1. Create an LND invoice
//  2. Create a submarine swap via Boltz API directly (not through the SwapManager)
//  3. Derive VHTLC opts from Boltz's response and verify address match
//  4. Import the vhtlc contract and persist the swap so the manager can refund it
//  5. Underfund the swap (send less than expectedAmount)
//  6. Wait for Boltz to mark the swap as failed (lockupFailed)
//  7. Call manager.RefundSubmarineSwap: Boltz co-signs the refund
func TestRefundSubmarineSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice, datadir := setupSwapWallet(t, "")
	faucetOffchain(t, alice, 0.001) // 100,000 sats

	balanceBefore, err := alice.Balance(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	t.Cleanup(cancel)

	boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
	sw := createBoltzSubmarineSwap(t, ctx, alice, datadir, boltzSvc)

	// The manager is created while the swap is still just created on Boltz (not yet
	// underfunded), so its startup recovery sees a non-actionable swap and leaves it to the
	// manual refund below.
	manager := setupSwapManager(t, alice)

	underfundAndWaitLockupFailed(t, ctx, alice, sw)

	refundedSwap, scheduledAt, err := manager.RefundSubmarineSwap(ctx, sw.id)
	require.NoError(t, err, "cooperative refund of an underfunded submarine swap should succeed")
	require.Nil(t, scheduledAt, "refund should happen collaboratively, not be scheduled")
	require.NotNil(t, refundedSwap)
	require.NotEmpty(t, refundedSwap.RedeemTxid)

	// The refunded swap is persisted as failed, with the refund txid set.
	persisted, err := manager.GetSwap(ctx, sw.id)
	require.NoError(t, err)
	require.Equal(t, int(swap.SwapStatusFailed), persisted.Status)
	require.Equal(t, refundedSwap.RedeemTxid, persisted.RedeemTxid)

	time.Sleep(2 * time.Second)

	requireVHTLCSpentBy(t, alice, sw.vhtlcScript, refundedSwap.RedeemTxid)

	// Verify balance is preserved (the underfunded amount came back).
	balanceAfter, err := alice.Balance(t.Context())
	require.NoError(t, err)
	require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
		"offchain balance should be preserved after the refund")
}

func TestChainSwap(t *testing.T) {
	// The manager funds a VHTLC, Boltz locks up BTC on-chain and the manager claims it to the
	// destination address. The completion is observed through the persisted swap.
	t.Run("arkade to btc", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.001) // 100,000 sats

		manager := setupSwapManager(t, alice)

		btcAddress, err := runCommand("nigiri", "rpc", "getnewaddress")
		require.NoError(t, err)
		require.NotEmpty(t, btcAddress)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		chainSwap, err := manager.ArkadeToBtcChainSwap(ctx, btcAddress, 50000)
		require.NoError(t, err)
		require.NotNil(t, chainSwap)
		require.NotEmpty(t, chainSwap.Id)

		persisted := awaitPersistedSwap(t, manager, chainSwap.Id, swap.SwapStatusSuccess)
		require.NotNil(t, persisted.ChainSwap)
		require.NotEmpty(t, persisted.ChainSwap.RedeemTxid)

		// The point of the swap is receiving BTC onchain: verify the claim tx paid the
		// destination address (still unconfirmed, hence minconf=0).
		received, err := runCommand("nigiri", "rpc", "getreceivedbyaddress", btcAddress, "0")
		require.NoError(t, err)
		receivedBtc, err := strconv.ParseFloat(strings.TrimSpace(received), 64)
		require.NoError(t, err)
		require.Greater(t, receivedBtc, 0.0, "BTC should have landed at the destination address")
	})

	// The manager creates the swap, the test funds the BTC lockup address onchain, Boltz funds a
	// VHTLC that the manager claims in background.
	// The completion is observed through the persisted swap.
	t.Run("btc to arkade", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		// Alice needs some initial funds for the VHTLC fee overhead
		faucetOffchain(t, alice, 0.001)

		manager := setupSwapManager(t, alice)

		balanceBefore, err := alice.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		chainSwap, err := manager.BtcToArkadeChainSwap(ctx, 50000)
		require.NoError(t, err)
		require.NotNil(t, chainSwap)
		require.NotEmpty(t, chainSwap.Id)
		require.NotNil(t, chainSwap.ChainSwap)
		require.NotEmpty(t, chainSwap.ChainSwap.Address)

		// Fund the BTC lockup address with the swap amount and confirm it: Boltz then funds the
		// vhtlc the manager claims in background.
		_, err = runCommand(
			"nigiri", "rpc", "sendtoaddress", chainSwap.ChainSwap.Address, "0.00050000",
		)
		require.NoError(t, err)
		generateBlocks(t, 1)

		// Boltz funds the vhtlc through a settle round while we wait: without new blocks its
		// commitment tx never confirms and the swap stalls until the timeout. Locally background
		// activity mines often enough to hide this, on CI nobody else does, so keep mining
		// best-effort until the swap completes.
		minerDone := make(chan struct{})
		t.Cleanup(func() { close(minerDone) })
		go func() {
			for {
				select {
				case <-minerDone:
					return
				case <-time.After(10 * time.Second):
					// Can't use generateBlocks because if it ever failed, it would cause a panic in
					// test suit as we can't call t.FailNow in a goroutine.
					// nolint
					runCommand("nigiri", "rpc", "generate", "1")
				}
			}
		}()

		persisted := awaitPersistedSwap(t, manager, chainSwap.Id, swap.SwapStatusSuccess)
		require.NotEmpty(t, persisted.RedeemTxid)
		require.NotNil(t, persisted.ChainSwap)
		require.NotEmpty(t, persisted.ChainSwap.FundingTxid)

		requireVHTLCSpentBy(t, alice, persisted.VHTLCScript, persisted.RedeemTxid)

		// The point of the swap is receiving offchain funds: verify the balance increased.
		balanceAfter, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.Greater(
			t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
			"alice should have received the swapped funds offchain")
	})
}

// TestChainSwapQuoteRenegotiation exercises the renegotiation path of the BTC-to-Arkade chain
// swap: a lockup funded with the wrong amount makes Boltz reject it with
// transaction.lockupFailed, the manager fetches and accepts the new quote in background, and
// the swap completes with the renegotiated amounts. Both wrong directions are renegotiable:
// Boltz reduces the server lockup for an underfunded one and raises it for an overfunded one.
func TestChainSwapQuoteRenegotiation(t *testing.T) {
	tests := []struct {
		name         string
		fundedAmount string
	}{
		{name: "underfunded lockup", fundedAmount: "0.00045000"},
		{name: "overfunded lockup", fundedAmount: "0.00055000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settleBoltzFulmine(t)
			alice := setupClient(t, "")
			// Alice needs some initial funds for the VHTLC fee overhead
			faucetOffchain(t, alice, 0.001)

			manager := setupSwapManager(t, alice)

			balanceBefore, err := alice.Balance(t.Context())
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
			t.Cleanup(cancel)

			chainSwap, err := manager.BtcToArkadeChainSwap(ctx, 50000)
			require.NoError(t, err)
			require.NotNil(t, chainSwap)
			require.NotEmpty(t, chainSwap.Id)
			require.NotNil(t, chainSwap.ChainSwap)
			require.NotEmpty(t, chainSwap.ChainSwap.Address)

			// Fund the BTC lockup with the wrong amount and confirm it: Boltz rejects it and the
			// manager renegotiates before the swap proceeds as usual.
			_, err = runCommand(
				"nigiri", "rpc", "sendtoaddress", chainSwap.ChainSwap.Address, tt.fundedAmount,
			)
			require.NoError(t, err)
			generateBlocks(t, 1)

			// Boltz funds the vhtlc through a settle round while we wait: without new blocks its
			// commitment tx never confirms and the swap stalls until the timeout. Locally
			// background activity mines often enough to hide this, on CI nobody else does, so
			// keep mining best-effort until the swap completes.
			minerDone := make(chan struct{})
			t.Cleanup(func() { close(minerDone) })
			go func() {
				for {
					select {
					case <-minerDone:
						return
					case <-time.After(10 * time.Second):
						// Can't use generateBlocks because if it ever failed, it would cause a
						// panic in test suit as we can't call t.FailNow in a goroutine.
						// nolint
						runCommand("nigiri", "rpc", "generate", "1")
					}
				}
			}()

			persisted := awaitPersistedSwap(t, manager, chainSwap.Id, swap.SwapStatusSuccess)
			require.NotEmpty(t, persisted.RedeemTxid)
			require.NotNil(t, persisted.ChainSwap)
			require.NotEmpty(t, persisted.ChainSwap.FundingTxid)

			requireVHTLCSpentBy(t, alice, persisted.VHTLCScript, persisted.RedeemTxid)

			// The point of the swap is receiving offchain funds: verify the balance increased.
			balanceAfter, err := alice.Balance(t.Context())
			require.NoError(t, err)
			require.Greater(
				t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
				"alice should have received the swapped funds offchain",
			)
		})
	}
}

// TestRefundChainSwap exercises the manual refund of a BTC -> Ark chain swap whose BTC lockup
// Boltz failed (underfunded): before the HTLC locktime expires the refund can only be scheduled;
// once the expiry height is mined the scheduled task broadcasts the script-path refund of the
// btc lockup to a boarding address.
func TestRefundChainSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice, datadir := setupSwapWallet(t, "")

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	t.Cleanup(cancel)

	// The manager is created first so that its startup restore and recovery observe an empty
	// store and don't race with the manual refund below.
	manager := setupSwapManager(t, alice)

	boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
	// Underfund the BTC lockup: with no manager loop accepting the renegotiated quote, Boltz
	// fails the lockup and the swap can only be refunded.
	cs := createBoltzBtcToArkadeChainSwap(t, ctx, alice, datadir, boltzSvc, 50000, 40000)

	// Before the locktime expires the refund can only be scheduled at the expiry height.
	refunded, scheduledAt, err := manager.RefundChainSwap(ctx, cs.id)
	require.NoError(t, err)
	require.NotNil(t, refunded)
	require.NotNil(t, scheduledAt, "refund should be scheduled, the locktime is not expired")
	require.Empty(t, refunded.ChainSwap.RedeemTxid)
	require.Equal(t, int(swap.SwapStatusFailed), refunded.Status)

	// Mine past the HTLC locktime: the scheduled task fires and broadcasts the refund.
	heightStr, err := runCommand("nigiri", "rpc", "getblockcount")
	require.NoError(t, err)
	height, err := strconv.Atoi(strings.TrimSpace(heightStr))
	require.NoError(t, err)
	locktime := int(refunded.ChainSwap.RefundLocktime)
	require.Greater(t, locktime, height, "the htlc locktime should not be expired yet")
	generateBlocks(t, locktime-height+1)

	var redeemTxid string
	require.Eventually(t, func() bool {
		s, err := manager.GetSwap(ctx, cs.id)
		if err != nil || s.ChainSwap.RedeemTxid == "" {
			return false
		}
		redeemTxid = s.ChainSwap.RedeemTxid
		return true
	}, 60*time.Second, 2*time.Second, "the scheduled task should broadcast the refund")

	// The refund tx made it to the mempool: the script-path spend of the refund leaf is valid.
	_, err = runCommand("nigiri", "rpc", "getrawtransaction", redeemTxid)
	require.NoError(t, err)
}

// TestRecoverSwaps exercises the recovery a SwapManager runs at startup for the swaps a
// previous run left behind.
func TestRecoverSwaps(t *testing.T) {
	// A submarine swap we funded that failed while no manager was running must be refunded by
	// the recovery, without any manual intervention.
	t.Run("refunds a failed submarine swap after wallet restart", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t, "")
		faucetOffchain(t, alice, 0.001) // 100,000 sats

		balanceBefore, err := alice.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		sw := createBoltzSubmarineSwap(t, ctx, alice, datadir, boltzSvc)

		// Fail the swap before any manager exists, so recovery is the only actor that can
		// refund it.
		underfundAndWaitLockupFailed(t, ctx, alice, sw)

		// Creating the manager kicks off the startup recovery, which finds the pending swap,
		// sees it failed on Boltz and refunds it.
		manager := setupSwapManager(t, alice)

		var refunded *swaptypes.Swap
		require.Eventually(t, func() bool {
			s, err := manager.GetSwap(ctx, sw.id)
			if err != nil || s.Status != int(swap.SwapStatusFailed) || s.RedeemTxid == "" {
				return false
			}
			refunded = s
			return true
		}, 60*time.Second, time.Second, "recovery should refund the failed swap")

		time.Sleep(2 * time.Second)

		requireVHTLCSpentBy(t, alice, sw.vhtlcScript, refunded.RedeemTxid)

		balanceAfter, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
			"offchain balance should be preserved after the recovered refund")
	})

	// A reverse swap whose vhtlc Boltz funded but that was left unclaimed when the manager
	// stopped must be claimed by the recovery of the next manager.
	t.Run("claims a pending reverse swap after wallet restart", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice := setupClient(t, "")
		faucetOffchain(t, alice, 0.001) // fee overhead for the claim

		balanceBefore, err := alice.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		// The first manager creates the reverse swap, then is closed before the vhtlc is even
		// funded: Close aborts the background claim and leaves the swap pending, as a crash
		// mid-flight would.
		manager1 := setupSwapManager(t, alice)
		reverseSwap, err := manager1.ReverseSwap(ctx, 4000)
		require.NoError(t, err)
		require.NotEmpty(t, reverseSwap.Id)
		require.NotNil(t, reverseSwap.LNSwap)
		require.NotEmpty(t, reverseSwap.LNSwap.Invoice)
		require.NoError(t, manager1.Close())

		// Pay the invoice: Boltz funds the vhtlc, but no manager is watching to claim it.
		go func() { _ = lndPayInvoice(reverseSwap.LNSwap.Invoice) }()

		pkScript, err := hex.DecodeString(reverseSwap.VHTLCScript)
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, alice, pkScript)
			return err == nil && len(vtxos) > 0
		}, 60*time.Second, time.Second, "boltz should fund the reverse swap vhtlc")

		// A fresh manager recovers the funded-but-unclaimed swap on startup and claims it.
		manager2 := setupSwapManager(t, alice)
		persisted := awaitPersistedSwap(t, manager2, reverseSwap.Id, swap.SwapStatusSuccess)
		require.NotEmpty(t, persisted.RedeemTxid)

		requireVHTLCSpentBy(t, alice, reverseSwap.VHTLCScript, persisted.RedeemTxid)

		balanceAfter, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.Greater(t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
			"alice should have received the reverse-swapped funds via recovery")
	})

	// An Arkade -> BTC chain swap whose vhtlc we funded and for which Boltz locked up the BTC,
	// but that was never claimed, must be claimed by the recovery on the next manager startup.
	// The swap is created directly against the Boltz API so that no manager claims it: the
	// manager flow funds and claims in one sub-second pass, leaving no interruptible window.
	t.Run("claims a pending arkade to btc chain swap after wallet restart", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t, "")
		faucetOffchain(t, alice, 0.001) // 100,000 sats

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		cs := createBoltzChainSwap(t, ctx, alice, datadir, boltzSvc, 50000)

		// Boltz locks up the BTC once it sees our vhtlc funding; since nothing claims it, the
		// swap sits in the server-lockup state until recovery claims it. The swap status carries
		// the lockup tx (the chain transactions endpoint is unsupported for ARK swaps).
		require.Eventually(t, func() bool {
			status, err := boltzSvc.GetSwapStatus(cs.id)
			return err == nil &&
				boltz.ParseEvent(status.Status) == boltz.TransactionServerMempoool &&
				status.Transaction.Hex != ""
		}, 240*time.Second, 2*time.Second, "boltz should lock up the BTC")

		// A fresh manager recovers the swap and claims the BTC to the destination address.
		manager := setupSwapManager(t, alice)
		persisted := awaitPersistedSwap(t, manager, cs.id, swap.SwapStatusSuccess)
		require.NotNil(t, persisted.ChainSwap)
		require.NotEmpty(t, persisted.ChainSwap.RedeemTxid)

		// The BTC arrived at the destination address (still unconfirmed, hence minconf=0).
		received, err := runCommand("nigiri", "rpc", "getreceivedbyaddress", cs.btcAddress, "0")
		require.NoError(t, err)
		receivedBtc, err := strconv.ParseFloat(strings.TrimSpace(received), 64)
		require.NoError(t, err)
		require.Greater(t, receivedBtc, 0.0, "BTC should have landed at the destination address")
	})

	// A BTC -> Arkade chain swap whose btc lockup we funded and for which Boltz funded the
	// vhtlc, but that was never claimed, must be claimed by the recovery on the next manager
	// startup.
	t.Run("claims a pending btc to arkade chain swap after wallet restart", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t, "")
		faucetOffchain(t, alice, 0.001) // fee overhead for the claim

		balanceBefore, err := alice.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		cs := createBoltzBtcToArkadeChainSwap(t, ctx, alice, datadir, boltzSvc, 50000, 50000)

		// Boltz funds the vhtlc once our btc lockup confirms; since nothing claims it, the swap
		// sits in the server-lockup state until recovery claims it.
		require.Eventually(t, func() bool {
			status, err := boltzSvc.GetSwapStatus(cs.id)
			return err == nil &&
				boltz.ParseEvent(status.Status) == boltz.TransactionServerMempoool
		}, 240*time.Second, 2*time.Second, "boltz should fund the vhtlc")

		// A fresh manager recovers the pending swap on startup and claims the vhtlc.
		manager := setupSwapManager(t, alice)
		persisted := awaitPersistedSwap(t, manager, cs.id, swap.SwapStatusSuccess)
		require.NotEmpty(t, persisted.RedeemTxid)

		requireVHTLCSpentBy(t, alice, cs.vhtlcScript, persisted.RedeemTxid)

		balanceAfter, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.Greater(t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
			"alice should have received the swapped funds via recovery")
	})

	// A BTC -> Arkade chain swap whose btc lockup Boltz rejected for a wrong amount must be
	// renegotiated by the recovery on the next manager startup, like the live flow would have,
	// and then completed with the new quote.
	t.Run("renegotiates a failed btc to arkade chain swap after wallet restart", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t, "")
		faucetOffchain(t, alice, 0.001) // fee overhead for the claim

		balanceBefore, err := alice.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		// Underfund the lockup: with no manager running, nobody accepts the renegotiated quote
		// and the swap sits in the lockup-failed state until recovery picks it up.
		cs := createBoltzBtcToArkadeChainSwap(t, ctx, alice, datadir, boltzSvc, 50000, 40000)

		require.Eventually(t, func() bool {
			status, err := boltzSvc.GetSwapStatus(cs.id)
			return err == nil &&
				boltz.ParseEvent(status.Status) == boltz.TransactionLockupFailed
		}, 60*time.Second, 2*time.Second, "boltz should reject the underfunded lockup")

		// A fresh manager renegotiates the swap on startup and claims the vhtlc Boltz funds
		// with the new quote.
		manager := setupSwapManager(t, alice)
		persisted := awaitPersistedSwap(t, manager, cs.id, swap.SwapStatusSuccess)
		require.NotEmpty(t, persisted.RedeemTxid)

		requireVHTLCSpentBy(t, alice, cs.vhtlcScript, persisted.RedeemTxid)

		balanceAfter, err := alice.Balance(t.Context())
		require.NoError(t, err)
		require.Greater(t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
			"alice should have received the renegotiated funds via recovery")
	})
}

// TestRestoreSwaps exercises the restore a SwapManager runs on startup when its store is empty,
// ie. after a wallet restore: it reconstructs the swaps known to Boltz from our xpub, persists
// them, and lets the recovery finish them.
func TestRestoreSwaps(t *testing.T) {
	// A submarine swap we funded that failed must be refunded after restoring the wallet from
	// its seed into a fresh datadir, with no local swap or contract data left.
	t.Run("refunds a failed submarine swap after a wallet restore", func(t *testing.T) {
		settleBoltzFulmine(t)
		original, datadir := setupSwapWallet(t, "")
		faucetOffchain(t, original, 0.001) // 100,000 sats

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		sw := createBoltzSubmarineSwap(t, ctx, original, datadir, boltzSvc)

		// Fail the swap on Boltz's side.
		underfundAndWaitLockupFailed(t, ctx, original, sw)

		// Restore the wallet from the same seed into a fresh datadir: its swap and contract
		// stores are empty, as on a new device. The original swap key is m/0/0, which the
		// restored wallet re-derives from the same seed.
		seed, err := original.Dump(ctx)
		require.NoError(t, err)
		restored, _ := setupSwapWallet(t, seed)

		// Creating the manager triggers the restore (empty store), which fetches the swap from
		// Boltz by our xpub, rebuilds and imports the vhtlc contract, persists the swap, and
		// then recovery refunds it.
		manager := setupSwapManager(t, restored)

		var refunded *swaptypes.Swap
		require.Eventually(t, func() bool {
			s, err := manager.GetSwap(ctx, sw.id)
			if err != nil || s.Status != int(swap.SwapStatusFailed) || s.RedeemTxid == "" {
				return false
			}
			refunded = s
			return true
		}, 90*time.Second, 2*time.Second, "restore + recovery should refund the failed swap")

		time.Sleep(2 * time.Second)

		requireVHTLCSpentBy(t, restored, sw.vhtlcScript, refunded.RedeemTxid)
	})

	// A reverse swap whose vhtlc Boltz funded but that was never claimed must be claimed after a
	// wallet restore. Unlike the on-startup recovery, the restored store has no preimage: recovery
	// must re-derive it deterministically from the restored receiver key, so this also exercises
	// that the deterministic preimage survives a wallet restore.
	t.Run("claims a funded reverse swap after a wallet restore", func(t *testing.T) {
		settleBoltzFulmine(t)
		original, _ := setupSwapWallet(t, "")
		faucetOffchain(t, original, 0.001) // fee overhead for the claim

		balanceBefore, err := original.Balance(t.Context())
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		// The first manager creates the reverse swap and is closed before the vhtlc is funded, as
		// a crash mid-flight would leave it: unclaimed and with only Boltz aware of it.
		manager1 := setupSwapManager(t, original)
		reverseSwap, err := manager1.ReverseSwap(ctx, 4000)
		require.NoError(t, err)
		require.NotEmpty(t, reverseSwap.Id)
		require.NotNil(t, reverseSwap.LNSwap)
		require.NotEmpty(t, reverseSwap.LNSwap.Invoice)
		require.NoError(t, manager1.Close())

		// Pay the invoice: Boltz funds the vhtlc, but no manager is watching to claim it.
		go func() { _ = lndPayInvoice(reverseSwap.LNSwap.Invoice) }()

		pkScript, err := hex.DecodeString(reverseSwap.VHTLCScript)
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			vtxos, err := getVHTLCFunds(t, original, pkScript)
			return err == nil && len(vtxos) > 0
		}, 60*time.Second, time.Second, "boltz should fund the reverse swap vhtlc")

		// Restore the wallet from the same seed into a fresh datadir: empty swap and contract
		// stores. The restore reconstructs the reverse swap from our xpub, and recovery claims the
		// funded vhtlc, re-deriving the preimage from the restored receiver key.
		seed, err := original.Dump(ctx)
		require.NoError(t, err)
		restored, _ := setupSwapWallet(t, seed)

		manager2 := setupSwapManager(t, restored)
		persisted := awaitPersistedSwap(t, manager2, reverseSwap.Id, swap.SwapStatusSuccess)
		require.NotEmpty(t, persisted.RedeemTxid)

		requireVHTLCSpentBy(t, restored, reverseSwap.VHTLCScript, persisted.RedeemTxid)

		balanceAfter, err := restored.Balance(t.Context())
		require.NoError(t, err)
		require.Greater(t, balanceAfter.OffchainBalance.Total, balanceBefore.OffchainBalance.Total,
			"the restored wallet should have received the reverse-swapped funds via recovery")
	})

	// A chain swap we funded that failed must be refunded after a wallet restore. Chain-swap
	// restore is refund-only: the BTC-side claim key and destination address are ephemeral and
	// lost on restore, so a failed (underfunded) Arkade lockup is the scenario recovery resolves.
	t.Run("refunds a failed arkade to btc chain swap after a wallet restore", func(t *testing.T) {
		settleBoltzFulmine(t)
		original, _ := setupSwapWallet(t, "")
		faucetOffchain(t, original, 0.001) // 100,000 sats

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
		t.Cleanup(cancel)

		boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
		swapId := createFailedBoltzChainSwap(t, ctx, original, boltzSvc, 50000)

		// Restore the wallet from the same seed into a fresh datadir: empty swap and contract
		// stores. Restore reconstructs the chain swap (refund side only) from our xpub and
		// recovery refunds the vhtlc we funded.
		seed, err := original.Dump(ctx)
		require.NoError(t, err)
		restored, _ := setupSwapWallet(t, seed)

		manager := setupSwapManager(t, restored)

		var refunded *swaptypes.Swap
		require.Eventually(t, func() bool {
			s, err := manager.GetSwap(ctx, swapId)
			if err != nil || s.Status != int(swap.SwapStatusFailed) || s.RedeemTxid == "" {
				return false
			}
			refunded = s
			return true
		}, 90*time.Second, 2*time.Second, "restore + recovery should refund the failed chain swap")

		time.Sleep(2 * time.Second)

		requireVHTLCSpentBy(t, restored, refunded.VHTLCScript, refunded.RedeemTxid)
	})
}

// boltzChainSwap holds the pieces of an Arkade -> BTC chain swap created directly against the
// Boltz API, needed to drive and assert its recovery.
type boltzChainSwap struct {
	id         string
	btcAddress string
}

// createBoltzChainSwap creates an Arkade -> BTC chain swap directly against the Boltz API
// (bypassing the SwapManager), imports the Arkade vhtlc, seeds a pending swap record and funds
// the vhtlc. Nothing claims the BTC Boltz locks up, so the swap is left in the server-lockup
// state for the recovery to complete.
func createBoltzChainSwap(
	t *testing.T, ctx context.Context, alice sdk.Wallet, datadir string, boltzSvc *boltz.Api,
	amount uint64,
) boltzChainSwap {
	t.Helper()

	btcAddress, err := runCommand("nigiri", "rpc", "getnewaddress")
	require.NoError(t, err)
	require.NotEmpty(t, btcAddress)

	// Reserve the wallet key that refunds the Arkade vhtlc (we are its sender).
	keyId, err := alice.Identity().NextKeyId(ctx, "")
	require.NoError(t, err)
	keyRef, err := alice.Identity().GetKey(ctx, keyId)
	require.NoError(t, err)

	// The ephemeral key that claims the BTC HTLC.
	claimKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Derive the preimage deterministically from the sender key exactly like the manager
	// does: the swap record is seeded without it, so the recovery must re-derive it.
	signer, ok := alice.Identity().(swap.PreimageSigner)
	require.True(t, ok, "the wallet identity must support preimage derivation")
	preimage, err := swap.DerivePreimage(ctx, signer, *keyRef)
	require.NoError(t, err)
	shaHash, hash160 := preimage.Hash()

	createResp, err := boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		PreimageHash:    hex.EncodeToString(shaHash),
		ClaimPublicKey:  hex.EncodeToString(claimKey.PubKey().SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		UserLockAmount:  amount,
	})
	require.NoError(t, err)
	require.NotNil(t, createResp.LockupDetails.Timeouts)

	receiverPub, err := parseBoltzPubkey(createResp.LockupDetails.ServerPublicKey)
	require.NoError(t, err)

	timeouts := createResp.LockupDetails.Timeouts
	contractManager := alice.ContractManager()
	vhtlcHandler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	require.NoError(t, err)
	vhtlcContract, err := vhtlcHandler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:    keyId,
		Sender:         keyRef.PubKey,
		Receiver:       receiverPub,
		PreimageHash:   hash160,
		RefundLocktime: arklib.AbsoluteLocktime(timeouts.Refund),
		UnilateralClaimDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralClaim),
		),
		UnilateralRefundDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralRefund),
		),
		UnilateralRefundWithoutReceiverDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralRefundWithoutReceiver),
		),
	})
	require.NoError(t, err)
	require.Equal(t, createResp.LockupDetails.LockupAddress, vhtlcContract.Address,
		"locally derived vhtlc address must match Boltz's")
	require.NoError(t, contractManager.ImportContract(ctx, *vhtlcContract))

	seedSwapRecord(t, datadir, swaptypes.Swap{
		Id:          createResp.Id,
		From:        boltz.CurrencyArk,
		To:          boltz.CurrencyBtc,
		CreatedAt:   time.Now(),
		Status:      int(swap.SwapStatusPending),
		VHTLCScript: vhtlcContract.Script,
		Amount:      amount,
		ChainSwap: &swaptypes.ChainSwapInfo{
			Address:            createResp.ClaimDetails.LockupAddress,
			PrivateKey:         hex.EncodeToString(claimKey.Serialize()),
			DestinationAddress: btcAddress,
			ServerPublicKey:    createResp.ClaimDetails.ServerPublicKey,
			RefundLocktime:     uint32(createResp.ClaimDetails.TimeoutBlockHeight),
		},
	})

	// Fund the Arkade vhtlc: this triggers Boltz to lock up the BTC.
	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{
		{To: createResp.LockupDetails.LockupAddress, Amount: amount},
	})
	require.NoError(t, err)

	return boltzChainSwap{
		id:         createResp.Id,
		btcAddress: btcAddress,
	}
}

// createFailedBoltzChainSwap creates an Arkade -> BTC chain swap directly against the Boltz API
// and funds its Arkade vhtlc with less than the expected amount, so Boltz fails the lockup. It
// seeds no local swap record and imports no contract: the caller restores from the wallet seed
// and lets the restore reconstruct the swap and its vhtlc. Returns the swap id.
func createFailedBoltzChainSwap(
	t *testing.T, ctx context.Context, alice sdk.Wallet, boltzSvc *boltz.Api, amount uint64,
) string {
	t.Helper()

	// Our wallet key plays the refund (sender) role in the Arkade vhtlc; the claim key is the
	// ephemeral key that would have claimed the BTC side.
	keyId, err := alice.Identity().NextKeyId(ctx, "")
	require.NoError(t, err)
	keyRef, err := alice.Identity().GetKey(ctx, keyId)
	require.NoError(t, err)

	claimKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	preimage, _ := newPreimage(t)
	shaHash, _ := preimage.Hash()

	createResp, err := boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		PreimageHash:    hex.EncodeToString(shaHash),
		ClaimPublicKey:  hex.EncodeToString(claimKey.PubKey().SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		UserLockAmount:  amount,
	})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.Id)

	// Underfund the Arkade lockup: Boltz observes the amount mismatch and fails the swap, leaving
	// the vhtlc we partially funded to be refunded.
	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{
		{To: createResp.LockupDetails.LockupAddress, Amount: amount - 100},
	})
	require.NoError(t, err)
	time.Sleep(5 * time.Second)

	return createResp.Id
}

// swapResult carries the outcome of a swap performed in a goroutine by the concurrency tests.
type swapResult struct {
	swap *swaptypes.Swap
	err  error
}

// setupSwapWallet is like setupClient but returns also the wallet datadir, needed to open the
// swap store the SwapManager persists to.
// setupSwapWallet initializes a wallet against the test server. An empty seed generates a new
// one; passing an existing seed restores that wallet into a fresh datadir (empty swap and
// contract stores), as on a new device.
func setupSwapWallet(t *testing.T, seed string) (sdk.Wallet, string) {
	t.Helper()

	datadir := t.TempDir()
	arkClient, err := sdk.NewWallet(datadir)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, seed, password)
	require.NoError(t, err)

	err = arkClient.Unlock(t.Context(), password)
	require.NoError(t, err)

	synced := <-arkClient.IsSynced(t.Context())
	require.Nil(t, synced.Err)
	require.True(t, synced.Synced)

	t.Cleanup(arkClient.Stop)

	return arkClient, datadir
}

func setupSwapManager(t *testing.T, wallet sdk.Wallet) *swap.SwapManager {
	t.Helper()

	boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}
	manager, err := swap.NewSwapManager(
		wallet, boltzSvc,
		swap.WithLnSwapTimeout(300*time.Second), swap.WithChainSwapTimeout(300*time.Second),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		// nolint
		manager.Close()
	})

	return manager
}

// awaitPersistedSwap polls the manager until the swap with the given id reaches a terminal
// status, and requires it to be the wanted one. The persisted swap is the safe observation
// point for the swaps completed in background by the manager.
func awaitPersistedSwap(
	t *testing.T, manager *swap.SwapManager, id string, want swap.SwapStatus,
) *swaptypes.Swap {
	t.Helper()

	var persisted *swaptypes.Swap
	require.Eventually(t, func() bool {
		record, err := manager.GetSwap(context.Background(), id)
		if err != nil || record.Status == int(swap.SwapStatusPending) {
			return false
		}
		persisted = record
		return true
	}, 240*time.Second, 2*time.Second, "swap %s never left pending status", id)

	require.Equal(t, int(want), persisted.Status)
	return persisted
}

// seedSwapRecord adds a swap to the store persisted in the given datadir. The store is opened
// and closed within the helper so it can be used before creating the SwapManager.
func seedSwapRecord(t *testing.T, datadir string, record swaptypes.Swap) {
	t.Helper()

	store, err := swapstore.NewService(datadir)
	require.NoError(t, err)
	defer func() {
		// nolint
		store.Close()
	}()

	require.NoError(t, store.Swaps().Add(context.Background(), record))
}

func createReverseSwapWithRetry(
	ctx context.Context, manager *swap.SwapManager, amount uint64,
) (*swaptypes.Swap, error) {
	const attempts = 5

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		reverseSwap, err := manager.ReverseSwap(ctx, amount)
		if err == nil {
			return reverseSwap, nil
		}

		lastErr = err
		if !isBoltzSerializationAbort(err) || attempt == attempts-1 {
			return nil, err
		}

		backoff := time.Duration(attempt+1) * 400 * time.Millisecond
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	return nil, lastErr
}

func isBoltzSerializationAbort(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "could not serialize access") ||
		strings.Contains(msg, "read/write dependencies among transactions")
}

func boltzRelativeLocktime(value uint32) arklib.RelativeLocktime {
	if value >= 512 {
		return arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: value}
	}
	return arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: value}
}

func parseBoltzPubkey(pubkey string) (*btcec.PublicKey, error) {
	decoded, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	if len(decoded) == schnorr.PubKeyBytesLen {
		return schnorr.ParsePubKey(decoded)
	}
	return btcec.ParsePubKey(decoded)
}

// settleBoltzFulmine ensures boltz-fulmine has settled VTXOs available.
// Without this, swept/expired VTXOs cause "missing vtxos" errors on Boltz.
func settleBoltzFulmine(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(boltzFulmineUrl + "/settle")
	if err != nil {
		return
	}
	// nolint
	resp.Body.Close()
	generateBlocks(t, 1)
}

// boltzSubmarineSwap holds the pieces of a submarine swap created directly against the Boltz
// API, needed to fund and refund it.
type boltzSubmarineSwap struct {
	id          string
	address     string
	expectedAmt uint64
	vhtlcScript string
}

// createBoltzSubmarineSwap creates a submarine swap directly against the Boltz API (bypassing
// the SwapManager), imports the resulting vhtlc contract into alice's wallet and seeds a pending
// swap record in the swap store at datadir. Underfunding and manager creation are left to the
// caller so it controls their ordering relative to the manager's startup recovery.
func createBoltzSubmarineSwap(
	t *testing.T, ctx context.Context, alice sdk.Wallet, datadir string, boltzSvc *boltz.Api,
) boltzSubmarineSwap {
	t.Helper()

	// Create an LND invoice (we need the rHash for VHTLC derivation)
	invoice, rHash, err := lndAddInvoiceWithHash(5000)
	require.NoError(t, err)
	require.NotEmpty(t, invoice)

	rHashBytes, err := hex.DecodeString(rHash)
	require.NoError(t, err)
	preimageHash := input.Ripemd160H(rHashBytes)

	// Reserve a wallet key to play the sender role in the VHTLC
	keyId, err := alice.Identity().NextKeyId(ctx, "")
	require.NoError(t, err)
	keyRef, err := alice.Identity().GetKey(ctx, keyId)
	require.NoError(t, err)

	// Create submarine swap directly via Boltz API
	createResp, err := boltzSvc.CreateSwap(boltz.CreateSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		Invoice:         invoice,
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		PaymentTimeout:  120,
	})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.Address)
	require.Greater(t, createResp.ExpectedAmount, uint64(100))

	// Parse Boltz's claim public key (the receiver in the VHTLC)
	receiverPub, err := parseBoltzPubkey(createResp.ClaimPublicKey)
	require.NoError(t, err)

	// The swap was created directly with Boltz rather than through the SwapManager, so the
	// resulting vhtlc contract must be imported into the contract manager for the wallet to
	// be able to sign for it.
	contractManager := alice.ContractManager()
	vhtlcHandler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	require.NoError(t, err)
	vhtlcContract, err := vhtlcHandler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:    keyId,
		Sender:         keyRef.PubKey,
		Receiver:       receiverPub,
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(createResp.TimeoutBlockHeights.RefundLocktime),
		UnilateralClaimDelay: boltzRelativeLocktime(
			createResp.TimeoutBlockHeights.UnilateralClaim,
		),
		UnilateralRefundDelay: boltzRelativeLocktime(
			createResp.TimeoutBlockHeights.UnilateralRefund,
		),
		UnilateralRefundWithoutReceiverDelay: boltzRelativeLocktime(
			createResp.TimeoutBlockHeights.UnilateralRefundWithoutReceiver,
		),
	})
	require.NoError(t, err)
	require.Equal(
		t, createResp.Address, vhtlcContract.Address,
		"locally derived VHTLC address must match Boltz's",
	)
	require.NoError(t, contractManager.ImportContract(ctx, *vhtlcContract))

	// Persist the swap so the manager can look it up by id. Done before creating the manager,
	// which opens its own connection to the same store.
	seedSwapRecord(t, datadir, swaptypes.Swap{
		Id:          createResp.Id,
		From:        boltz.CurrencyArk,
		To:          boltz.CurrencyBtc,
		CreatedAt:   time.Now(),
		Status:      int(swap.SwapStatusPending),
		VHTLCScript: vhtlcContract.Script,
		Amount:      createResp.ExpectedAmount,
		LNSwap: &swaptypes.LNSwapInfo{
			Invoice:      invoice,
			PreimageHash: preimageHash,
		},
	})

	return boltzSubmarineSwap{
		id:          createResp.Id,
		address:     createResp.Address,
		expectedAmt: createResp.ExpectedAmount,
		vhtlcScript: vhtlcContract.Script,
	}
}

// underfundAndWaitLockupFailed funds the swap lockup with less than the expected amount and
// waits for Boltz to observe it and mark the swap as failed.
func underfundAndWaitLockupFailed(
	t *testing.T, ctx context.Context, alice sdk.Wallet, sw boltzSubmarineSwap,
) {
	t.Helper()
	_, err := alice.SendOffChain(ctx, []clientTypes.Receiver{
		{To: sw.address, Amount: sw.expectedAmt - 100},
	})
	require.NoError(t, err)
	time.Sleep(5 * time.Second)
}

// requireVHTLCSpentBy asserts the vhtlc vtxo identified by the given script has been spent by
// the given ark tx.
func requireVHTLCSpentBy(t *testing.T, alice sdk.Wallet, vhtlcScript, arkTxid string) {
	t.Helper()
	pkScript, err := hex.DecodeString(vhtlcScript)
	require.NoError(t, err)
	vtxos, err := getVHTLCFunds(t, alice, pkScript)
	require.NoError(t, err)
	require.NotEmpty(t, vtxos)
	require.True(t, vtxos[0].Spent)
	require.Equal(t, arkTxid, vtxos[0].ArkTxid)
}

// boltzBtcToArkadeChainSwap holds the pieces of a BTC -> Arkade chain swap created directly
// against the Boltz API, needed to drive and assert its recovery or refund.
type boltzBtcToArkadeChainSwap struct {
	id          string
	btcAddress  string
	fundingTxid string
	vhtlcScript string
}

// createBoltzBtcToArkadeChainSwap creates a BTC -> Arkade chain swap directly against the Boltz
// API (bypassing the SwapManager), imports the Arkade vhtlc (we are its receiver), funds the
// BTC lockup address with fundAmount sats (confirmed with a block) and then seeds a pending
// swap record: the record carries the funding txid, so it can only be written after funding.
// Funding less than the swap amount makes Boltz fail the lockup, leaving the BTC to be
// refunded.
func createBoltzBtcToArkadeChainSwap(
	t *testing.T, ctx context.Context, alice sdk.Wallet, datadir string, boltzSvc *boltz.Api,
	amount, fundAmount uint64,
) boltzBtcToArkadeChainSwap {
	t.Helper()

	// Our wallet key plays the claim (receiver) role in the Arkade vhtlc; the refund key of
	// the BTC HTLC is ephemeral.
	keyId, err := alice.Identity().NextKeyId(ctx, "")
	require.NoError(t, err)
	keyRef, err := alice.Identity().GetKey(ctx, keyId)
	require.NoError(t, err)

	refundKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	// Derive the preimage deterministically from the receiver key exactly like the manager
	// does: the swap record is seeded without it, so the recovery and the refund must
	// re-derive it.
	signer, ok := alice.Identity().(swap.PreimageSigner)
	require.True(t, ok, "the wallet identity must support preimage derivation")
	preimage, err := swap.DerivePreimage(ctx, signer, *keyRef)
	require.NoError(t, err)
	shaHash, hash160 := preimage.Hash()

	createResp, err := boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyBtc,
		To:              boltz.CurrencyArk,
		PreimageHash:    hex.EncodeToString(shaHash),
		ClaimPublicKey:  hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(refundKey.PubKey().SerializeCompressed()),
		UserLockAmount:  amount,
	})
	require.NoError(t, err)
	require.NotNil(t, createResp.ClaimDetails.Timeouts)

	senderPub, err := parseBoltzPubkey(createResp.ClaimDetails.ServerPublicKey)
	require.NoError(t, err)

	timeouts := createResp.ClaimDetails.Timeouts
	contractManager := alice.ContractManager()
	vhtlcHandler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	require.NoError(t, err)
	vhtlcContract, err := vhtlcHandler.NewContract(ctx, vhtlchandler.ContractArgs{
		Sender:         senderPub,
		ReceiverKeyId:  keyId,
		Receiver:       keyRef.PubKey,
		PreimageHash:   hash160,
		RefundLocktime: arklib.AbsoluteLocktime(timeouts.Refund),
		UnilateralClaimDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralClaim),
		),
		UnilateralRefundDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralRefund),
		),
		UnilateralRefundWithoutReceiverDelay: boltzRelativeLocktime(
			uint32(timeouts.UnilateralRefundWithoutReceiver),
		),
	})
	require.NoError(t, err)
	require.Equal(t, createResp.ClaimDetails.LockupAddress, vhtlcContract.Address,
		"locally derived vhtlc address must match Boltz's")
	require.NoError(t, contractManager.ImportContract(ctx, *vhtlcContract))

	// Fund the BTC HTLC lockup address onchain and confirm it.
	btcAddress := createResp.LockupDetails.LockupAddress
	fundingTxid, err := runCommand(
		"nigiri", "rpc", "sendtoaddress", btcAddress,
		fmt.Sprintf("%.8f", float64(fundAmount)/1e8),
	)
	require.NoError(t, err)
	fundingTxid = strings.TrimSpace(fundingTxid)
	require.NotEmpty(t, fundingTxid)
	generateBlocks(t, 1)

	seedSwapRecord(t, datadir, swaptypes.Swap{
		Id:          createResp.Id,
		From:        boltz.CurrencyBtc,
		To:          boltz.CurrencyArk,
		CreatedAt:   time.Now(),
		Status:      int(swap.SwapStatusPending),
		VHTLCScript: vhtlcContract.Script,
		Amount:      amount,
		ChainSwap: &swaptypes.ChainSwapInfo{
			FundingTxid:     fundingTxid,
			Address:         btcAddress,
			PrivateKey:      hex.EncodeToString(refundKey.Serialize()),
			ServerPublicKey: createResp.LockupDetails.ServerPublicKey,
			RefundLocktime:  uint32(createResp.LockupDetails.TimeoutBlockHeight),
		},
	})

	return boltzBtcToArkadeChainSwap{
		id:          createResp.Id,
		btcAddress:  btcAddress,
		fundingTxid: fundingTxid,
		vhtlcScript: vhtlcContract.Script,
	}
}
