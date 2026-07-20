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
	alice, datadir := setupSwapWallet(t)
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

// TestRecoverPendingSwaps exercises the recovery a SwapManager runs at startup for the swaps a
// previous run left behind.
func TestRecoverPendingSwaps(t *testing.T) {
	// A submarine swap we funded that failed while no manager was running must be refunded by
	// the recovery, without any manual intervention.
	t.Run("refunds a failed submarine swap on startup", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t)
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
	t.Run("claims a funded reverse swap left pending on shutdown", func(t *testing.T) {
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
	t.Run("claims a chain swap left pending on shutdown", func(t *testing.T) {
		settleBoltzFulmine(t)
		alice, datadir := setupSwapWallet(t)
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

	preimage, hash160 := newPreimage(t)
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
	require.NotNil(t, createResp.LockupDetails.Timeouts)

	receiverPub, err := parseBoltzPubkey(createResp.LockupDetails.ServerPublicKey)
	require.NoError(t, err)

	timeouts := createResp.LockupDetails.Timeouts
	contractManager := alice.ContractManager()
	vhtlcHandler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	require.NoError(t, err)
	vhtlcContract, err := vhtlcHandler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:                          keyId,
		Sender:                               keyRef.PubKey,
		Receiver:                             receiverPub,
		PreimageHash:                         hash160,
		RefundLocktime:                       arklib.AbsoluteLocktime(timeouts.Refund),
		UnilateralClaimDelay:                 boltzRelativeLocktime(uint32(timeouts.UnilateralClaim)),
		UnilateralRefundDelay:                boltzRelativeLocktime(uint32(timeouts.UnilateralRefund)),
		UnilateralRefundWithoutReceiverDelay: boltzRelativeLocktime(uint32(timeouts.UnilateralRefundWithoutReceiver)),
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
		Preimage:    preimage,
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

// TestChainSwapArkToBtc exercises the Ark-to-BTC chain swap flow using real Boltz:
// the manager funds a VHTLC, Boltz locks up BTC on-chain and the manager claims it to the
// destination address. The completion is observed through the persisted swap.
func TestChainSwapArkToBtc(t *testing.T) {
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
}

// swapResult carries the outcome of a swap performed in a goroutine by the concurrency tests.
type swapResult struct {
	swap *swaptypes.Swap
	err  error
}

// setupSwapWallet is like setupClient but returns also the wallet datadir, needed to open the
// swap store the SwapManager persists to.
func setupSwapWallet(t *testing.T) (sdk.Wallet, string) {
	t.Helper()

	datadir := t.TempDir()
	arkClient, err := sdk.NewWallet(datadir)
	require.NoError(t, err)

	err = arkClient.Init(t.Context(), serverUrl, "", password)
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
	manager, err := swap.NewSwapManager(wallet, boltzSvc, swap.WithTimeout(300*time.Second))
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
