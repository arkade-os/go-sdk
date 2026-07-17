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
	defer cancel()

	swapResult, err := manager.PayInvoice(ctx, invoice)
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
	defer cancel()

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
	defer cancel()

	reverseSwap, err := manager.ReverseSwap(ctx, 3000)
	require.NoError(t, err)
	require.NotEmpty(t, reverseSwap.Id)
	require.NotNil(t, reverseSwap.LNSwap)
	require.NotEmpty(t, reverseSwap.LNSwap.Invoice)

	payResult, err := manager.PayInvoice(ctx, reverseSwap.LNSwap.Invoice)
	require.NoError(t, err)
	require.NotNil(t, payResult)
	require.Equal(t, int(swap.SwapStatusSuccess), payResult.Status)

	persisted := awaitPersistedSwap(t, manager, reverseSwap.Id, swap.SwapStatusSuccess)
	require.NotEmpty(t, persisted.RedeemTxid)
}

// TestConcurrentSwaps exercises multiple simultaneous swap operations to test the swap
// manager's concurrency. It runs parallel submarine and reverse swaps.
func TestConcurrentSwaps(t *testing.T) {
	// PayInvoice returns a nil error also when the swap fails and is refunded or times out:
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
				s, err := manager.PayInvoice(ctx, invoice)
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
			s, err := manager.PayInvoice(ctx, invoice)
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

// TestRefundSwap tests the cooperative refund path for an underfunded submarine swap.
//
// Flow:
//  1. Create an LND invoice
//  2. Create a submarine swap via Boltz API directly (not through the SwapManager)
//  3. Derive VHTLC opts from Boltz's response and verify address match
//  4. Import the vhtlc contract and persist the swap so the manager can refund it
//  5. Underfund the swap (send less than expectedAmount)
//  6. Wait for Boltz to mark the swap as failed (lockupFailed)
//  7. Call manager.RefundSwap: Boltz co-signs the refund
func TestRefundSwap(t *testing.T) {
	settleBoltzFulmine(t)
	alice, datadir := setupSwapWallet(t)
	faucetOffchain(t, alice, 0.001) // 100,000 sats

	balanceBefore, err := alice.Balance(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Second)
	defer cancel()

	boltzSvc := &boltz.Api{URL: boltzUrl, WSURL: boltzWsUrl}

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

	manager := setupSwapManager(t, alice)

	// Underfund the swap — send less than expectedAmount
	underfundAmount := createResp.ExpectedAmount - 100
	_, err = alice.SendOffChain(ctx, []clientTypes.Receiver{
		{To: createResp.Address, Amount: underfundAmount},
	})
	require.NoError(t, err)

	// Wait for Boltz to observe the underfunded lockup and mark the swap as failed
	time.Sleep(5 * time.Second)

	refundedSwap, scheduledAt, err := manager.RefundSwap(ctx, createResp.Id)
	require.NoError(t, err, "cooperative refund of an underfunded submarine swap should succeed")
	require.Nil(t, scheduledAt, "refund should happen collaboratively, not be scheduled")
	require.NotNil(t, refundedSwap)
	require.NotEmpty(t, refundedSwap.RedeemTxid)

	// The refunded swap is persisted as failed, with the refund txid set.
	persisted, err := manager.GetSwap(ctx, createResp.Id)
	require.NoError(t, err)
	require.Equal(t, int(swap.SwapStatusFailed), persisted.Status)
	require.Equal(t, refundedSwap.RedeemTxid, persisted.RedeemTxid)

	time.Sleep(2 * time.Second)

	// Verify the vhtlc vtxo has been spent by the refund tx.
	pkScript, err := hex.DecodeString(vhtlcContract.Script)
	require.NoError(t, err)
	vtxos, err := getVHTLCFunds(t, alice, pkScript)
	require.NoError(t, err)
	require.NotEmpty(t, vtxos)
	require.True(t, vtxos[0].Spent)
	require.Equal(t, refundedSwap.RedeemTxid, vtxos[0].ArkTxid)

	// Verify balance is preserved (the underfunded amount came back).
	balanceAfter, err := alice.Balance(t.Context())
	require.NoError(t, err)
	require.Equal(t, balanceBefore.OffchainBalance.Total, balanceAfter.OffchainBalance.Total,
		"offchain balance should be preserved after the refund")
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
	defer cancel()

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
