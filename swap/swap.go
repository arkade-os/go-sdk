package swap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	arksdk "github.com/arkade-os/go-sdk"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/contract/handlers"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	gocronscheduler "github.com/arkade-os/go-sdk/swap/scheduler/gocron"
	"github.com/arkade-os/go-sdk/swap/store"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/psbt"

	log "github.com/sirupsen/logrus"
)

const (
	SwapStatusUndefined SwapStatus = iota
	SwapStatusPending
	SwapStatusSuccess
	SwapStatusFailed

	SwapTypeSubmarine = "submarine"
	SwapTypeReverse   = "reverse"
	SwapTypeChain     = "chain"

	boltzReconnectBackoff = time.Second
)

var ErrorNoVtxosFound = fmt.Errorf("no vtxos found for the given vhtlc opts")

type SwapStatus int

type SwapManager struct {
	wallet       arksdk.Wallet
	boltzSvc     *boltz.Api
	store        swaptypes.Store
	schedulerSvc swaptypes.Scheduler
	swapTimeout  time.Duration
	config       clientTypes.Config
	// contractMu serializes the key-reservation → ImportContract span across
	// concurrent swap creations: getNewKey derives the next key from the
	// latest persisted contract, so it must not run again until the previous
	// contract has been imported (with deterministic preimages, a reused key
	// also means a duplicate payment hash rejected by Boltz).
	contractMu sync.Mutex

	// ctx is the manager's lifetime context: Close cancels it to abort the background
	// operations (reverse-swap claim, chain-swap monitoring, startup recovery), and bgWg lets
	// Close wait for them to exit before the store is closed.
	ctx    context.Context
	cancel context.CancelFunc
	bgWg   sync.WaitGroup
}

func NewSwapManager(
	wallet arksdk.Wallet, boltzSvc *boltz.Api, opts ...Option,
) (*SwapManager, error) {
	if wallet == nil {
		return nil, fmt.Errorf("missing wallet")
	}
	if boltzSvc == nil {
		return nil, fmt.Errorf("missing boltz client")
	}
	// The manager derives keys, signs and claims/refunds vhtlcs: it can't work with a locked
	// wallet.
	if wallet.IsLocked(context.Background()) {
		return nil, fmt.Errorf("wallet must be unlocked")
	}
	o, err := applyOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid option(s): %w", err)
	}

	if o.verbose {
		log.SetLevel(log.DebugLevel)
	}

	cfg, err := wallet.GetConfigData(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get config data: %w", err)
	}
	walletStoreConfig := wallet.Store().GetConfig()

	var datadir string
	switch walletStoreConfig.StoreType {
	case types.SQLStore:
		var ok bool
		datadir, ok = walletStoreConfig.Args.(string)
		if !ok {
			return nil, fmt.Errorf(
				"invalid config args for sqlite store: expected string datadir, got %T",
				walletStoreConfig.Args,
			)
		}
	default:
		return nil, fmt.Errorf("unknown wallet store type: %s", walletStoreConfig.StoreType)
	}

	store, err := store.NewService(datadir)
	if err != nil {
		return nil, fmt.Errorf("failed to init swap store: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &SwapManager{
		wallet:       wallet,
		boltzSvc:     boltzSvc,
		store:        store,
		schedulerSvc: gocronscheduler.NewScheduler(wallet.Explorer(), o.pollInterval),
		swapTimeout:  o.timeout,
		config:       *cfg,
		ctx:          ctx,
		cancel:       cancel,
	}
	// The scheduler drives the delayed unilateral refunds, it must run for the whole lifetime
	// of the manager.
	h.schedulerSvc.Start()

	// Restore the swaps known to Boltz if the store is empty (ie. after a wallet restore),
	// then terminate the swaps left in flight, without blocking the constructor.
	h.bgWg.Go(func() {
		h.restoreSwaps(h.ctx)
		h.recoverPendingSwaps(h.ctx)
	})

	return h, nil
}

// Close aborts all background operations and releases the manager's resources. It's safe to
// call more than once.
func (h *SwapManager) Close() error {
	if h.cancel != nil {
		h.cancel()
	}
	// Wait for the background operations to notice the cancellation and exit before tearing
	// down the scheduler and the store they use.
	h.waitForBackground(5 * time.Second)

	if h.schedulerSvc != nil {
		h.schedulerSvc.Stop()
	}
	if h.store == nil {
		return nil
	}
	return h.store.Close()
}

func (h *SwapManager) waitForBackground(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		h.bgWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Warn("timed out waiting for swap manager background operations to exit")
	}
}

// GetSwap returns the swap with the given id from the store. It's the way to observe the
// status of the swaps completed in background, like reverse and chain ones.
func (h *SwapManager) GetSwap(ctx context.Context, swapId string) (*swaptypes.Swap, error) {
	return h.store.Swaps().Get(ctx, swapId)
}

func (h *SwapManager) SubmarineSwap(
	ctx context.Context, invoice string,
) (*swaptypes.Swap, error) {
	inv := invoice
	// Decode the offer to get the amount
	if IsBolt12Offer(invoice) {
		decodedOffer, err := DecodeBolt12Offer(invoice)
		if err != nil {
			return nil, fmt.Errorf("failed to decode offer: %v", err)
		}

		amountInSats := decodedOffer.AmountInSats
		if amountInSats == 0 {
			return nil, fmt.Errorf("offer amount must be greater than 0")
		}

		response, err := h.boltzSvc.FetchBolt12Invoice(boltz.FetchBolt12InvoiceRequest{
			Offer:  invoice,
			Amount: amountInSats,
			Note:   decodedOffer.DescriptionStr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to fetch invoice: %v", err)
		}
		if response.Error != "" {
			return nil, fmt.Errorf("failed to fetch invoice: %s", response.Error)
		}
		inv = response.Invoice
	}

	return h.submarineSwap(ctx, inv)
}

func (h *SwapManager) ReverseSwap(ctx context.Context, amount uint64) (*swaptypes.Swap, error) {
	return h.reverseSwap(ctx, amount)
}

func (h *SwapManager) RefundSubmarineSwap(
	ctx context.Context, swapId string,
) (*swaptypes.Swap, *time.Time, error) {
	swap, err := h.store.Swaps().Get(ctx, swapId)
	if err != nil {
		return nil, nil, err
	}

	contractArgs, err := h.getSwapContractArgs(ctx, swap)
	if err != nil {
		return nil, nil, err
	}

	return h.refundSwap(ctx, swap, contractArgs)
}

// getSwapContractArgs returns the vhtlc contract args of the given swap, resolving its contract
// from the contract manager by the swap's vhtlc script.
func (h *SwapManager) getSwapContractArgs(
	ctx context.Context, swap *swaptypes.Swap,
) (vhtlchandler.ContractArgs, error) {
	var empty vhtlchandler.ContractArgs

	scripts := []string{swap.VHTLCScript}
	contracts, err := h.wallet.ContractManager().GetContracts(ctx, contract.WithScripts(scripts))
	if err != nil {
		return empty, fmt.Errorf(
			"failed to get vhtlc contract %s for swap %s: %w", scripts[0], swap.Id, err,
		)
	}
	if len(contracts) <= 0 {
		return empty, fmt.Errorf("vhtlc contract %s not found for swap %s", scripts[0], swap.Id)
	}
	contract := contracts[0]

	handler, err := h.wallet.ContractManager().GetHandler(ctx, contract)
	if err != nil {
		return empty, fmt.Errorf("failed to get contract handler for swap %s: %w", swap.Id, err)
	}
	args, err := handler.GetArgs(contract)
	if err != nil {
		return empty, fmt.Errorf("failed to get contract args for swap %s: %w", swap.Id, err)
	}
	parsed, ok := args.(vhtlchandler.ContractArgs)
	if !ok {
		return empty, fmt.Errorf(
			"invalid contract args type: got %T, expected %T", args, vhtlchandler.ContractArgs{},
		)
	}
	return parsed, nil
}

func (h *SwapManager) submarineSwap(ctx context.Context, invoice string) (*swaptypes.Swap, error) {
	var preimageHash []byte
	if IsBolt12Invoice(invoice) {
		decodedInvoice, err := DecodeBolt12Invoice(invoice)
		if err != nil {
			return nil, fmt.Errorf("failed to decode bolt12 invoice: %v", err)
		}
		preimageHash = decodedInvoice.PaymentHash160
	} else {
		_, hash, _, err := decodeInvoice(invoice)
		if err != nil {
			return nil, fmt.Errorf("failed to decode invoice: %v", err)
		}
		preimageHash = hash
	}

	contractManager := h.wallet.ContractManager()
	handler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	if err != nil {
		return nil, err
	}

	h.contractMu.Lock()
	unlockContractMu := sync.OnceFunc(h.contractMu.Unlock)
	defer unlockContractMu()

	keyRef, err := h.getNewKey(ctx, handler)
	if err != nil {
		return nil, err
	}

	// Create the swapResp
	swapResp, err := h.boltzSvc.CreateSwap(boltz.CreateSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		Invoice:         invoice,
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		PaymentTimeout:  uint32(h.swapTimeout.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request submarine swap: %v", err)
	}

	receiverPubkey, err := parsePubkey(swapResp.ClaimPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid claim pubkey: %v", err)
	}

	contract, err := handler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:           keyRef.Id,
		Sender:                keyRef.PubKey,
		Receiver:              receiverPubkey,
		PreimageHash:          preimageHash,
		RefundLocktime:        arklib.AbsoluteLocktime(swapResp.TimeoutBlockHeights.RefundLocktime),
		UnilateralClaimDelay:  parseLocktime(swapResp.TimeoutBlockHeights.UnilateralClaim),
		UnilateralRefundDelay: parseLocktime(swapResp.TimeoutBlockHeights.UnilateralRefund),
		UnilateralRefundWithoutReceiverDelay: parseLocktime(
			swapResp.TimeoutBlockHeights.UnilateralRefundWithoutReceiver,
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify vHTLC: %v", err)
	}

	if swapResp.Address != contract.Address {
		return nil, fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			contract.Address, swapResp.Address,
		)
	}

	args, err := handler.GetArgs(*contract)
	if err != nil {
		return nil, fmt.Errorf("failed to get contract args for swap %s: %w", swapResp.Id, err)
	}
	parsed, ok := args.(vhtlchandler.ContractArgs)
	if !ok {
		return nil, fmt.Errorf(
			"invalid contract args type for swap %s: got %T, expected %T",
			swapResp.Id, args, vhtlchandler.ContractArgs{},
		)
	}

	if err := contractManager.ImportContract(ctx, *contract); err != nil {
		return nil, err
	}
	unlockContractMu()

	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swapResp.Id}, 5*time.Second); err != nil {
		return nil, err
	}

	receivers := []clientTypes.Receiver{{To: swapResp.Address, Amount: swapResp.ExpectedAmount}}
	var txid string
	// Fund the VHTLC
	if err := retry(ctx, 200*time.Millisecond, func(ctx context.Context) (bool, error) {
		var err error
		txid, err = h.wallet.SendOffChain(ctx, receivers)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "vtxo_already_spent") {
				return false, nil
			}
			return true, fmt.Errorf("failed to pay to vHTLC address: %v", err)
		}
		return true, nil
	}); err != nil {
		log.WithError(err).Error("failed to pay to vHTLC address")
		return nil, fmt.Errorf("something went wrong, please retry")
	}

	swap := &swaptypes.Swap{
		Id:          swapResp.Id,
		From:        boltz.CurrencyArk,
		To:          boltz.CurrencyBtc,
		CreatedAt:   time.Now(),
		Status:      int(SwapStatusPending),
		VHTLCScript: contract.Script,
		Amount:      swapResp.ExpectedAmount,
		FundingTxid: txid,
		LNSwap: &swaptypes.LNSwapInfo{
			Invoice:      invoice,
			PreimageHash: preimageHash,
		},
	}
	if err := h.persistSwap(ctx, *swap); err != nil {
		return nil, err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, h.swapTimeout)
	defer cancel()
	ctx = timeoutCtx

	for {
		select {
		case update, ok := <-ws.Updates:
			if !ok {
				nextWs, err := h.reconnectBoltzWebsocket(ctx, ws, swapResp.Id)
				if err != nil {
					return nil, err
				}
				if nextWs == nil {
					continue
				}
				ws = nextWs
				continue
			}

			switch boltz.ParseEvent(update.Status) {
			case boltz.TransactionLockupFailed, boltz.InvoiceFailedToPay:
				updatedSwap, _, err := h.refundSwap(context.Background(), swap, parsed)
				if err != nil {
					log.WithError(err).Errorf(
						"submarine swap %s failed with status %s and we failed to refund it",
						swapResp.Id, update.Status,
					)
					return nil, err
				}
				return updatedSwap, nil
			case boltz.TransactionClaimed, boltz.InvoiceSettled:
				swap.Status = int(SwapStatusSuccess)
				swap.RedeemTxid = update.Transaction.Id
				if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
					return nil, err
				}

				return swap, nil
			}
		case <-ctx.Done():
			swap.Status = int(SwapStatusFailed)
			if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
				return nil, err
			}
			go func() {
				log.Debugf(
					"process aborted while waiting for updates for swap %s, "+
						"trying to schedule a unilrateral refund before aborting...", swapResp.Id,
				)
				if err := h.scheduleUnilateralRefund(ctx, swap, parsed.RefundLocktime); err != nil {
					log.WithError(err).Errorf(
						"failed to schedule refund of swap %s unilaterally", swapResp.Id,
					)
				}
			}()

			return swap, nil
		}
	}

}

func (h *SwapManager) reverseSwap(ctx context.Context, amount uint64) (*swaptypes.Swap, error) {
	contractManager := h.wallet.ContractManager()
	keyProvider := h.wallet.Identity()
	handler, err := contractManager.Registry().GetHandler(types.ContractTypeVHTLC)
	if err != nil {
		return nil, err
	}

	h.contractMu.Lock()
	unlockContractMu := sync.OnceFunc(h.contractMu.Unlock)
	defer unlockContractMu()

	keyRef, err := h.getNewKey(ctx, handler)
	if err != nil {
		return nil, err
	}

	// If the identity supports schnorr signing, use it to generate a deterministic preimage,
	// otherwise use a random preimage
	schnorrSigner, ok := keyProvider.(PreimageSigner)
	persistPreimage := ok
	var preimage vhtlc.Preimage
	if ok {
		preimage, err = DerivePreimage(ctx, schnorrSigner, *keyRef)
		if err != nil {
			return nil, fmt.Errorf("failed to generate deterministic preimage: %w", err)
		}
	} else {
		preimage = make([]byte, 32)
		if _, err := rand.Read(preimage); err != nil {
			return nil, fmt.Errorf("failed to generate random preimage: %w", err)
		}
	}

	preimageHashSHA256, preimageHashHASH160 := preimage.Hash()

	swapResp, err := h.boltzSvc.CreateReverseSwap(boltz.CreateReverseSwapRequest{
		From:           boltz.CurrencyBtc,
		To:             boltz.CurrencyArk,
		InvoiceAmount:  amount,
		ClaimPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		PreimageHash:   hex.EncodeToString(preimageHashSHA256),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to make reverse submarine swap: %v", err)
	}

	// verify vHTLC
	senderPubkey, err := parsePubkey(swapResp.RefundPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid refund pubkey: %v", err)
	}

	// verify preimage hash and invoice amount
	invoiceAmount, gotPreimageHash, invoiceExpiry, err := decodeInvoice(swapResp.Invoice)
	if err != nil {
		return nil, fmt.Errorf("failed to decode invoice: %v", err)
	}

	if !bytes.Equal(preimageHashHASH160, gotPreimageHash) {
		return nil, fmt.Errorf(
			"invalid preimage hash: expected %x, got %x from Boltz",
			preimageHashHASH160, gotPreimageHash,
		)
	}
	if invoiceAmount != amount {
		return nil, fmt.Errorf(
			"invalid invoice amount: expected %d, got %d from Boltz", amount, invoiceAmount,
		)
	}

	contract, err := handler.NewContract(ctx, vhtlchandler.ContractArgs{
		Sender:                senderPubkey,
		ReceiverKeyId:         keyRef.Id,
		Receiver:              keyRef.PubKey,
		PreimageHash:          preimageHashHASH160,
		RefundLocktime:        arklib.AbsoluteLocktime(swapResp.TimeoutBlockHeights.RefundLocktime),
		UnilateralClaimDelay:  parseLocktime(swapResp.TimeoutBlockHeights.UnilateralClaim),
		UnilateralRefundDelay: parseLocktime(swapResp.TimeoutBlockHeights.UnilateralRefund),
		UnilateralRefundWithoutReceiverDelay: parseLocktime(
			swapResp.TimeoutBlockHeights.UnilateralRefundWithoutReceiver,
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify vHTLC: %v", err)
	}

	if swapResp.LockupAddress != contract.Address {
		return nil, fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			contract.Address, swapResp.LockupAddress,
		)
	}

	if err := contractManager.ImportContract(ctx, *contract); err != nil {
		return nil, err
	}
	unlockContractMu()

	swap := &swaptypes.Swap{
		Id:          swapResp.Id,
		From:        boltz.CurrencyBtc,
		To:          boltz.CurrencyArk,
		CreatedAt:   time.Now(),
		Status:      int(SwapStatusPending),
		VHTLCScript: contract.Script,
		Amount:      swapResp.OnchainAmount,
		LNSwap: &swaptypes.LNSwapInfo{
			Invoice:      swapResp.Invoice,
			PreimageHash: preimageHashHASH160,
		},
	}
	if persistPreimage {
		swap.Preimage = preimage
	}
	if err := h.persistSwap(ctx, *swap); err != nil {
		return nil, err
	}

	h.bgWg.Go(func() {
		txid, err := h.waitAndClaim(invoiceExpiry, swap, preimage)

		// If the manager is shutting down, leave the swap pending for the next startup's
		// recovery instead of marking it and writing to a store that's about to close.
		if h.ctx.Err() != nil {
			return
		}

		if err != nil {
			swap.Status = int(SwapStatusFailed)
			log.WithError(err).Error("failed to claim VHTLC")
		} else {
			swap.RedeemTxid = txid
			swap.Status = int(SwapStatusSuccess)
			log.Debugf("swap %s completed, claimed vhtlc with %s", swap.Id, txid)
		}

		if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
			log.WithError(err).Error("failed to update persisted reverse swap")
		}
	})
	return swap, nil
}

func (h *SwapManager) refundSwap(
	ctx context.Context, swap *swaptypes.Swap, contractArgs vhtlchandler.ContractArgs,
) (*swaptypes.Swap, *time.Time, error) {
	pubkeys := []*btcec.PublicKey{contractArgs.Sender, contractArgs.Receiver, contractArgs.Signer}

	// if withReceiver is enabled, boltz should sign the transactions
	updatedSwap, err := h.collaborativeRefund(ctx, *swap, pubkeys)
	if err == nil {
		return updatedSwap, nil, nil
	}

	log.WithError(err).Debugf(
		"failed to refund swap %s collaboratively, scheduling unilateral refund...", swap.Id,
	)
	if err := h.scheduleUnilateralRefund(ctx, swap, contractArgs.RefundLocktime); err != nil {
		return nil, nil, err
	}
	scheduledAt := time.Now().Add(time.Duration(contractArgs.RefundLocktime) * time.Second)
	return swap, &scheduledAt, nil
}

func (h *SwapManager) waitAndClaim(
	invoiceExpiry int, swap *swaptypes.Swap, preimage vhtlc.Preimage,
) (string, error) {
	expiryDuration := time.Duration(invoiceExpiry) * time.Second
	ctx, cancel := context.WithTimeout(h.ctx, expiryDuration*2)
	defer cancel()

	ws := h.boltzSvc.NewWebsocket()

	err := ws.ConnectAndSubscribe(ctx, []string{swap.Id}, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer func() { _ = ws.Close() }()

	var txid string
	for {
		select {
		case update, ok := <-ws.Updates:
			if !ok {
				nextWs, err := h.reconnectBoltzWebsocket(ctx, ws, swap.Id)
				if err != nil {
					return "", err
				}
				if nextWs == nil {
					continue
				}
				ws = nextWs
				continue
			}
			parsedStatus := boltz.ParseEvent(update.Status)

			confirmed := false
			switch parsedStatus {
			case boltz.TransactionMempool:
				confirmed = true
			case boltz.InvoiceFailedToPay, boltz.TransactionFailed, boltz.TransactionLockupFailed:
				return "", fmt.Errorf("failed to receive payment: %s", update.Status)
			}
			if confirmed {
				interval := 200 * time.Millisecond
				if err := retry(ctx, interval, func(ctx context.Context) (bool, error) {
					var err error
					txid, err = h.wallet.ClaimVHTLC(ctx, swap.VHTLCScript, preimage)
					if err != nil {
						return false, err
					}

					return true, nil
				}); err != nil {
					return "", err
				}
				return txid, nil
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
}

// collaborativeRefund attempts to refund a swap with Boltz cooperation.
// It first builds and signs the refund and checkpoint transactions, then asks boltz to sign and
// finally submits and finalizes the offchain tx with combined signatures.
func (h *SwapManager) collaborativeRefund(
	ctx context.Context, swap swaptypes.Swap, pubkeys []*btcec.PublicKey,
) (*swaptypes.Swap, error) {
	// Build and sign refund and checkpoint transactions.
	refundTx, checkpointTx, err := h.wallet.RefundVHTLC(ctx, swap.VHTLCScript)
	if err != nil {
		return nil, err
	}

	refundPtx, err := psbt.NewFromRawBytes(strings.NewReader(refundTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund tx: %w", err)
	}
	checkpointPtx, err := psbt.NewFromRawBytes(strings.NewReader(checkpointTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund checkpoint tx: %w", err)
	}

	refundTxid := refundPtx.UnsignedTx.TxID()

	// Get unsigned refund and checkpoint txs signed.
	_, unsignedRefundTx, err := stripTxSignatures(refundPtx)
	if err != nil {
		return nil, err
	}
	_, unsignedCheckpointTx, err := stripTxSignatures(checkpointPtx)
	if err != nil {
		return nil, err
	}

	// Ask Boltz to cosign the refund and checkpoint txs by providing their unsigned versions.
	requestRefund := h.boltzSvc.RefundChainSwap
	if swap.LNSwap != nil {
		requestRefund = h.boltzSvc.RefundSubmarine
	}
	refundResp, err := requestRefund(swap.Id, boltz.RefundSwapRequest{
		Transaction: unsignedRefundTx,
		Checkpoint:  unsignedCheckpointTx,
	})
	if err != nil {
		return nil, err
	}

	cosignedRefundPtx, err := psbt.NewFromRawBytes(strings.NewReader(refundResp.Transaction), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund tx signed by boltz: %s", err)
	}

	cosignedCheckpointPtx, err := psbt.NewFromRawBytes(
		strings.NewReader(refundResp.Checkpoint),
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund checkpoint tx signed by boltz: %s", err)
	}

	// Combine the signatures of the refund tx and submit the offchain tx to the server to get its
	// signatures. The checkpoint tx is sent unsigned here.
	_, signedRefundTx, err := combineTxSignatures(refundPtx, cosignedRefundPtx)
	if err != nil {
		return nil, err
	}

	_, finalRefundTx, serverSignedCheckpointTxs, err := h.wallet.Client().SubmitTx(
		ctx, signedRefundTx, []string{unsignedCheckpointTx},
	)
	if err != nil {
		return nil, err
	}

	// Verify signer's sigs on the refund and checkpoint txs.
	finalRefundPtx, err := psbt.NewFromRawBytes(strings.NewReader(finalRefundTx), true)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refund tx signed by server: %s", err)
	}

	if err := verifyTxSignatures(
		finalRefundPtx, pubkeys, getInputTapLeaves(refundPtx),
	); err != nil {
		return nil, fmt.Errorf("failed to verify fully signed refund tx: %w", err)
	}

	serverSignedCheckpointPtx, err := psbt.NewFromRawBytes(
		strings.NewReader(serverSignedCheckpointTxs[0]), true,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checkpoint tx signed by us: %s", err)
	}

	// Combine all checkpoint tx signatures (ours, boltz's, and the server's) and finalize the
	// offchain tx.
	finalCheckpointPtx, finalCheckpointTx, err := combineTxSignatures(
		checkpointPtx, cosignedCheckpointPtx, serverSignedCheckpointPtx,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to combine signatures of refund checkpoint txs: %s", err)
	}

	// Verify all signatures are valid before finalizing.
	if err := verifyTxSignatures(
		finalCheckpointPtx, pubkeys, getInputTapLeaves(checkpointPtx),
	); err != nil {
		return nil, fmt.Errorf("failed to verify fully signed refund checkpoint tx: %w", err)
	}

	if err := h.wallet.Client().FinalizeTx(
		ctx, refundTxid, []string{finalCheckpointTx},
	); err != nil {
		return nil, fmt.Errorf("failed to finalize refund tx: %w", err)
	}

	swap.RedeemTxid = refundTxid
	swap.Status = int(SwapStatusFailed)

	// Update the status of the swap in the store.
	if err := h.persistUpdatedSwap(ctx, swap); err != nil {
		return nil, fmt.Errorf("failed to update swap %s: %w", swap.Id, err)
	}

	return &swap, nil
}

func (h *SwapManager) scheduleUnilateralRefund(
	ctx context.Context, swap *swaptypes.Swap, refundLocktime arklib.AbsoluteLocktime,
) error {
	refund := func() {
		txid, err := h.wallet.UnilateralRefundVHTLC(ctx, swap.VHTLCScript)
		if err != nil {
			log.WithError(err).Errorf("failed to refund swap %s", swap.Id)
			return
		}

		swap.RedeemTxid = txid
		if err := h.persistUpdatedSwap(ctx, *swap); err != nil {
			log.WithError(err).Errorf("failed to update refunded swap %s", swap.Id)
			return
		}
		log.Debugf("swap %s refunded with tx %s", swap.Id, txid)
	}
	if refundLocktime.IsSeconds() {
		at := time.Unix(int64(refundLocktime), 0)
		if err := h.schedulerSvc.ScheduleTaskAtTime(at, refund); err != nil {
			return fmt.Errorf("failed to schedule refund of swap %s: %w", swap.Id, err)
		}
		log.Debugf("scheduled refund of swap %s at %s", swap.Id, at.Format(time.RFC3339))
		return nil
	}

	if err := h.schedulerSvc.ScheduleTaskAtHeight(uint32(refundLocktime), refund); err != nil {
		return fmt.Errorf("failed to schedule refund of swap %s: %w", swap.Id, err)
	}
	log.Debugf("scheduled refund of swap %s at height %d", swap.Id, refundLocktime)
	return nil
}

func (h *SwapManager) getNewKey(
	ctx context.Context, handler handlers.Handler,
) (*identity.KeyRef, error) {
	store := h.wallet.Store().ContractStore()
	keyProvider := h.wallet.Identity()

	latestContract, err := store.GetLatestActiveContract(ctx, types.ContractTypeVHTLC)
	if err != nil {
		return nil, err
	}

	var keyId string
	if latestContract != nil {
		keyRef, err := handler.GetKeyRef(*latestContract)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to get key ref for contract %s: %w", latestContract.Script, err,
			)
		}
		keyId = keyRef.Id
	}

	nextKeyId, err := keyProvider.NextKeyId(ctx, keyId)
	if err != nil {
		return nil, fmt.Errorf("failed to compute next key index: %w", err)
	}

	keyRef, err := keyProvider.GetKey(ctx, nextKeyId)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key for contract: %w", err)
	}
	return keyRef, nil
}

func (h *SwapManager) reconnectBoltzWebsocket(
	ctx context.Context, oldWs *boltz.Websocket, swapId string,
) (*boltz.Websocket, error) {
	nextWs := h.boltzSvc.NewWebsocket()
	if err := nextWs.ConnectAndSubscribe(ctx, []string{swapId}, 5*time.Second); err != nil {
		_ = oldWs.Close()
		_ = nextWs.Close()

		select {
		case <-time.After(boltzReconnectBackoff):
			return nil, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	_ = oldWs.Close()
	return nextWs, nil
}

func (h *SwapManager) persistSwap(ctx context.Context, swap swaptypes.Swap) error {
	if err := h.store.Swaps().Add(ctx, swap); err != nil {
		return err
	}

	log.Debugf("persisted swap %s", swap.Id)
	return nil
}

func (h *SwapManager) persistUpdatedSwap(ctx context.Context, swap swaptypes.Swap) error {
	if err := h.store.Swaps().Update(ctx, swap); err != nil {
		return err
	}
	log.Debugf("updated swap %s", swap.Id)
	return nil
}
