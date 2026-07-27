package swap

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	vhtlchandler "github.com/arkade-os/go-sdk/contract/handlers/vhtlc"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	log "github.com/sirupsen/logrus"
)

func (h *SwapManager) ArkadeToBtcChainSwap(
	ctx context.Context, btcAddress string, amount uint64,
) (*swaptypes.Swap, error) {
	claimKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral claim key for HTLC: %w", err)
	}

	keyProvider := h.wallet.Identity()
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
		return nil, fmt.Errorf("failed to get new key: %w", err)
	}

	// If the identity supports schnorr signing, use it to generate a deterministic preimage,
	// otherwise use a random preimage
	preimageSigner, ok := keyProvider.(PreimageSigner)
	persistPreimage := !ok
	var preimage vhtlc.Preimage
	if ok {
		preimage, err = DerivePreimage(ctx, preimageSigner, *keyRef)
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

	swapResp, err := h.boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyArk,
		To:              boltz.CurrencyBtc,
		PreimageHash:    hex.EncodeToString(preimageHashSHA256),
		ClaimPublicKey:  hex.EncodeToString(claimKey.PubKey().SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		UserLockAmount:  amount,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create chain swap with Boltz: %w", err)
	}

	receiverPubkey, err := parsePubkey(swapResp.LockupDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid claim pubkey: %v", err)
	}

	contract, err := handler.NewContract(ctx, vhtlchandler.ContractArgs{
		SenderKeyId:    keyRef.Id,
		Sender:         keyRef.PubKey,
		Receiver:       receiverPubkey,
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.LockupDetails.Timeouts.Refund),
		UnilateralClaimDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralClaim),
		),
		UnilateralRefundDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefund),
		),
		UnilateralRefundWithoutReceiverDelay: parseLocktime(
			uint32(swapResp.LockupDetails.Timeouts.UnilateralRefundWithoutReceiver),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild contract: %w", err)
	}

	if contract.Address != swapResp.LockupDetails.LockupAddress {
		return nil, fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			contract.Address, swapResp.LockupDetails.LockupAddress,
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

	// Rebuild the BTC HTLC and verify its address matches the one got from Boltz, so that we
	// are sure that we can claim the BTC UTXO before we send the VTXO. Done directly instead
	// of via the contract manager because HTLCs are locked by ephemeral keys instead of wallet
	// ones, so the receiver doesn't need to be online to receive.
	refundKey, err := parsePubkey(swapResp.ClaimDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid refund pubkey for swap %s: %w", swapResp.Id, err)
	}

	htlcScript, err := htlc.NewHTLCScriptFromOpts(htlc.Opts{
		ClaimKey:       claimKey.PubKey(),
		RefundKey:      refundKey,
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.ClaimDetails.TimeoutBlockHeight),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild htlc for swap %s: %w", swapResp.Id, err)
	}

	// Boltz is the sender of the BTC HTLC in this direction, its key comes first in the
	// MuSig2 aggregation of the taproot internal key.
	htlcAddress, err := htlcScript.Address(networkNameToParams(h.config.Network.Name), true)
	if err != nil {
		return nil, fmt.Errorf("failed to encode htlc address for swap %s: %w", swapResp.Id, err)
	}
	if htlcAddress != swapResp.ClaimDetails.LockupAddress {
		return nil, fmt.Errorf(
			"htlc address mismatch: rebuilt %s, got %s from boltz",
			htlcAddress, swapResp.ClaimDetails.LockupAddress,
		)
	}

	if err := contractManager.ImportContract(ctx, *contract); err != nil {
		return nil, err
	}
	unlockContractMu()

	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swapResp.Id}, 5*time.Second); err != nil {
		// ConnectAndSubscribe can fail with the connection open (subscription failed).
		_ = ws.Close()
		return nil, err
	}

	swap := &swaptypes.Swap{
		Id:          swapResp.Id,
		From:        boltz.CurrencyArk,
		To:          boltz.CurrencyBtc,
		CreatedAt:   time.Now(),
		Status:      int(SwapStatusPending),
		VHTLCScript: contract.Script,
		Amount:      amount,
		ChainSwap: &swaptypes.ChainSwapInfo{
			Address:            swapResp.ClaimDetails.LockupAddress,
			PrivateKey:         hex.EncodeToString(claimKey.Serialize()),
			DestinationAddress: btcAddress,
			ServerPublicKey:    swapResp.ClaimDetails.ServerPublicKey,
			RefundLocktime:     uint32(swapResp.ClaimDetails.TimeoutBlockHeight),
		},
	}
	if persistPreimage {
		swap.Preimage = preimage
	}
	if err := h.persistSwap(ctx, *swap); err != nil {
		_ = ws.Close()
		return nil, err
	}

	// The websocket is consumed by the goroutine below, it's in charge of closing it too.
	h.bgWg.Go(func() {
		ctx, cancel := context.WithTimeout(h.ctx, h.chainSwapTimeout)
		defer cancel()
		defer func() { _ = ws.Close() }()

		fail := func(err error, msg string) {
			// If the manager is shutting down, leave the swap pending for the next startup's
			// recovery instead of marking it and writing to a store that's about to close.
			if h.ctx.Err() != nil {
				return
			}
			log.WithError(err).Errorf("%s for swap %s", msg, swapResp.Id)
			swap.Status = int(SwapStatusFailed)
			if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
				log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
			}
		}

		quoteAccepted := false
		for {
			select {
			case update, ok := <-ws.Updates:
				if !ok {
					nextWs, err := h.reconnectBoltzWebsocket(ctx, ws, swapResp.Id)
					if err != nil {
						fail(err, "failed to reconnect websocket")
						return
					}
					if nextWs == nil {
						continue
					}
					ws = nextWs
					continue
				}

				switch boltz.ParseEvent(update.Status) {
				case boltz.SwapCreated:
					// Boltz accepted the swap, fund the VHTLC to start it.
					txid, err := h.wallet.SendOffChain(ctx, []clientTypes.Receiver{{
						To:     swapResp.LockupDetails.LockupAddress,
						Amount: swap.Amount,
					}})
					if err != nil {
						fail(err, "failed to fund vhtlc")
						return
					}

					swap.FundingTxid = txid
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}
				case boltz.TransactionLockupFailed:
					// Our lockup doesn't match the swap amount, fetch and accept a new quote.
					// Boltz may send this event more than once, react to it only once.
					if quoteAccepted {
						continue
					}
					quote, err := h.boltzSvc.GetChainSwapQuote(swapResp.Id)
					if err != nil {
						fail(err, "lockup failed and we failed to get a new quote")
						return
					}
					if err := h.boltzSvc.AcceptChainSwapQuote(swapResp.Id, *quote); err != nil {
						fail(err, "lockup failed and we failed to accept the new quote")
						return
					}
					quoteAccepted = true
				case boltz.TransactionServerMempoool:
					// Boltz locked up the BTC, claim it to the destination address.
					swap.ChainSwap.FundingTxid = update.Transaction.Id
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}

					claimTxid, err := h.claimBtcLockup(
						swapResp.Id, htlcScript, claimKey, preimage, btcAddress,
						update.Transaction.Hex,
					)
					if err != nil {
						fail(err, "failed to claim btc lockup")
						return
					}

					swap.Status = int(SwapStatusSuccess)
					swap.ChainSwap.RedeemTxid = claimTxid
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
					}
					return
				case boltz.SwapExpired, boltz.TransactionFailed:
					// Boltz can't complete the swap, refund the VHTLC collaboratively or
					// schedule a unilateral refund as fallback.
					if _, _, err := h.refundSwap(swap, parsed); err != nil {
						fail(err, fmt.Sprintf(
							"swap failed with status %s and we failed to refund it",
							update.Status,
						))
					}
					return
				}
			case <-ctx.Done():
				// A shutdown cancellation leaves the swap pending for the next startup's
				// recovery; only a genuine timeout fails it and schedules the refund.
				if h.ctx.Err() != nil {
					return
				}

				swap.Status = int(SwapStatusFailed)
				if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
					log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
				}

				log.Debugf(
					"process aborted while waiting for updates for swap %s, "+
						"trying to schedule a unilrateral refund before aborting...", swapResp.Id,
				)
				if err := h.scheduleUnilateralRefund(swap, parsed.RefundLocktime); err != nil {
					log.WithError(err).Errorf(
						"failed to schedule refund of swap %s unilaterally", swapResp.Id,
					)
				}

				return
			}
		}
	})

	return swap, nil
}

// BtcToArkadeChainSwap receives amount sats onto Arkade from onchain BTC: it returns a swap
// carrying the BTC address (swap.ChainSwap.Address) the caller must fund with the swap amount.
// Once the lockup is detected Boltz funds a vhtlc that the manager claims in the background, so
// the swap completes after this returns — observe it via GetSwap.
// The BTC HTLC is locked by an ephemeral key persisted with the swap: if the swap fails, the
// manager refunds the lockup to a boarding address once the HTLC locktime expires.
func (h *SwapManager) BtcToArkadeChainSwap(
	ctx context.Context, amount uint64,
) (*swaptypes.Swap, error) {
	refundKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral refund key for HTLC: %w", err)
	}

	keyProvider := h.wallet.Identity()
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
		return nil, fmt.Errorf("failed to get new key: %w", err)
	}

	// If the identity supports schnorr signing, use it to generate a deterministic preimage,
	// otherwise use a random preimage
	preimageSigner, ok := keyProvider.(PreimageSigner)
	persistPreimage := !ok
	var preimage vhtlc.Preimage
	if ok {
		preimage, err = DerivePreimage(ctx, preimageSigner, *keyRef)
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

	swapResp, err := h.boltzSvc.CreateChainSwap(boltz.CreateChainSwapRequest{
		From:            boltz.CurrencyBtc,
		To:              boltz.CurrencyArk,
		PreimageHash:    hex.EncodeToString(preimageHashSHA256),
		ClaimPublicKey:  hex.EncodeToString(keyRef.PubKey.SerializeCompressed()),
		RefundPublicKey: hex.EncodeToString(refundKey.PubKey().SerializeCompressed()),
		UserLockAmount:  amount,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create chain swap with Boltz: %w", err)
	}

	senderPubkey, err := parsePubkey(swapResp.ClaimDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid sender pubkey: %v", err)
	}

	contract, err := handler.NewContract(ctx, vhtlchandler.ContractArgs{
		Sender:         senderPubkey,
		ReceiverKeyId:  keyRef.Id,
		Receiver:       keyRef.PubKey,
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.ClaimDetails.Timeouts.Refund),
		UnilateralClaimDelay: parseLocktime(
			uint32(swapResp.ClaimDetails.Timeouts.UnilateralClaim),
		),
		UnilateralRefundDelay: parseLocktime(
			uint32(swapResp.ClaimDetails.Timeouts.UnilateralRefund),
		),
		UnilateralRefundWithoutReceiverDelay: parseLocktime(
			uint32(swapResp.ClaimDetails.Timeouts.UnilateralRefundWithoutReceiver),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild contract: %w", err)
	}

	if contract.Address != swapResp.ClaimDetails.LockupAddress {
		return nil, fmt.Errorf(
			"vhtlc address mismatch: rebuilt %s, got %s from boltz",
			contract.Address, swapResp.ClaimDetails.LockupAddress,
		)
	}

	// Rebuild the BTC HTLC and verify its address matches the one got from Boltz, so that we
	// are sure that we can refund the BTC UTXO if the swap fails. Done directly instead of via
	// the contract manager because HTLCs are locked by ephemeral keys instead of wallet ones,
	// so the receiver doesn't need to be online to receive.
	claimKey, err := parsePubkey(swapResp.LockupDetails.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid claim pubkey for swap %s: %w", swapResp.Id, err)
	}

	htlcScript, err := htlc.NewHTLCScriptFromOpts(htlc.Opts{
		ClaimKey:       claimKey,
		RefundKey:      refundKey.PubKey(),
		PreimageHash:   preimageHashHASH160,
		RefundLocktime: arklib.AbsoluteLocktime(swapResp.LockupDetails.TimeoutBlockHeight),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rebuild htlc for swap %s: %w", swapResp.Id, err)
	}

	// Boltz is the receiver of the BTC HTLC in this direction, its key comes first in the
	// MuSig2 aggregation of the taproot internal key.
	htlcAddress, err := htlcScript.Address(networkNameToParams(h.config.Network.Name), false)
	if err != nil {
		return nil, fmt.Errorf("failed to encode htlc address for swap %s: %w", swapResp.Id, err)
	}
	if htlcAddress != swapResp.LockupDetails.LockupAddress {
		return nil, fmt.Errorf(
			"htlc address mismatch: rebuilt %s, got %s from boltz",
			htlcAddress, swapResp.LockupDetails.LockupAddress,
		)
	}

	if err := contractManager.ImportContract(ctx, *contract); err != nil {
		return nil, err
	}
	unlockContractMu()

	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swapResp.Id}, 5*time.Second); err != nil {
		// ConnectAndSubscribe can fail with the connection open (subscription failed).
		_ = ws.Close()
		return nil, err
	}

	swap := &swaptypes.Swap{
		Id:          swapResp.Id,
		From:        boltz.CurrencyBtc,
		To:          boltz.CurrencyArk,
		CreatedAt:   time.Now(),
		Status:      int(SwapStatusPending),
		VHTLCScript: contract.Script,
		Amount:      amount,
		ChainSwap: &swaptypes.ChainSwapInfo{
			Address:         swapResp.LockupDetails.LockupAddress,
			PrivateKey:      hex.EncodeToString(refundKey.Serialize()),
			ServerPublicKey: swapResp.LockupDetails.ServerPublicKey,
			RefundLocktime:  uint32(swapResp.LockupDetails.TimeoutBlockHeight),
		},
	}
	if persistPreimage {
		swap.Preimage = preimage
	}
	if err := h.persistSwap(ctx, *swap); err != nil {
		_ = ws.Close()
		return nil, err
	}

	// The websocket is consumed by the goroutine below, it's in charge of closing it too.
	h.bgWg.Go(func() {
		ctx, cancel := context.WithTimeout(h.ctx, h.chainSwapTimeout)
		defer cancel()
		defer func() { _ = ws.Close() }()

		fail := func(err error, msg string) {
			// If the manager is shutting down, leave the swap pending for the next startup's
			// recovery instead of marking it and writing to a store that's about to close.
			if h.ctx.Err() != nil {
				return
			}
			log.WithError(err).Errorf("%s for swap %s", msg, swapResp.Id)
			swap.Status = int(SwapStatusFailed)
			if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
				log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
			}
		}

		quoteAccepted := false
		for {
			select {
			case update, ok := <-ws.Updates:
				if !ok {
					nextWs, err := h.reconnectBoltzWebsocket(ctx, ws, swapResp.Id)
					if err != nil {
						fail(err, "failed to reconnect websocket")
						return
					}
					if nextWs == nil {
						continue
					}
					ws = nextWs
					continue
				}

				switch boltz.ParseEvent(update.Status) {
				case boltz.SwapCreated:
					// Boltz accepted the swap, the caller must fund the btc lockup address.
					log.Debugf(
						"swap %s created, waiting for the btc lockup to be funded", swapResp.Id,
					)
				case boltz.TransactionMempool, boltz.TransactionConfirmed:
					// Our btc lockup was detected, persist its txid.
					if swap.ChainSwap.FundingTxid == update.Transaction.Id {
						continue
					}
					swap.ChainSwap.FundingTxid = update.Transaction.Id
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}
				case boltz.TransactionLockupFailed:
					// Our lockup doesn't match the swap amount, fetch and accept a new quote.
					// Boltz may send this event more than once, react to it only once.
					if quoteAccepted {
						continue
					}
					quote, err := h.boltzSvc.GetChainSwapQuote(swapResp.Id)
					if err != nil {
						fail(err, "lockup failed and we failed to get a new quote")
						return
					}
					if err := h.boltzSvc.AcceptChainSwapQuote(swapResp.Id, *quote); err != nil {
						fail(err, "lockup failed and we failed to accept the new quote")
						return
					}
					quoteAccepted = true
				case boltz.TransactionServerMempoool:
					// Boltz funded the vhtlc, claim it by revealing the preimage.
					swap.FundingTxid = update.Transaction.Id
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}

					var claimTxid string
					if err := retry(
						ctx, 200*time.Millisecond,
						func(ctx context.Context) (bool, error) {
							var err error
							claimTxid, err = h.wallet.ClaimVHTLC(ctx, swap.VHTLCScript, preimage)
							if err != nil {
								return false, err
							}
							return true, nil
						},
					); err != nil {
						fail(err, "failed to claim vhtlc")
						return
					}

					swap.Status = int(SwapStatusSuccess)
					swap.RedeemTxid = claimTxid
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}

					// Cooperatively sign Boltz's claim of the btc lockup so they can spend the
					// cheaper key path. Boltz builds its claim tx only after it sees the preimage
					// revealed by our claim, so retry for a while. Non-critical: they can claim
					// via script path with the revealed preimage.
					cosignCtx, cosignCancel := context.WithTimeout(ctx, 30*time.Second)
					if err := retry(
						cosignCtx, time.Second,
						func(context.Context) (bool, error) {
							if err := h.signBoltzBtcClaim(
								swapResp.Id, htlcScript, refundKey,
							); err != nil {
								return false, err
							}
							return true, nil
						},
					); err != nil {
						log.WithError(err).Warnf(
							"failed to cosign boltz btc claim for swap %s", swapResp.Id,
						)
					}
					cosignCancel()
					return
				case boltz.SwapExpired, boltz.TransactionFailed:
					// Boltz can't complete the swap, refund the btc lockup once its locktime
					// expires, if we ever funded it.
					swap.Status = int(SwapStatusFailed)
					if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
						fail(err, "failed to update swap")
						return
					}
					if swap.ChainSwap.FundingTxid == "" {
						return
					}
					if err := h.scheduleBtcRefund(swap, htlcScript, refundKey); err != nil {
						fail(err, fmt.Sprintf(
							"swap failed with status %s and we failed to schedule the btc refund",
							update.Status,
						))
					}
					return
				}
			case <-ctx.Done():
				// A shutdown cancellation leaves the swap pending for the next startup's
				// recovery; only a genuine timeout fails it and schedules the refund.
				if h.ctx.Err() != nil {
					return
				}

				swap.Status = int(SwapStatusFailed)
				if err := h.persistUpdatedSwap(context.Background(), *swap); err != nil {
					log.WithError(err).Errorf("failed to update swap %s", swapResp.Id)
				}

				if swap.ChainSwap.FundingTxid == "" {
					return
				}
				log.Debugf(
					"process aborted while waiting for updates for swap %s, "+
						"trying to schedule the refund of the btc lockup before aborting...",
					swapResp.Id,
				)
				if err := h.scheduleBtcRefund(swap, htlcScript, refundKey); err != nil {
					log.WithError(err).Errorf(
						"failed to schedule refund of swap %s", swapResp.Id,
					)
				}

				return
			}
		}
	})

	return swap, nil
}

// RefundChainSwap refunds a failed chain swap by id. For an Arkade -> BTC swap it refunds the
// vhtlc we funded: first collaboratively with Boltz, falling back to scheduling the trustless
// unilateral refund at the vhtlc's refund locktime. For a BTC -> Arkade swap it refunds the btc
// lockup to a boarding address: immediately if the HTLC locktime already expired, otherwise the
// refund is scheduled at the expiry height. The returned time is the moment a scheduled refund
// will fire, nil when the swap was refunded right away.
// This is meant to be used as fallback as the manager takes care of handling the refund
// automatically in ArkadeToBtcChainSwap and BtcToArkadeChainSwap.
func (h *SwapManager) RefundChainSwap(
	ctx context.Context, swapId string,
) (*swaptypes.Swap, *time.Time, error) {
	swap, err := h.store.Swaps().Get(ctx, swapId)
	if err != nil {
		return nil, nil, err
	}
	if swap.ChainSwap == nil {
		return nil, nil, fmt.Errorf("swap %s is not a chain swap", swapId)
	}

	if swap.From == boltz.CurrencyArk {
		contractArgs, err := h.getSwapContractArgs(ctx, swap)
		if err != nil {
			return nil, nil, err
		}
		return h.refundSwap(swap, contractArgs)
	}

	if swap.ChainSwap.FundingTxid == "" {
		return nil, nil, fmt.Errorf(
			"btc lockup of swap %s was never funded, nothing to refund", swapId,
		)
	}
	if swap.ChainSwap.RedeemTxid != "" {
		return nil, nil, fmt.Errorf(
			"btc lockup of swap %s already redeemed with tx %s",
			swapId, swap.ChainSwap.RedeemTxid,
		)
	}

	htlcScript, refundKey, err := h.getSwapHtlc(ctx, swap)
	if err != nil {
		return nil, nil, err
	}

	swap.Status = int(SwapStatusFailed)

	locktime := int64(htlcScript.RefundLocktime)
	height, err := h.wallet.Explorer().GetBlockHeight()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get block height: %w", err)
	}
	if height < locktime {
		if err := h.scheduleBtcRefund(swap, htlcScript, refundKey); err != nil {
			return nil, nil, err
		}
		if err := h.persistUpdatedSwap(ctx, *swap); err != nil {
			return nil, nil, err
		}
		// Approximate the expiry time from the remaining blocks (~10' each).
		scheduledAt := time.Now().Add(time.Duration(locktime-height) * 10 * time.Minute)
		return swap, &scheduledAt, nil
	}

	txid, err := h.refundBtcLockup(ctx, swap, htlcScript, refundKey)
	if err != nil {
		return nil, nil, err
	}
	swap.ChainSwap.RedeemTxid = txid
	if err := h.persistUpdatedSwap(ctx, *swap); err != nil {
		return nil, nil, err
	}
	return swap, nil, nil
}

// claimBtcLockup claims the BTC locked up by Boltz to the destination address. It first tries
// a cooperative MuSig2 key-path spend, then falls back to a script-path spend of the claim
// leaf revealing the preimage.
func (h *SwapManager) claimBtcLockup(
	swapId string, htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey,
	preimage []byte, btcAddress, lockupTxHex string,
) (string, error) {
	explorerSvc := h.wallet.Explorer()

	lockupTx, err := deserializeTransaction(lockupTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode lockup tx: %w", err)
	}
	lockupPkScript, err := htlcScript.PkScript(true)
	if err != nil {
		return "", fmt.Errorf("failed to get htlc output script: %w", err)
	}

	vout := -1
	var lockupAmount uint64
	for i, out := range lockupTx.TxOut {
		if bytes.Equal(out.PkScript, lockupPkScript) {
			vout, lockupAmount = i, uint64(out.Value)
			break
		}
	}
	if vout < 0 {
		return "", fmt.Errorf("htlc output not found in lockup tx %s", lockupTx.TxHash())
	}

	claimTx, err := constructClaimTransaction(explorerSvc, h.config.Dust, claimTransactionParams{
		lockupTxid:      lockupTx.TxHash().String(),
		lockupVout:      uint32(vout),
		lockupAmount:    lockupAmount,
		destinationAddr: btcAddress,
		network:         networkNameToParams(h.config.Network.Name),
	})
	if err != nil {
		return "", fmt.Errorf("failed to construct claim tx: %w", err)
	}

	prevOutFetcher := NewPrevOutputFetcher(
		&wire.TxOut{Value: int64(lockupAmount), PkScript: lockupPkScript},
		claimTx.TxIn[0].PreviousOutPoint,
	)

	witness, err := h.signClaimCooperative(
		swapId, htlcScript, claimKey, preimage, claimTx, prevOutFetcher,
	)
	if err != nil {
		log.WithError(err).Warnf(
			"failed to sign claim tx for swap %s cooperatively, "+
				"falling back to script-path spend", swapId,
		)
		witness, err = signClaimScriptPath(htlcScript, claimKey, preimage, claimTx, prevOutFetcher)
		if err != nil {
			return "", err
		}
	}
	claimTx.TxIn[0].Witness = witness

	claimTxHex, err := serializeTransaction(claimTx)
	if err != nil {
		return "", fmt.Errorf("failed to serialize claim tx: %w", err)
	}
	txid, err := explorerSvc.Broadcast(claimTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast claim tx: %w", err)
	}
	return txid, nil
}

// signClaimCooperative computes the key-path witness of the claim tx by exchanging MuSig2
// nonces and partial signatures with Boltz, revealing the preimage to let them claim the
// VHTLC on their side.
func (h *SwapManager) signClaimCooperative(
	swapId string, htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey, preimage []byte,
	claimTx *wire.MsgTx, prevOutFetcher txscript.PrevOutputFetcher,
) (wire.TxWitness, error) {
	musigSession, err := newLocalMuSig2Session(claimKey, htlcScript.RefundKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create musig2 session: %w", err)
	}
	ourNonce, err := musigSession.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	claimTxHex, err := serializeTransaction(claimTx)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize claim tx: %w", err)
	}

	boltzResp, err := h.boltzSvc.SubmitChainSwapClaim(swapId, boltz.ChainSwapClaimRequest{
		Preimage: hex.EncodeToString(preimage),
		ToSign: boltz.ToSign{
			Nonce:   SerializePubNonce(ourNonce),
			ClaimTx: claimTxHex,
			Index:   0,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit claim to boltz: %w", err)
	}

	boltzNonce, err := ParsePubNonce(boltzResp.PubNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boltz nonce: %w", err)
	}
	boltzPartialSig, err := ParsePartialSignatureScalar32(boltzResp.PartialSignature)
	if err != nil {
		return nil, fmt.Errorf("failed to parse boltz partial sig: %w", err)
	}

	msg, err := TaprootMessage(claimTx, 0, prevOutFetcher)
	if err != nil {
		return nil, fmt.Errorf("failed to compute taproot message: %w", err)
	}

	combinedNonce, err := musigSession.AggregateNonces(boltzNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate nonces: %w", err)
	}

	merkleRoot := htlcScript.MerkleRoot()
	ourPartialSig, err := musigSession.PartialSign(combinedNonce, msg, merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to make our partial sig: %w", err)
	}
	if ourPartialSig.R == nil {
		return nil, fmt.Errorf("missing nonce point in our partial sig")
	}

	finalSig, err := CombineFinalSig(
		ourPartialSig.R,
		[]*musig2.PartialSignature{ourPartialSig, boltzPartialSig},
		musigSession.Keys(), msg, merkleRoot,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to combine sigs: %w", err)
	}

	tweakedKey, err := ComputeTweakedOutputKey(musigSession.Keys(), merkleRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tweaked key: %w", err)
	}
	if err := VerifyFinalSig(msg, finalSig, tweakedKey); err != nil {
		return nil, fmt.Errorf("failed to verify final sig: %w", err)
	}

	return wire.TxWitness{finalSig.Serialize()}, nil
}

// signClaimScriptPath computes the script-path witness of the claim tx by signing the claim
// leaf with the ephemeral claim key and revealing the preimage in the witness.
func signClaimScriptPath(
	htlcScript *htlc.HTLCScript, claimKey *btcec.PrivateKey, preimage []byte,
	claimTx *wire.MsgTx, prevOutFetcher txscript.PrevOutputFetcher,
) (wire.TxWitness, error) {
	tapscript, err := htlcScript.ClaimTapscript(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim tapscript: %w", err)
	}

	sigHashes := txscript.NewTxSigHashes(claimTx, prevOutFetcher)
	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, claimTx, 0, prevOutFetcher,
		txscript.NewBaseTapLeaf(tapscript.RevealedScript),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tapscript sighash: %w", err)
	}

	var msg [32]byte
	copy(msg[:], sigHash)
	sig, err := signLocalSchnorr(claimKey, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign claim tx: %w", err)
	}

	ctrlBlock, err := tapscript.ControlBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	return wire.TxWitness{
		sig.Serialize(), preimage, tapscript.RevealedScript, ctrlBlock,
	}, nil
}

// refundBtcLockup refunds the BTC we locked up for a failed Btc -> Arkade chain swap to a fresh
// boarding address via a script-path spend of the refund leaf. It can be broadcast only after
// the HTLC locktime expired. The refunded funds can then be settled to become vtxos.
func (h *SwapManager) refundBtcLockup(
	ctx context.Context, swap *swaptypes.Swap, htlcScript *htlc.HTLCScript,
	refundKey *btcec.PrivateKey,
) (string, error) {
	explorerSvc := h.wallet.Explorer()

	lockupTxHex, err := explorerSvc.GetTxHex(swap.ChainSwap.FundingTxid)
	if err != nil {
		return "", fmt.Errorf("failed to fetch lockup tx: %w", err)
	}
	lockupTx, err := deserializeTransaction(lockupTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode lockup tx: %w", err)
	}
	lockupPkScript, err := htlcScript.PkScript(false)
	if err != nil {
		return "", fmt.Errorf("failed to get htlc output script: %w", err)
	}

	vout := -1
	var lockupAmount uint64
	for i, out := range lockupTx.TxOut {
		if bytes.Equal(out.PkScript, lockupPkScript) {
			vout, lockupAmount = i, uint64(out.Value)
			break
		}
	}
	if vout < 0 {
		return "", fmt.Errorf("htlc output not found in lockup tx %s", lockupTx.TxHash())
	}

	// The refund goes to a boarding address so it can be settled to become vtxos.
	boardingAddr, err := h.wallet.NewBoardingAddress(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get boarding address: %w", err)
	}

	refundTx, err := constructClaimTransaction(explorerSvc, h.config.Dust, claimTransactionParams{
		lockupTxid:      lockupTx.TxHash().String(),
		lockupVout:      uint32(vout),
		lockupAmount:    lockupAmount,
		destinationAddr: boardingAddr,
		network:         networkNameToParams(h.config.Network.Name),
	})
	if err != nil {
		return "", fmt.Errorf("failed to construct refund tx: %w", err)
	}
	// The refund leaf checks a CLTV: the tx locktime must be set to it and the input sequence
	// must not be final for the check to pass.
	refundTx.LockTime = uint32(htlcScript.RefundLocktime)
	refundTx.TxIn[0].Sequence = wire.MaxTxInSequenceNum - 1

	prevOutFetcher := NewPrevOutputFetcher(
		&wire.TxOut{Value: int64(lockupAmount), PkScript: lockupPkScript},
		refundTx.TxIn[0].PreviousOutPoint,
	)

	witness, err := signRefundScriptPath(htlcScript, refundKey, refundTx, prevOutFetcher)
	if err != nil {
		return "", err
	}
	refundTx.TxIn[0].Witness = witness

	refundTxHex, err := serializeTransaction(refundTx)
	if err != nil {
		return "", fmt.Errorf("failed to serialize refund tx: %w", err)
	}
	txid, err := explorerSvc.Broadcast(refundTxHex)
	if err != nil {
		return "", fmt.Errorf("failed to broadcast refund tx: %w", err)
	}
	return txid, nil
}

// signRefundScriptPath computes the script-path witness of the refund tx by signing the refund
// leaf with the ephemeral refund key.
func signRefundScriptPath(
	htlcScript *htlc.HTLCScript, refundKey *btcec.PrivateKey,
	refundTx *wire.MsgTx, prevOutFetcher txscript.PrevOutputFetcher,
) (wire.TxWitness, error) {
	tapscript, err := htlcScript.RefundTapscript(false)
	if err != nil {
		return nil, fmt.Errorf("failed to get refund tapscript: %w", err)
	}

	sigHashes := txscript.NewTxSigHashes(refundTx, prevOutFetcher)
	sigHash, err := txscript.CalcTapscriptSignaturehash(
		sigHashes, txscript.SigHashDefault, refundTx, 0, prevOutFetcher,
		txscript.NewBaseTapLeaf(tapscript.RevealedScript),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tapscript sighash: %w", err)
	}

	var msg [32]byte
	copy(msg[:], sigHash)
	sig, err := signLocalSchnorr(refundKey, msg)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refund tx: %w", err)
	}

	ctrlBlock, err := tapscript.ControlBlock.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize control block: %w", err)
	}

	return wire.TxWitness{sig.Serialize(), tapscript.RevealedScript, ctrlBlock}, nil
}

// scheduleBtcRefund schedules the refund of the btc lockup of a failed Btc -> Arkade chain swap
// at the block height its locktime expires. The task fires immediately if the locktime is
// already past.
func (h *SwapManager) scheduleBtcRefund(
	swap *swaptypes.Swap, htlcScript *htlc.HTLCScript, refundKey *btcec.PrivateKey,
) error {
	refund := func() {
		// The scheduler fires this at the HTLC locktime, long after the caller returned, so the
		// request context that scheduled it is dead by now. Use the manager lifetime context,
		// bounded by a timeout started here so a stuck refund can't run unbounded.
		ctx, cancel := context.WithTimeout(h.ctx, refundTimeout)
		defer cancel()

		txid, err := h.refundBtcLockup(ctx, swap, htlcScript, refundKey)
		if err != nil {
			log.WithError(err).Errorf("failed to refund btc lockup of swap %s", swap.Id)
			return
		}

		swap.ChainSwap.RedeemTxid = txid
		if err := h.persistUpdatedSwap(ctx, *swap); err != nil {
			log.WithError(err).Errorf("failed to update refunded swap %s", swap.Id)
			return
		}
		log.Debugf("btc lockup of swap %s refunded with tx %s", swap.Id, txid)
	}

	locktime := uint32(htlcScript.RefundLocktime)
	if err := h.schedulerSvc.ScheduleTaskAtHeight(locktime, refund); err != nil {
		return fmt.Errorf("failed to schedule btc refund of swap %s: %w", swap.Id, err)
	}
	log.Debugf("scheduled btc refund of swap %s at height %d", swap.Id, locktime)
	return nil
}

// signBoltzBtcClaim provides our partial signature for Boltz to claim the btc lockup of a
// Btc -> Arkade chain swap via the cheaper key-path spend, by exchanging MuSig2 nonces and
// partial signatures over the sighash of their claim tx.
func (h *SwapManager) signBoltzBtcClaim(
	swapId string, htlcScript *htlc.HTLCScript, refundKey *btcec.PrivateKey,
) error {
	claimDetails, err := h.boltzSvc.GetChainSwapClaimDetails(swapId)
	if err != nil {
		return fmt.Errorf("failed to get claim details: %w", err)
	}

	boltzPubkey, err := parsePubkey(claimDetails.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse boltz pubkey: %w", err)
	}

	musigSession, err := newLocalMuSig2Session(refundKey, boltzPubkey)
	if err != nil {
		return fmt.Errorf("failed to create musig2 session: %w", err)
	}
	ourNonce, err := musigSession.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	boltzNonce, err := ParsePubNonce(claimDetails.PubNonce)
	if err != nil {
		return fmt.Errorf("failed to parse boltz nonce: %w", err)
	}

	sigHash, err := hex.DecodeString(claimDetails.TransactionHash)
	if err != nil {
		return fmt.Errorf("failed to decode claim tx sighash: %w", err)
	}
	var msg [32]byte
	copy(msg[:], sigHash)

	combinedNonce, err := musigSession.AggregateNonces(boltzNonce)
	if err != nil {
		return fmt.Errorf("failed to aggregate nonces: %w", err)
	}

	ourPartialSig, err := musigSession.PartialSign(combinedNonce, msg, htlcScript.MerkleRoot())
	if err != nil {
		return fmt.Errorf("failed to make our partial sig: %w", err)
	}

	var buf bytes.Buffer
	if err := ourPartialSig.Encode(&buf); err != nil {
		return fmt.Errorf("failed to encode our partial sig: %w", err)
	}

	if _, err := h.boltzSvc.SubmitChainSwapClaim(swapId, boltz.ChainSwapClaimRequest{
		Signature: boltz.CrossSignSignature{
			PubNonce:         SerializePubNonce(ourNonce),
			PartialSignature: hex.EncodeToString(buf.Bytes()),
		},
	}); err != nil {
		return fmt.Errorf("failed to submit our partial sig to boltz: %w", err)
	}
	return nil
}

// getSwapHtlc rebuilds the BTC HTLC of a Btc -> Arkade chain swap from the persisted ephemeral
// refund key, server key and locktime, and the swap's preimage hash. The full keys (with their
// Y parity) are needed: the swap tree only carries x-only keys, which can't reproduce the
// MuSig2 taproot output.
func (h *SwapManager) getSwapHtlc(
	ctx context.Context, swap *swaptypes.Swap,
) (*htlc.HTLCScript, *btcec.PrivateKey, error) {
	refundKeyBytes, err := hex.DecodeString(swap.ChainSwap.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode refund key: %w", err)
	}
	refundKey, _ := btcec.PrivKeyFromBytes(refundKeyBytes)

	claimKey, err := parsePubkey(swap.ChainSwap.ServerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server pubkey: %w", err)
	}

	preimage, err := h.swapPreimage(ctx, swap)
	if err != nil {
		return nil, nil, err
	}
	_, preimageHash := preimage.Hash()

	htlcScript, err := htlc.NewHTLCScriptFromOpts(htlc.Opts{
		ClaimKey:       claimKey,
		RefundKey:      refundKey.PubKey(),
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(swap.ChainSwap.RefundLocktime),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to rebuild btc htlc: %w", err)
	}
	return htlcScript, refundKey, nil
}
