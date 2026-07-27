package swap

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/go-sdk/htlc"
	"github.com/arkade-os/go-sdk/swap/boltz"
	swaptypes "github.com/arkade-os/go-sdk/swap/types"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"

	log "github.com/sirupsen/logrus"
)

// recoverPendingSwaps terminates the swaps a previous run left in flight: it claims what can be
// claimed and refunds what must be refunded. For each swap it asks Boltz for the current status
// and acts on it, so nothing here depends on in-memory state that didn't survive the restart.
// Swaps whose status is not actionable yet (e.g. a reverse swap whose vhtlc Boltz hasn't funded)
// are left pending for a future recovery run. It's best-effort: a failure on one swap is logged
// and doesn't stop the others.
func (h *SwapManager) recoverPendingSwaps(ctx context.Context) {
	// Failed swaps we funded but never refunded: the scheduled unilateral refund doesn't
	// survive a restart, so re-drive the refund.
	failedSwaps, err := h.store.Swaps().List(ctx, int(SwapStatusFailed))
	if err != nil {
		log.WithError(err).Error("swap recovery: failed to list failed swaps")
		return
	}
	for i := range failedSwaps {
		swap := failedSwaps[i]
		if swap.From == boltz.CurrencyArk {
			if swap.RedeemTxid != "" {
				continue
			}
			if err := h.recoverRefund(ctx, &swap); err != nil {
				log.WithError(err).Warnf("swap recovery: failed to refund failed swap %s", swap.Id)
			}
			continue
		}
		// Failed Btc -> Arkade chain swaps: the scheduled refund of the btc lockup doesn't
		// survive a restart, re-schedule it if the lockup was funded and never redeemed.
		if swap.ChainSwap == nil || swap.ChainSwap.FundingTxid == "" ||
			swap.ChainSwap.RedeemTxid != "" {
			continue
		}
		if err := h.recoverBtcRefund(ctx, &swap); err != nil {
			log.WithError(err).Warnf(
				"swap recovery: failed to refund btc lockup of failed swap %s", swap.Id,
			)
		}
	}

	pendingSwaps, err := h.store.Swaps().List(ctx, int(SwapStatusPending))
	if err != nil {
		log.WithError(err).Error("swap recovery: failed to list pending swaps")
		return
	}
	for i := range pendingSwaps {
		swap := pendingSwaps[i]
		if err := h.recoverSwap(ctx, &swap); err != nil {
			log.WithError(err).Warnf("swap recovery: failed to recover swap %s", swap.Id)
		}
	}
}

// recoverSwap asks Boltz for the current status of the given pending swap and drives it to its
// terminal state accordingly.
func (h *SwapManager) recoverSwap(ctx context.Context, swap *swaptypes.Swap) error {
	status, err := h.boltzSvc.GetSwapStatus(swap.Id)
	if err != nil {
		return fmt.Errorf("failed to get boltz status: %w", err)
	}
	event := boltz.ParseEvent(status.Status)

	switch {
	case swap.ChainSwap != nil:
		return h.recoverChainSwap(ctx, swap, status, event)
	case swap.From == boltz.CurrencyBtc:
		return h.recoverReverseSwap(ctx, swap, event)
	default:
		return h.recoverSubmarineSwap(ctx, swap, status, event)
	}
}

// recoverReverseSwap claims the vhtlc Boltz funded, if any. We are the receiver and nothing is
// locked on our side, so a failed reverse swap is simply marked as such.
func (h *SwapManager) recoverReverseSwap(
	ctx context.Context, swap *swaptypes.Swap, event boltz.SwapUpdateEvent,
) error {
	switch event {
	case boltz.TransactionMempool, boltz.TransactionConfirmed:
		preimage, err := h.swapPreimage(ctx, swap)
		if err != nil {
			return err
		}
		txid, err := h.wallet.ClaimVHTLC(ctx, swap.VHTLCScript, preimage)
		if err != nil {
			return fmt.Errorf("failed to claim vhtlc: %w", err)
		}
		swap.Status = int(SwapStatusSuccess)
		swap.RedeemTxid = txid
		log.Debugf("swap recovery: reverse swap %s claimed with tx %s", swap.Id, txid)
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.TransactionClaimed, boltz.InvoiceSettled:
		// Already claimed before the restart, only the store was left behind.
		swap.Status = int(SwapStatusSuccess)
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.SwapExpired, boltz.TransactionFailed, boltz.InvoiceFailedToPay,
		boltz.TransactionLockupFailed:
		swap.Status = int(SwapStatusFailed)
		return h.persistUpdatedSwap(ctx, *swap)
	default:
		log.Debugf(
			"swap recovery: reverse swap %s not actionable in status %d, leaving pending",
			swap.Id, event,
		)
		return nil
	}
}

// recoverSubmarineSwap marks a settled swap as successful, or refunds the vhtlc we funded if the
// swap failed.
func (h *SwapManager) recoverSubmarineSwap(
	ctx context.Context, swap *swaptypes.Swap, status *boltz.SwapStatusResponse,
	event boltz.SwapUpdateEvent,
) error {
	switch event {
	case boltz.TransactionClaimed, boltz.InvoiceSettled:
		swap.Status = int(SwapStatusSuccess)
		swap.RedeemTxid = status.Transaction.Id
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.SwapExpired, boltz.TransactionFailed, boltz.InvoiceFailedToPay,
		boltz.TransactionLockupFailed:
		return h.recoverRefund(ctx, swap)
	default:
		log.Debugf(
			"swap recovery: submarine swap %s not actionable in status %d, leaving pending",
			swap.Id, event,
		)
		return nil
	}
}

// recoverChainSwap marks a claimed chain swap as successful, or refunds the vhtlc we funded if
// the swap failed. When Boltz has locked up the BTC, it claims it to the persisted destination
// address.
func (h *SwapManager) recoverChainSwap(
	ctx context.Context, swap *swaptypes.Swap, status *boltz.SwapStatusResponse,
	event boltz.SwapUpdateEvent,
) error {
	if swap.From == boltz.CurrencyBtc {
		return h.recoverBtcToArkadeChainSwap(ctx, swap, event)
	}

	switch event {
	case boltz.TransactionClaimed:
		swap.Status = int(SwapStatusSuccess)
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.SwapExpired, boltz.TransactionFailed, boltz.TransactionLockupFailed:
		return h.recoverRefund(ctx, swap)
	case boltz.TransactionServerMempoool:
		return h.recoverChainSwapClaim(ctx, swap, status)
	default:
		log.Debugf(
			"swap recovery: chain swap %s not actionable in status %d, leaving pending",
			swap.Id, event,
		)
		return nil
	}
}

// recoverChainSwapClaim claims the BTC Boltz locked up for an Arkade -> BTC chain swap. The BTC
// HTLC is rebuilt from the persisted swap tree, the claim key and destination address come from
// the swap record, and the lockup tx is the one carried by the swap status (the transactions
// endpoint is not supported for ARK chain swaps).
func (h *SwapManager) recoverChainSwapClaim(
	ctx context.Context, swap *swaptypes.Swap, status *boltz.SwapStatusResponse,
) error {
	info := swap.ChainSwap
	if info.DestinationAddress == "" {
		return fmt.Errorf("missing destination address, cannot claim")
	}
	if status.Transaction.Hex == "" {
		return fmt.Errorf("missing server lockup tx in swap status")
	}

	claimKeyBytes, err := hex.DecodeString(info.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decode claim key: %w", err)
	}
	claimKey, _ := btcec.PrivKeyFromBytes(claimKeyBytes)

	refundKey, err := parsePubkey(info.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("invalid server pubkey: %w", err)
	}

	preimage, err := h.swapPreimage(ctx, swap)
	if err != nil {
		return err
	}
	_, preimageHash := preimage.Hash()

	// Rebuild the BTC HTLC from the full keys (with their Y parity) and timeout, exactly like
	// the live flow: the persisted swap tree only carries x-only keys, which can't reproduce
	// the MuSig2 taproot output.
	htlcScript, err := htlc.NewHTLCScriptFromOpts(htlc.Opts{
		ClaimKey:       claimKey.PubKey(),
		RefundKey:      refundKey,
		PreimageHash:   preimageHash,
		RefundLocktime: arklib.AbsoluteLocktime(info.RefundLocktime),
	})
	if err != nil {
		return fmt.Errorf("failed to rebuild btc htlc: %w", err)
	}

	claimTxid, err := h.claimBtcLockup(
		swap.Id, htlcScript, claimKey, preimage, info.DestinationAddress, status.Transaction.Hex,
	)
	if err != nil {
		return fmt.Errorf("failed to claim btc lockup: %w", err)
	}

	swap.Status = int(SwapStatusSuccess)
	swap.ChainSwap.FundingTxid = status.Transaction.Id
	swap.ChainSwap.RedeemTxid = claimTxid
	log.Debugf("swap recovery: chain swap %s claimed btc with tx %s", swap.Id, claimTxid)
	return h.persistUpdatedSwap(ctx, *swap)
}

// recoverBtcToArkadeChainSwap claims the vhtlc Boltz funded, if any. If the swap failed, it
// re-schedules the refund of the btc lockup we funded, if any: the ephemeral refund key
// survives the restart in the swap record, the scheduled refund task doesn't.
func (h *SwapManager) recoverBtcToArkadeChainSwap(
	ctx context.Context, swap *swaptypes.Swap, event boltz.SwapUpdateEvent,
) error {
	switch event {
	case boltz.TransactionServerMempoool, boltz.TransactionServerConfirmed:
		preimage, err := h.swapPreimage(ctx, swap)
		if err != nil {
			return err
		}
		txid, err := h.wallet.ClaimVHTLC(ctx, swap.VHTLCScript, preimage)
		if err != nil {
			return fmt.Errorf("failed to claim vhtlc: %w", err)
		}
		swap.Status = int(SwapStatusSuccess)
		swap.RedeemTxid = txid
		log.Debugf("swap recovery: chain swap %s claimed with tx %s", swap.Id, txid)
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.TransactionClaimed:
		// Already claimed before the restart, only the store was left behind.
		swap.Status = int(SwapStatusSuccess)
		return h.persistUpdatedSwap(ctx, *swap)
	case boltz.SwapExpired, boltz.TransactionFailed, boltz.TransactionLockupFailed:
		swap.Status = int(SwapStatusFailed)
		if err := h.persistUpdatedSwap(ctx, *swap); err != nil {
			return err
		}
		if swap.ChainSwap.FundingTxid == "" {
			return nil
		}
		return h.recoverBtcRefund(ctx, swap)
	default:
		log.Debugf(
			"swap recovery: chain swap %s not actionable in status %d, leaving pending",
			swap.Id, event,
		)
		return nil
	}
}

// recoverBtcRefund schedules the refund of the btc lockup of a failed Btc -> Arkade chain swap
// at the block height its locktime expires. The task fires immediately if it's already past.
func (h *SwapManager) recoverBtcRefund(ctx context.Context, swap *swaptypes.Swap) error {
	htlcScript, refundKey, err := h.getSwapHtlc(ctx, swap)
	if err != nil {
		return err
	}
	return h.scheduleBtcRefund(swap, htlcScript, refundKey)
}

// recoverRefund refunds the vhtlc funding the given swap. If the refund locktime has already
// expired, it goes straight for the trustless unilateral refund; otherwise it tries the
// collaborative refund first and schedules the unilateral one only as a fallback.
func (h *SwapManager) recoverRefund(ctx context.Context, swap *swaptypes.Swap) error {
	contractArgs, err := h.getSwapContractArgs(ctx, swap)
	if err != nil {
		return err
	}

	expired, err := h.refundLocktimeExpired(contractArgs.RefundLocktime)
	if err != nil {
		return err
	}
	if expired {
		// scheduleUnilateralRefund fires the refund immediately when the locktime is past.
		return h.scheduleUnilateralRefund(swap, contractArgs.RefundLocktime)
	}

	if _, _, err := h.refundSwap(swap, contractArgs); err != nil {
		return fmt.Errorf("failed to refund: %w", err)
	}
	return nil
}

// refundLocktimeExpired reports whether the given absolute refund locktime, expressed either in
// seconds or in block height, is already in the past.
func (h *SwapManager) refundLocktimeExpired(locktime arklib.AbsoluteLocktime) (bool, error) {
	if locktime.IsSeconds() {
		return time.Now().Unix() >= int64(locktime), nil
	}
	height, err := h.wallet.Explorer().GetBlockHeight()
	if err != nil {
		return false, fmt.Errorf("failed to get block height: %w", err)
	}
	return height >= int64(locktime), nil
}

// swapPreimage returns the preimage of the given swap, either the persisted one or, as a
// fallback, re-derived from the receiver key of its vhtlc contract.
func (h *SwapManager) swapPreimage(
	ctx context.Context, swap *swaptypes.Swap,
) (vhtlc.Preimage, error) {
	if len(swap.Preimage) > 0 {
		return vhtlc.Preimage(swap.Preimage), nil
	}

	contractArgs, err := h.getSwapContractArgs(ctx, swap)
	if err != nil {
		return nil, err
	}
	if contractArgs.ReceiverKeyId == "" {
		return nil, fmt.Errorf("we are not the receiver of the vhtlc, cannot derive preimage")
	}

	signer, ok := h.wallet.Identity().(PreimageSigner)
	if !ok {
		return nil, fmt.Errorf("wallet identity does not support preimage derivation")
	}

	return DerivePreimage(ctx, signer, identity.KeyRef{
		Id:     contractArgs.ReceiverKeyId,
		PubKey: contractArgs.Receiver,
	})
}
