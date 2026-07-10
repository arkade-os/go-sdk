package swap

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/go-sdk/swap/boltz"
	swapstore "github.com/arkade-os/go-sdk/swap/store/domain"
	log "github.com/sirupsen/logrus"
)

func (h *SwapHandler) persistSwap(
	ctx context.Context,
	swap Swap,
	from, to boltz.Currency,
	vhtlcContractScript string,
) error {
	if h.store == nil || h.store.Swaps() == nil {
		return nil
	}
	count, err := h.store.Swaps().Add(ctx, []swapstore.Swap{{
		ID:                  swap.Id,
		Amount:              swap.Amount,
		Timestamp:           swap.Timestamp,
		ToCurrency:          string(to),
		FromCurrency:        string(from),
		Status:              int(swap.Status),
		Invoice:             swap.Invoice,
		FundingTxID:         swap.TxId,
		RedeemTxID:          swap.RedeemTxid,
		VHTLCContractScript: vhtlcContractScript,
	}})
	if err != nil {
		return fmt.Errorf("persist swap %s: %w", swap.Id, err)
	}

	log.Debugf("persisted %v swaps", count)

	return nil
}

func (h *SwapHandler) updatePersistedSwap(ctx context.Context, swap Swap) error {
	if h.store == nil || h.store.Swaps() == nil {
		return nil
	}
	if err := h.store.Swaps().Update(ctx, swapstore.Swap{
		ID:         swap.Id,
		Status:     int(swap.Status),
		RedeemTxID: swap.RedeemTxid,
	}); err != nil {
		return fmt.Errorf("update persisted swap %s: %w", swap.Id, err)
	}
	return nil
}

func (h *SwapHandler) persistChainSwap(
	ctx context.Context,
	swap *ChainSwap,
	from, to boltz.Currency,
) error {
	if h.store == nil || h.store.ChainSwaps() == nil {
		return nil
	}
	if err := h.store.ChainSwaps().Add(ctx, chainSwapRecord(swap, from, to)); err != nil {
		return fmt.Errorf("persist chain swap %s: %w", swap.Id, err)
	}
	return nil
}

func (h *SwapHandler) persistChainSwapEventCallback(
	next ChainSwapEventCallback,
) ChainSwapEventCallback {
	return func(event ChainSwapEvent) {
		if err := h.persistChainSwapEvent(context.Background(), event); err != nil {
			log.WithError(err).Warn("failed to persist chain swap event")
		}
		if next != nil {
			next(event)
		}
	}
}

func (h *SwapHandler) persistChainSwapEvent(
	ctx context.Context,
	event ChainSwapEvent,
) error {
	if h.store == nil || h.store.ChainSwaps() == nil {
		return nil
	}

	switch e := event.(type) {
	case UserLockEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapUserLocked)
			s.UserLockupTxID = e.TxID
		})
	case ServerLockEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapServerLocked)
			s.ServerLockupTxID = e.TxID
		})
	case ClaimEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapClaimed)
			s.ClaimTxID = e.TxID
		})
	case RefundEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapRefunded)
			s.RefundTxID = e.TxID
		})
	case RefundEventUnilaterally:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapRefundedUnilaterally)
			s.RefundTxID = e.TxID
		})
	case FailEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapFailed)
			s.ErrorMessage = e.Error
		})
	case RefundFailedEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapRefundFailed)
			s.ErrorMessage = e.Error
		})
	case UserLockFailedEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *swapstore.ChainSwap) {
			s.Status = int(ChainSwapUserLockedFailed)
			s.ErrorMessage = e.Error
		})
	default:
		return nil
	}
}

func (h *SwapHandler) updatePersistedChainSwap(
	ctx context.Context,
	id string,
	update func(*swapstore.ChainSwap),
) error {
	if h.store == nil || h.store.ChainSwaps() == nil {
		return nil
	}
	record, err := h.store.ChainSwaps().Get(ctx, id)
	if err != nil {
		return err
	}
	update(record)
	return h.store.ChainSwaps().Update(ctx, *record)
}

func chainSwapRecord(
	swap *ChainSwap,
	from, to boltz.Currency,
) swapstore.ChainSwap {
	swap.mu.RLock()
	defer swap.mu.RUnlock()

	return swapstore.ChainSwap{
		ID:                      swap.Id,
		FromCurrency:            string(from),
		ToCurrency:              string(to),
		Amount:                  swap.Amount,
		Status:                  int(swap.Status),
		UserLockupTxID:          swap.UserLockTxid,
		ServerLockupTxID:        swap.ServerLockTxid,
		ClaimTxID:               swap.ClaimTxid,
		ClaimPreimage:           hex.EncodeToString(swap.Preimage),
		RefundTxID:              swap.RefundTxid,
		UserBTCLockupAddress:    swap.UserBtcLockupAddress,
		BTCHTLCPrivateKey:       swap.BTCHTLCPrivateKey,
		ErrorMessage:            swap.Error,
		BoltzCreateResponseJSON: swap.SwapRespJson,
		CreatedAt:               swap.Timestamp,
		UpdatedAt:               swap.Timestamp,
	}
}
