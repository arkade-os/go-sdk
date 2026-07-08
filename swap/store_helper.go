package swap

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/arkade-os/go-sdk/swap/boltz"
	log "github.com/sirupsen/logrus"
)

func (h *SwapHandler) persistSwap(
	ctx context.Context,
	swap Swap,
	from, to boltz.Currency,
	swapType SwapRecordType,
	vhtlcContractScript string,
) error {
	if h.store == nil || h.store.Swaps() == nil {
		return nil
	}
	_, err := h.store.Swaps().Add(ctx, []SwapRecord{{
		ID:                  swap.Id,
		Amount:              swap.Amount,
		Timestamp:           swap.Timestamp,
		ToCurrency:          string(to),
		FromCurrency:        string(from),
		Status:              swap.Status,
		Type:                swapType,
		Invoice:             swap.Invoice,
		FundingTxID:         swap.TxId,
		RedeemTxID:          swap.RedeemTxid,
		VHTLCContractScript: vhtlcContractScript,
	}})
	if err != nil {
		return fmt.Errorf("persist swap %s: %w", swap.Id, err)
	}
	return nil
}

func (h *SwapHandler) updatePersistedSwap(ctx context.Context, swap Swap) error {
	if h.store == nil || h.store.Swaps() == nil {
		return nil
	}
	if err := h.store.Swaps().Update(ctx, SwapRecord{
		ID:         swap.Id,
		Status:     swap.Status,
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
	from, to boltz.Currency,
	next ChainSwapEventCallback,
) ChainSwapEventCallback {
	return func(event ChainSwapEvent) {
		if err := h.persistChainSwapEvent(context.Background(), from, to, event); err != nil {
			log.WithError(err).Warn("failed to persist chain swap event")
		}
		if next != nil {
			next(event)
		}
	}
}

func (h *SwapHandler) persistChainSwapEvent(
	ctx context.Context,
	from, to boltz.Currency,
	event ChainSwapEvent,
) error {
	if h.store == nil || h.store.ChainSwaps() == nil {
		return nil
	}

	switch e := event.(type) {
	case CreateEvent:
		return h.store.ChainSwaps().Add(ctx, ChainSwapRecord{
			ID:                      e.Id,
			FromCurrency:            string(from),
			ToCurrency:              string(to),
			Amount:                  e.Amount,
			Status:                  e.Status,
			ClaimPreimage:           hex.EncodeToString(e.Preimage),
			UserBTCLockupAddress:    e.UserBtcLockupAddress,
			BoltzCreateResponseJSON: e.SwapRespJson,
			CreatedAt:               e.Timestamp,
			UpdatedAt:               e.Timestamp,
		})
	case UserLockEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapUserLocked
			s.UserLockupTxID = e.TxID
		})
	case ServerLockEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapServerLocked
			s.ServerLockupTxID = e.TxID
		})
	case ClaimEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapClaimed
			s.ClaimTxID = e.TxID
		})
	case RefundEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapRefunded
			s.RefundTxID = e.TxID
		})
	case RefundEventUnilaterally:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapRefundedUnilaterally
			s.RefundTxID = e.TxID
		})
	case FailEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapFailed
			s.ErrorMessage = e.Error
		})
	case RefundFailedEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapRefundFailed
			s.ErrorMessage = e.Error
		})
	case UserLockFailedEvent:
		return h.updatePersistedChainSwap(ctx, e.SwapID, func(s *ChainSwapRecord) {
			s.Status = ChainSwapUserLockedFailed
			s.ErrorMessage = e.Error
		})
	default:
		return nil
	}
}

func (h *SwapHandler) updatePersistedChainSwap(
	ctx context.Context,
	id string,
	update func(*ChainSwapRecord),
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
) ChainSwapRecord {
	swap.mu.RLock()
	defer swap.mu.RUnlock()

	return ChainSwapRecord{
		ID:                      swap.Id,
		FromCurrency:            string(from),
		ToCurrency:              string(to),
		Amount:                  swap.Amount,
		Status:                  swap.Status,
		UserLockupTxID:          swap.UserLockTxid,
		ServerLockupTxID:        swap.ServerLockTxid,
		ClaimTxID:               swap.ClaimTxid,
		ClaimPreimage:           hex.EncodeToString(swap.Preimage),
		RefundTxID:              swap.RefundTxid,
		UserBTCLockupAddress:    swap.UserBtcLockupAddress,
		ErrorMessage:            swap.Error,
		BoltzCreateResponseJSON: swap.SwapRespJson,
		CreatedAt:               swap.Timestamp,
		UpdatedAt:               swap.Timestamp,
	}
}
