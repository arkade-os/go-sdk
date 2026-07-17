package types

import (
	"context"

	"github.com/arkade-os/go-sdk/swap/boltz"
)

// ChainSwapEventHandler defines swap-specific behavior for both directions of chain swaps
// (Arkade <> BTC).
type ChainSwapEventHandler interface {
	// OnSwapCreated handles initial swap creation
	OnSwapCreated(ctx context.Context, update boltz.SwapUpdate) error

	// OnLockupFailed handles various failure scenarios
	OnLockupFailed(ctx context.Context, update boltz.SwapUpdate) error

	OnUserLockedMempool(ctx context.Context, update boltz.SwapUpdate) error

	// OnUserLocked handles user lockup confirmation
	OnUserLocked(ctx context.Context, update boltz.SwapUpdate) error

	// OnServerLockedMempool handles server lockup (ready to claim)
	OnServerLockedMempool(ctx context.Context, update boltz.SwapUpdate) error

	// OnServerLocked handles server lockup (ready to claim)
	OnServerLocked(ctx context.Context, update boltz.SwapUpdate) error

	OnSwapExpired(ctx context.Context, update boltz.SwapUpdate) error

	OnTransactionFailed(ctx context.Context, update boltz.SwapUpdate) error
}

// SwapEventHandler defines swap-specific behavior for submarine (Arkade→LN) and reverse
// (LN→Arkade) swaps, mirroring the strategy pattern of ChainSwapEventHandler.
type SwapEventHandler interface {
	// OnSwapCreated handles the initial swap creation ack.
	OnSwapCreated(ctx context.Context, update boltz.SwapUpdate) error

	// OnTransactionMempool handles a lockup tx detected in mempool: the user (Ark) lockup
	// for submarine swaps, the server (Boltz) one for reverse swaps.
	OnTransactionMempool(ctx context.Context, update boltz.SwapUpdate) error

	// OnRransactionConfirmed handles the confirmation of the lockup tx.
	OnTransactionConfirmed(ctx context.Context, update boltz.SwapUpdate) error

	// OnTransactionClaimed handles the claim of the lockup by the counterparty.
	OnTransactionClaimed(ctx context.Context, update boltz.SwapUpdate) error

	// OnLockupFailed handles a failed lockup tx.
	OnLockupFailed(ctx context.Context, update boltz.SwapUpdate) error

	// OnInvoiceSettled handles the settlement of the swap invoice.
	OnInvoiceSettled(ctx context.Context, update boltz.SwapUpdate) error

	// OnInvoiceFailedToPay handles a failed payment of the swap invoice.
	OnInvoiceFailedToPay(ctx context.Context, update boltz.SwapUpdate) error

	OnSwapExpired(ctx context.Context, update boltz.SwapUpdate) error

	OnTransactionFailed(ctx context.Context, update boltz.SwapUpdate) error

	OnTimeout(ctx context.Context) error
}
