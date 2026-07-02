package swap

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/go-sdk/swap/boltz"
	"github.com/arkade-os/go-sdk/vhtlc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	log "github.com/sirupsen/logrus"
)

func chainSwapMonitorContext(ctx context.Context) context.Context {
	// Chain swap monitors must survive cancellation of the request that created
	// or resumed the swap. The monitor exits via swap timeout or terminal state.
	return context.WithoutCancel(ctx)
}

func (h *SwapHandler) monitorAndClaimArkToBtcSwap(
	ctx context.Context,
	network *chaincfg.Params,
	eventCallback ChainSwapEventCallback,
	unilateralRefundCallback func(swapId string, opts vhtlc.Opts) error,
	btcClaimKey *btcec.PrivateKey,
	preimage []byte,
	btcDestinationAddress string,
	swapResp *boltz.CreateChainSwapResponse,
	swap *ChainSwap,
) {
	var (
		arkToBtc = true
		swapTree = swapResp.GetSwapTree(arkToBtc)
		swapId   = swap.Id
	)

	pk, err := parsePubkey(swapResp.ClaimDetails.ServerPublicKey)
	if err != nil {
		log.WithError(err).Errorf("Failed to parse server public key for swap %s", swapId)
		swap.Fail(fmt.Sprintf("parse server public key: %v", err))
		return
	}

	handler := NewArkToBtcHandler(
		h,
		ChainSwapState{
			SwapID:                   swapId,
			Timeout:                  time.Duration(h.timeout) * time.Second,
			EventCallback:            eventCallback,
			UnilateralRefundCallback: unilateralRefundCallback,
			Swap:                     swap,
		},
		network,
		btcClaimKey,
		preimage,
		btcDestinationAddress,
		swapResp,
		pk,
		swapTree,
	)

	h.monitorChainSwap(ctx, handler.GetState(), handler)
}

func (h *SwapHandler) monitorBtcToArkChainSwap(
	ctx context.Context,
	eventCallback ChainSwapEventCallback,
	preimage []byte,
	refundKey *btcec.PrivateKey,
	swapResp *boltz.CreateChainSwapResponse,
	swap *ChainSwap,
) {
	handler := NewBtcToArkHandler(
		h,
		ChainSwapState{
			SwapID:        swap.Id,
			Timeout:       time.Duration(h.timeout) * time.Second,
			EventCallback: eventCallback,
			Swap:          swap,
		},
		preimage,
		refundKey,
		swapResp,
	)

	h.monitorChainSwap(ctx, handler.GetState(), handler)
}

// monitorChainSwap is a generic WebSocket monitoring loop that delegates
// swap-specific event handling to the provided ChainSwapEventHandler.
// This extracts the common monitoring pattern used by both Ark→BTC and BTC→Ark swaps.
func (h *SwapHandler) monitorChainSwap(
	ctx context.Context,
	chainSwapState ChainSwapState,
	handler ChainSwapEventHandler,
) {
	swapId := handler.GetState().SwapID
	log.Infof("Starting WebSocket monitoring for chain swap %s", swapId)

	monitorCtx, cancel := context.WithTimeout(ctx, chainSwapState.Timeout)
	defer cancel()

	ws, err := h.connectChainSwapWebsocket(monitorCtx, swapId)
	if err != nil {
		log.WithError(err).Errorf("Failed to connect to WebSocket for swap %s", swapId)
		chainSwapState.Swap.Fail(fmt.Sprintf("websocket subscribe failed: %v", err))
		return
	}
	defer func() { _ = ws.Close() }()

	for {
		select {
		case update, ok := <-ws.Updates:
			if !ok {
				log.Warnf("WebSocket closed for chain swap %s, reconnecting", swapId)

				nextWs, err := h.connectChainSwapWebsocket(monitorCtx, swapId)
				if err != nil {
					log.WithError(err).Errorf("Failed to reconnect WebSocket for swap %s", swapId)
					chainSwapState.Swap.Fail(fmt.Sprintf("websocket reconnect failed: %v", err))
					return
				}

				_ = ws.Close()
				ws = nextWs
				continue
			}

			status := boltz.ParseEvent(update.Status)
			log.Infof("Chain swap %s status update: %d (raw: %s)", swapId, status, update.Status)

			var err error
			switch status {
			case boltz.SwapCreated:
				// boltz accepted swap request we created
				err = handler.HandleSwapCreated(monitorCtx, update)

			case boltz.TransactionLockupFailed:
				// user lockup tx failed, we need to fetch approve a new quote
				err = handler.HandleLockupFailed(monitorCtx, update)

			case boltz.TransactionMempool:
				// user lockup tx is in mempool
				err = handler.HandleUserLockedMempool(monitorCtx, update)

			case boltz.TransactionConfirmed:
				// user lockup tx confirmed
				err = handler.HandleUserLocked(monitorCtx, update)

			case boltz.TransactionServerMempoool:
				// boltz lockup tx in mempool
				err = handler.HandleServerLockedMempool(monitorCtx, update)

			case boltz.TransactionServerConfirmed:
				// boltz lockup tx confirmed
				err = handler.HandleServerLocked(monitorCtx, update)

			case boltz.SwapExpired:
				// swap expired
				err = handler.HandleSwapExpired(monitorCtx, update)

			case boltz.TransactionFailed:
				//?
				err = handler.HandleTransactionFailed(monitorCtx, update)

			default:
				log.Warnf("Unknown status %s (%d) for swap %s", update.Status, status, swapId)
				continue
			}

			// Handle errors from event handlers
			if err != nil {
				log.WithError(err).Errorf("Event handler error for swap %s", swapId)
				chainSwapState.Swap.Fail(err.Error())
				return
			}

			// Stop monitoring on terminal states to avoid false timeout failures.
			if chainSwapState.Swap.Status == ChainSwapClaimed ||
				chainSwapState.Swap.Status == ChainSwapFailed ||
				chainSwapState.Swap.Status == ChainSwapRefunded ||
				chainSwapState.Swap.Status == ChainSwapRefundedUnilaterally ||
				chainSwapState.Swap.Status == ChainSwapRefundFailed ||
				chainSwapState.Swap.Status == ChainSwapUserLockedFailed {
				return
			}

		case <-monitorCtx.Done():
			if monitorCtx.Err() != context.DeadlineExceeded {
				log.Infof("Context cancelled for swap %s monitoring", swapId)
				chainSwapState.Swap.Fail("context cancelled")
				return
			}

			log.Warnf("Swap %s monitoring timed out after %v", swapId, chainSwapState.Timeout)
			chainSwapState.Swap.Fail(
				fmt.Sprintf("monitoring timed out after %v", chainSwapState.Timeout),
			)
			return
		}
	}
}

func (h *SwapHandler) connectChainSwapWebsocket(
	ctx context.Context,
	swapId string,
) (*boltz.Websocket, error) {
	ws := h.boltzSvc.NewWebsocket()
	if err := ws.ConnectAndSubscribe(ctx, []string{swapId}, 5*time.Second); err != nil {
		_ = ws.Close()
		return nil, err
	}

	return ws, nil
}

// ChainSwapEventHandler defines swap-specific behavior for different swap directions.
// This interface uses the strategy pattern to extract common WebSocket monitoring logic.
type ChainSwapEventHandler interface {
	// HandleSwapCreated handles initial swap creation
	HandleSwapCreated(ctx context.Context, update boltz.SwapUpdate) error

	// HandleLockupFailed handles various failure scenarios
	HandleLockupFailed(ctx context.Context, update boltz.SwapUpdate) error

	HandleUserLockedMempool(ctx context.Context, update boltz.SwapUpdate) error

	// HandleUserLocked handles user lockup confirmation
	HandleUserLocked(ctx context.Context, update boltz.SwapUpdate) error

	// HandleServerLockedMempool handles server lockup (ready to claim)
	HandleServerLockedMempool(ctx context.Context, update boltz.SwapUpdate) error

	// HandleServerLocked handles server lockup (ready to claim)
	HandleServerLocked(ctx context.Context, update boltz.SwapUpdate) error

	HandleSwapExpired(ctx context.Context, update boltz.SwapUpdate) error

	HandleTransactionFailed(ctx context.Context, update boltz.SwapUpdate) error

	GetState() ChainSwapState
}

type ChainSwapState struct {
	SwapID                   string
	Timeout                  time.Duration
	EventCallback            ChainSwapEventCallback
	UnilateralRefundCallback func(swapId string, opts vhtlc.Opts) error
	Swap                     *ChainSwap
}
