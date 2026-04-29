package arksdk

import (
	"context"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

type autoSettlementInfo struct {
	// enabled and delegateMode are configured at construction time via
	// clientOptions and never mutated afterwards.
	enabled      bool
	delegateMode bool

	// nextSettleAt is the time at which the currently-pending auto-settle
	// will fire. Zero value means no schedule is active.
	// Guarded by mu together with settleTimer.
	nextSettleAt time.Time
	// settleTimer is the active one-shot timer that invokes Settle at
	// nextSettleAt. It is kept so new earlier expiries, Lock, and Stop can
	// cancel the pending callback before it runs.
	settleTimer *time.Timer
	mu          sync.Mutex

	// hooks holds the side-effecting calls made by the scheduler.
	// nil means "use the defaults" so the zero-value struct stays valid.
	// Tests can pre-populate this field with stub implementations to exercise
	// the scheduler in isolation.
	hooks *autoSettleHooks
}

// autoSettleHooks holds the side-effecting calls made by the auto-settle
// scheduler. The defaults wrap the real arkClient methods; tests inject
// counter/spy implementations to exercise the scheduler in isolation.
type autoSettleHooks struct {
	settle   func(ctx context.Context) error
	isLocked func(ctx context.Context) bool
}

// resolveAutoSettleHooks returns the configured hooks or the real
// arkClient-backed defaults when none have been injected.
func (a *arkClient) resolveAutoSettleHooks() autoSettleHooks {
	if a.autoSettlement.hooks != nil {
		return *a.autoSettlement.hooks
	}
	return autoSettleHooks{
		settle: func(ctx context.Context) error {
			_, err := a.Settle(ctx)
			return err
		},
		isLocked: func(ctx context.Context) bool {
			return a.IsLocked(ctx)
		},
	}
}

// autoSettleLoop is the long-lived goroutine that drives automatic settlement
// scheduling for an unlocked wallet. It is launched from Unlock() when
// WithAutoSettle() was passed at construction time and exits cleanly when ctx
// is cancelled (which happens via stopFn() in both Lock() and Stop()).
//
// Lifecycle:
//
//  1. Delegate-mode guard: if the placeholder delegateMode field is true, log
//     and exit immediately.
//  2. Wait for the initial sync to complete via a.IsSynced(ctx) so that
//     ListSpendableVtxos returns a populated set.
//  3. Subscribe to VTXO and UTXO event channels before any immediate Settle()
//     call, so settlement-created events cannot be missed.
//  4. Read spendable VTXOs plus unspent boarding UTXOs and compute the next
//     settlement-relevant expiry. If a VTXO expiry is already in the past,
//     trigger Settle() immediately, otherwise schedule a single-shot
//     timer for expiry - 2 * SessionDuration.
//  5. On every VtxosAdded or boarding UTXO add/confirm/replace event, reschedule
//     if the new event's expiry produces an earlier fire time.
//  6. On ctx.Done(), stop any pending timer, clear nextSettleAt, and exit.
func (a *arkClient) autoSettleLoop(ctx context.Context) {
	if a.autoSettlement.delegateMode {
		log.Warn("auto-settle: delegate mode is active; WithAutoSettle has no effect")
		return
	}

	// Wait for initial sync. IsSynced returns a buffered channel that delivers
	// exactly one event, so we don't need to drain it.
	select {
	case <-ctx.Done():
		return
	case syncEvent, ok := <-a.IsSynced(ctx):
		if !ok {
			return
		}
		if !syncEvent.Synced {
			if syncEvent.Err != nil {
				log.WithError(syncEvent.Err).Warn("auto-settle: sync failed, aborting")
			} else {
				log.Warn("auto-settle: sync did not complete, aborting")
			}
			return
		}
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to get config data, aborting")
		return
	}

	hooks := a.resolveAutoSettleHooks()
	vtxoCh := a.GetVtxoEventChannel(ctx)
	utxoCh := a.GetUtxoEventChannel(ctx)
	// These channels may be nil if the wallet was locked between Unlock and the
	// start of this loop. A select on a nil channel blocks forever, so this is
	// safe — ctx.Done() will still fire on Lock/Stop.

	a.scheduleFromCurrentFunds(ctx, cfg, hooks)

	for {
		select {
		case <-ctx.Done():
			a.cancelPendingSettle()
			return

		case event, ok := <-vtxoCh:
			if !ok {
				vtxoCh = nil
				continue
			}
			if event.Type != types.VtxosAdded {
				continue
			}

			// find the earliest expiry among the freshly-added VTXOs.
			// scheduleSettle compares computed fire times, so an expiry after the
			// current fire time can still move the schedule earlier.
			if nextExpiry, ok := nextSettlementExpiry(time.Now(), event.Vtxos, nil); ok {
				a.scheduleSettle(ctx, nextExpiry, cfg)
			}

		case event, ok := <-utxoCh:
			if !ok {
				utxoCh = nil
				continue
			}
			if !isBoardingUtxoScheduleEvent(event.Type) {
				continue
			}
			if nextExpiry, ok := nextSettlementExpiry(time.Now(), nil, event.Utxos); ok {
				a.scheduleSettle(ctx, nextExpiry, cfg)
			}
		}
	}
}

func (a *arkClient) scheduleFromCurrentFunds(
	ctx context.Context, cfg *clientTypes.Config, hooks autoSettleHooks,
) {
	if ctx.Err() != nil {
		return
	}

	vtxos, err := a.ListSpendableVtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to list spendable vtxos")
		return
	}
	boardingUtxos, err := a.listUnspentBoardingUtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to list boarding utxos")
		return
	}

	now := time.Now()
	nextExpiry, ok := nextSettlementExpiry(now, vtxos, boardingUtxos)
	if !ok {
		return
	}
	if nextExpiry.Before(now) {
		// at least one spendable VTXO has already expired — settle
		// immediately rather than waiting for a timer.
		if err := hooks.settle(ctx); err != nil {
			log.WithError(err).Warn("auto-settle: immediate settle failed")
		}
		return
	}
	a.scheduleSettle(ctx, nextExpiry, cfg)
}

// scheduleSettle (re)arms the auto-settle timer to fire at
// expiresAt - 2 * SessionDuration. If a strictly earlier schedule already
// exists, the call is a no-op.
//
// The timer callback re-checks IsLocked before invoking Settle() to handle
// the Lock/timer-fire race.
func (a *arkClient) scheduleSettle(
	ctx context.Context, expiresAt time.Time, cfg *clientTypes.Config,
) {
	hooks := a.resolveAutoSettleHooks()

	fireAt := settlementFireAt(expiresAt, cfg)
	now := time.Now()

	a.autoSettlement.mu.Lock()

	// Skip-if-earlier: keep the current schedule when it already fires sooner
	// than the candidate. We only apply this guard when the candidate is in
	// the future; an already-due candidate must always replace whatever we
	// have because the existing schedule may be far away.
	if !a.autoSettlement.nextSettleAt.IsZero() && fireAt.After(now) &&
		fireAt.After(a.autoSettlement.nextSettleAt) {
		a.autoSettlement.mu.Unlock()
		return
	}

	if a.autoSettlement.settleTimer != nil {
		a.autoSettlement.settleTimer.Stop()
		a.autoSettlement.settleTimer = nil
	}

	delay := fireAt.Sub(now)
	if delay < 0 {
		delay = 0
	}

	a.autoSettlement.nextSettleAt = fireAt
	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		claim := func() bool {
			a.autoSettlement.mu.Lock()
			defer a.autoSettlement.mu.Unlock()

			if a.autoSettlement.settleTimer != timer {
				return false
			}
			a.autoSettlement.nextSettleAt = time.Time{}
			a.autoSettlement.settleTimer = nil
			return ctx.Err() == nil
		}
		if !claim() {
			return
		}

		// Secondary guard against the Lock/timer-fire race: if Lock() ran
		// between scheduling and firing the wallet is locked and Settle would
		// fail noisily.
		if hooks.isLocked(ctx) {
			log.Debug("auto-settle: wallet locked at fire time, skipping settle")
			return
		}
		if ctx.Err() != nil {
			return
		}

		// Don't hold the auto-settle lock across Settle (it can publish vtxo
		// events that the loop wants to handle, which would deadlock).
		if err := hooks.settle(ctx); err != nil {
			log.WithError(err).Warn("auto-settle: scheduled settle failed")
		}
	})
	a.autoSettlement.settleTimer = timer
	a.autoSettlement.mu.Unlock()
}

// cancelPendingSettle stops a pending timer (if any) and clears the schedule.
// Used on context cancellation in autoSettleLoop and on Lock()/Stop().
func (a *arkClient) cancelPendingSettle() {
	a.autoSettlement.mu.Lock()
	if a.autoSettlement.settleTimer != nil {
		a.autoSettlement.settleTimer.Stop()
		a.autoSettlement.settleTimer = nil
	}
	a.autoSettlement.nextSettleAt = time.Time{}
	a.autoSettlement.mu.Unlock()
}

func (a *arkClient) listUnspentBoardingUtxos(ctx context.Context) ([]clientTypes.Utxo, error) {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	utxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	return utxos, err
}

func settlementFireAt(expiresAt time.Time, cfg *clientTypes.Config) time.Time {
	sessionDuration := time.Duration(cfg.SessionDuration) * time.Second
	return expiresAt.Add(-2 * sessionDuration)
}

func isBoardingUtxoScheduleEvent(eventType types.UtxoEventType) bool {
	return eventType == types.UtxosAdded ||
		eventType == types.UtxosConfirmed ||
		eventType == types.UtxosReplaced
}

// nextSettlementExpiry returns the earliest settlement-relevant expiry across
// spendable VTXOs and confirmed, unspent boarding UTXOs. Expired VTXOs are
// returned immediately so callers can renew them now; expired boarding UTXOs are
// ignored, matching Fulmine's computeNextExpiry behavior.
func nextSettlementExpiry(
	now time.Time, vtxos []clientTypes.Vtxo, boardingUtxos []clientTypes.Utxo,
) (time.Time, bool) {
	var next time.Time
	for _, v := range vtxos {
		if v.ExpiresAt.IsZero() {
			continue
		}
		if v.ExpiresAt.Before(now) {
			return v.ExpiresAt, true
		}
		if next.IsZero() || v.ExpiresAt.Before(next) {
			next = v.ExpiresAt
		}
	}

	for _, u := range boardingUtxos {
		expiry, ok := boardingUtxoExpiry(u)
		if !ok || expiry.Before(now) {
			continue
		}
		if next.IsZero() || expiry.Before(next) {
			next = expiry
		}
	}

	return next, !next.IsZero()
}

func boardingUtxoExpiry(utxo clientTypes.Utxo) (time.Time, bool) {
	if utxo.Spent || !utxo.IsConfirmed() {
		return time.Time{}, false
	}
	if !utxo.SpendableAt.IsZero() {
		return utxo.SpendableAt, true
	}
	return utxo.CreatedAt.Add(time.Duration(utxo.Delay.Seconds()) * time.Second), true
}
