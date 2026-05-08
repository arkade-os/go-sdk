package arksdk

import (
	"context"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

const (
	defaultAutoSettleInitialRetryBackoff = 5 * time.Second
	defaultAutoSettleMaxRetryBackoff     = time.Minute
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
	// retryBackoff is the delay for the next retry after a failed Settle.
	// Zero means the next failure uses initialRetryBackoff.
	retryBackoff time.Duration
	// initialRetryBackoff and maxRetryBackoff are optional test overrides.
	// Zero values use the package defaults.
	initialRetryBackoff time.Duration
	maxRetryBackoff     time.Duration
	mu                  sync.Mutex

	// hooks holds the external calls made by the scheduler.
	// nil means "use the defaults" so the zero-value struct stays valid.
	// Tests can pre-populate this field with stub implementations to exercise
	// the scheduler in isolation.
	hooks *autoSettleHooks
}

// autoSettleHooks holds the external calls made by the auto-settle scheduler.
// The defaults wrap the real arkClient methods; tests inject counter/spy
// implementations to exercise the scheduler in isolation.
type autoSettleHooks struct {
	settle                   func(ctx context.Context) error
	isLocked                 func(ctx context.Context) bool
	getConfigData            func(ctx context.Context) (*clientTypes.Config, error)
	listSpendableVtxos       func(ctx context.Context) ([]clientTypes.Vtxo, error)
	listUnspentBoardingUtxos func(ctx context.Context) ([]clientTypes.Utxo, error)
}

// resolveAutoSettleHooks returns the configured hooks or the real
// arkClient-backed defaults when none have been injected.
func (a *arkClient) resolveAutoSettleHooks() autoSettleHooks {
	hooks := autoSettleHooks{
		settle: func(ctx context.Context) error {
			_, err := a.Settle(ctx)
			return err
		},
		isLocked: func(ctx context.Context) bool {
			return a.IsLocked(ctx)
		},
		getConfigData: func(ctx context.Context) (*clientTypes.Config, error) {
			return a.GetConfigData(ctx)
		},
		listSpendableVtxos: func(ctx context.Context) ([]clientTypes.Vtxo, error) {
			return a.ListSpendableVtxos(ctx)
		},
		listUnspentBoardingUtxos: func(ctx context.Context) ([]clientTypes.Utxo, error) {
			return a.listUnspentBoardingUtxos(ctx)
		},
	}
	if a.autoSettlement.hooks == nil {
		return hooks
	}

	custom := *a.autoSettlement.hooks
	if custom.settle != nil {
		hooks.settle = custom.settle
	}
	if custom.isLocked != nil {
		hooks.isLocked = custom.isLocked
	}
	if custom.getConfigData != nil {
		hooks.getConfigData = custom.getConfigData
	}
	if custom.listSpendableVtxos != nil {
		hooks.listSpendableVtxos = custom.listSpendableVtxos
	}
	if custom.listUnspentBoardingUtxos != nil {
		hooks.listUnspentBoardingUtxos = custom.listUnspentBoardingUtxos
	}
	return hooks
}

// autoSettleLoop is the long-lived goroutine that drives automatic settlement
// scheduling for an unlocked wallet. It is launched from Unlock() when
// WithAutoSettle() was passed at construction time and exits cleanly when ctx
// is cancelled (which happens via stopFn() in both Lock() and Stop()).
//
// Lifecycle:
//
//  1. Defensive delegate-mode guard: option validation rejects auto-settle with
//     delegate mode, but internally-constructed clients can still set both.
//  2. Wait for the initial sync to complete via a.IsSynced(ctx) so wallet state
//     is ready for VTXO/UTXO reads. The snapshot may still be empty.
//  3. Subscribe to VTXO and UTXO event channels before any immediate Settle()
//     call, so settlement-created events cannot be missed.
//  4. Read spendable VTXOs plus unspent boarding UTXOs and compute the next
//     settlement-relevant expiry. Transient snapshot read failures are retried
//     with backoff while the loop keeps processing VTXO/UTXO events. If a VTXO
//     expiry is already in the past, trigger Settle() immediately; otherwise,
//     schedule a single-shot timer for expiry - 2 * SessionDuration.
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

	hooks := a.resolveAutoSettleHooks()
	cfg, err := hooks.getConfigData(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to get config data, aborting")
		return
	}

	vtxoCh := a.GetVtxoEventChannel(ctx)
	utxoCh := a.GetUtxoEventChannel(ctx)
	// Lock can run while Unlock is still starting this goroutine. In that case,
	// the event channels may already be cleared and these getters return nil.
	// The select below can keep those nil channels: Go ignores nil-channel cases
	// in a select, and the same Lock call cancels ctx so ctx.Done() exits the loop.

	// Snapshot retry restores the baseline view of funds: VTXOs/UTXOs that
	// already existed when auto-settle started. Event channels cover new changes,
	// but they do not guarantee replay of that existing state. Keeping the retry
	// timer in the select loop lets new events schedule settlement while the
	// baseline read is waiting to be retried.
	var snapshotRetryTimer *time.Timer
	var snapshotRetryCh <-chan time.Time
	var snapshotRetryBackoff time.Duration

	// stopSnapshotRetry is used on loop exit to release a pending retry timer and
	// reset retry state.
	stopSnapshotRetry := func() {
		if snapshotRetryTimer != nil {
			snapshotRetryTimer.Stop()
		}
		snapshotRetryTimer = nil
		snapshotRetryCh = nil
		snapshotRetryBackoff = 0
	}
	defer stopSnapshotRetry()

	// scheduleSnapshotRetry arms exactly one baseline snapshot retry. The retry
	// stops once scheduleFromCurrentFunds returns true; another retry is armed
	// only when that snapshot read fails again.
	scheduleSnapshotRetry := func() {
		if snapshotRetryTimer != nil || ctx.Err() != nil {
			return
		}
		// Use a timer case instead of sleeping here so the loop keeps consuming
		// VTXO/UTXO events while waiting to retry the baseline snapshot.
		snapshotRetryBackoff = nextAutoSettleRetryBackoff(
			snapshotRetryBackoff,
			a.autoSettlement.initialRetryBackoff,
			a.autoSettlement.maxRetryBackoff,
		)
		snapshotRetryTimer = time.NewTimer(snapshotRetryBackoff)
		snapshotRetryCh = snapshotRetryTimer.C
	}

	if !a.scheduleFromCurrentFunds(ctx, cfg, hooks) {
		// The initial baseline read failed. Keep the event loop running and retry
		// later, because existing funds will not necessarily produce a new event.
		scheduleSnapshotRetry()
	}

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

		case <-snapshotRetryCh:
			snapshotRetryTimer = nil
			snapshotRetryCh = nil
			if a.scheduleFromCurrentFunds(ctx, cfg, hooks) {
				// A successful snapshot read means the baseline was restored, even
				// if there were no funds to schedule. Clear backoff and do not arm
				// another retry.
				snapshotRetryBackoff = 0
				continue
			}
			scheduleSnapshotRetry()
		}
	}
}

// scheduleFromCurrentFunds reads the current spendable VTXOs and unspent boarding
// UTXOs, then schedules the earliest settlement-relevant expiry found. A true
// return means the snapshot read succeeded, even if the wallet had no funds to
// schedule; false means the read failed and the caller should retry the baseline
// snapshot later.
func (a *arkClient) scheduleFromCurrentFunds(
	ctx context.Context, cfg *clientTypes.Config, hooks autoSettleHooks,
) bool {
	if ctx.Err() != nil {
		return false
	}

	vtxos, err := hooks.listSpendableVtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to list spendable vtxos")
		return false
	}
	boardingUtxos, err := hooks.listUnspentBoardingUtxos(ctx)
	if err != nil {
		log.WithError(err).Warn("auto-settle: failed to list boarding utxos")
		return false
	}

	now := time.Now()
	nextExpiry, ok := nextSettlementExpiry(now, vtxos, boardingUtxos)
	if !ok {
		return true
	}
	if nextExpiry.Before(now) {
		// at least one spendable VTXO has already expired — settle
		// immediately rather than waiting for a timer.
		a.settleWithRetry(ctx, hooks, "auto-settle: immediate settle failed")
		return true
	}
	a.scheduleSettle(ctx, nextExpiry, cfg)
	return true
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
	a.scheduleSettleAt(ctx, fireAt, hooks, true)
}

func (a *arkClient) scheduleSettleAt(
	ctx context.Context, fireAt time.Time, hooks autoSettleHooks, resetRetry bool,
) {
	if ctx.Err() != nil {
		return
	}

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
	if resetRetry {
		a.autoSettlement.retryBackoff = 0
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
		a.settleWithRetry(ctx, hooks, "auto-settle: scheduled settle failed")
	})
	a.autoSettlement.settleTimer = timer
	a.autoSettlement.mu.Unlock()

	log.WithFields(log.Fields{
		"settle_at": fireAt,
		"delay":     delay.String(),
		"retry":     !resetRetry,
	}).Info("auto-settle: settlement scheduled")
}

func (a *arkClient) settleWithRetry(
	ctx context.Context, hooks autoSettleHooks, failureMessage string,
) {
	if err := hooks.settle(ctx); err != nil {
		log.WithError(err).Warn(failureMessage)
		a.scheduleSettleRetry(ctx, hooks)
		return
	}
	a.resetSettleRetryBackoff()
	log.Info("auto-settle: settlement completed successfully")
}

func (a *arkClient) scheduleSettleRetry(ctx context.Context, hooks autoSettleHooks) {
	if ctx.Err() != nil {
		return
	}

	a.autoSettlement.mu.Lock()
	delay := a.nextSettleRetryBackoffLocked()
	a.autoSettlement.mu.Unlock()

	a.scheduleSettleAt(ctx, time.Now().Add(delay), hooks, false)
}

func (a *arkClient) nextSettleRetryBackoffLocked() time.Duration {
	a.autoSettlement.retryBackoff = nextAutoSettleRetryBackoff(
		a.autoSettlement.retryBackoff,
		a.autoSettlement.initialRetryBackoff,
		a.autoSettlement.maxRetryBackoff,
	)
	return a.autoSettlement.retryBackoff
}

func nextAutoSettleRetryBackoff(
	current, initial, maxBackoff time.Duration,
) time.Duration {
	if initial <= 0 {
		initial = defaultAutoSettleInitialRetryBackoff
	}
	if maxBackoff <= 0 {
		maxBackoff = defaultAutoSettleMaxRetryBackoff
	}
	if maxBackoff < initial {
		maxBackoff = initial
	}
	if current <= 0 {
		return initial
	}
	current *= 2
	if current > maxBackoff {
		return maxBackoff
	}
	return current
}

func (a *arkClient) resetSettleRetryBackoff() {
	a.autoSettlement.mu.Lock()
	a.autoSettlement.retryBackoff = 0
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
	a.autoSettlement.retryBackoff = 0
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
