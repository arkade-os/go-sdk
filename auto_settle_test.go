package arksdk

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestScheduleSettle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		locked bool
		run    func(t *testing.T, a *arkClient, calls *atomic.Int32)
	}{
		{
			name: "schedules future expiry",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}
				expiresAt := time.Now().Add(30 * time.Minute)

				a.scheduleSettle(context.Background(), expiresAt, cfg)

				got := a.WhenNextSettlement()
				require.False(
					t,
					got.IsZero(),
					"WhenNextSettlement should be set after scheduleSettle",
				)
				require.WithinDuration(t, settlementFireAt(expiresAt, cfg), got, time.Second)
				require.Equal(t, int32(0), calls.Load(), "settle must not fire before its delay")
			},
		},
		{
			name: "reschedules earlier expiry and keeps later candidate out",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}

				firstExpiry := time.Now().Add(30 * time.Minute)
				a.scheduleSettle(context.Background(), firstExpiry, cfg)
				first := a.WhenNextSettlement()
				require.False(t, first.IsZero())

				earlierExpiry := time.Now().Add(10 * time.Minute)
				a.scheduleSettle(context.Background(), earlierExpiry, cfg)
				second := a.WhenNextSettlement()
				require.True(t, second.Before(first), "earlier expiry should move schedule earlier")
				require.WithinDuration(t, settlementFireAt(earlierExpiry, cfg), second, time.Second)

				a.scheduleSettle(context.Background(), time.Now().Add(45*time.Minute), cfg)
				require.Equal(
					t,
					second,
					a.WhenNextSettlement(),
					"later schedule must not displace earlier one",
				)
				require.Equal(t, int32(0), calls.Load(), "settle must not fire before delay")
			},
		},
		{
			name: "reschedules when expiry is after current fire time",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60 * 60}

				firstExpiry := time.Now().Add(4 * time.Hour)
				a.scheduleSettle(context.Background(), firstExpiry, cfg)
				firstFireAt := a.WhenNextSettlement()
				require.False(t, firstFireAt.IsZero())

				newExpiry := firstExpiry.Add(-30 * time.Minute)
				require.True(t, newExpiry.After(firstFireAt),
					"this reproduces the expiry-vs-fire-time comparison bug")

				a.scheduleSettle(context.Background(), newExpiry, cfg)
				secondFireAt := a.WhenNextSettlement()
				require.True(t, secondFireAt.Before(firstFireAt))
				require.WithinDuration(
					t,
					settlementFireAt(newExpiry, cfg),
					secondFireAt,
					time.Second,
				)
				require.Equal(t, int32(0), calls.Load(), "settle must not fire before delay")
			},
		},
		{
			name: "fires immediately for expired candidate",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}

				a.scheduleSettle(context.Background(), time.Now().Add(-time.Hour), cfg)

				waitFor(t, 500*time.Millisecond, func() bool { return calls.Load() == 1 })
				waitFor(
					t,
					200*time.Millisecond,
					func() bool { return a.WhenNextSettlement().IsZero() },
				)
				require.Equal(t, int32(1), calls.Load(), "expected exactly one settle call")
			},
		},
		{
			name: "retries failed settle with backoff",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}
				retryBackoff := 50 * time.Millisecond
				firstCall := make(chan time.Time, 1)
				secondCall := make(chan time.Time, 1)

				a.autoSettlement.initialRetryBackoff = retryBackoff
				a.autoSettlement.maxRetryBackoff = retryBackoff
				a.autoSettlement.hooks.settle = func(ctx context.Context) error {
					now := time.Now()
					if calls.Add(1) == 1 {
						firstCall <- now
						return errors.New("boom")
					}
					secondCall <- now
					return nil
				}

				a.scheduleSettle(context.Background(), time.Now().Add(-time.Hour), cfg)

				first := receiveTime(t, firstCall, 500*time.Millisecond)
				waitFor(t, 500*time.Millisecond, func() bool {
					return !a.WhenNextSettlement().IsZero()
				})

				require.Equal(t, int32(1), calls.Load(),
					"settle should not retry before the backoff")

				second := receiveTime(t, secondCall, 500*time.Millisecond)
				require.GreaterOrEqual(t, second.Sub(first), retryBackoff)
				waitFor(
					t,
					200*time.Millisecond,
					func() bool { return a.WhenNextSettlement().IsZero() },
				)
			},
		},
		{
			name: "cancel clears schedule and prevents settle",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}

				a.scheduleSettle(context.Background(), time.Now().Add(time.Hour), cfg)
				require.False(t, a.WhenNextSettlement().IsZero())

				a.cancelPendingSettle()

				require.True(t, a.WhenNextSettlement().IsZero(),
					"cancelPendingSettle must clear nextSettleAt")
				time.Sleep(50 * time.Millisecond)
				require.Equal(t, int32(0), calls.Load(), "settle must not fire after cancel")
			},
		},
		{
			name:   "locked wallet skips settle at fire time",
			locked: true,
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}

				a.scheduleSettle(context.Background(), time.Now().Add(-time.Hour), cfg)

				waitFor(
					t,
					500*time.Millisecond,
					func() bool { return a.WhenNextSettlement().IsZero() },
				)
				require.Equal(t, int32(0), calls.Load(),
					"settle must not be called when wallet is locked at fire time")
			},
		},
		{
			name: "canceled context skips settle at fire time",
			run: func(t *testing.T, a *arkClient, calls *atomic.Int32) {
				cfg := &clientTypes.Config{SessionDuration: 60}
				ctx, cancel := context.WithCancel(context.Background())
				cancel()

				a.scheduleSettle(ctx, time.Now().Add(-time.Hour), cfg)

				waitFor(
					t,
					500*time.Millisecond,
					func() bool { return a.WhenNextSettlement().IsZero() },
				)
				require.Equal(t, int32(0), calls.Load(),
					"settle must not be called after context cancellation")
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			hooks, calls := stubHooks(tt.locked)
			a := newTestClient(hooks)
			defer a.cancelPendingSettle()

			tt.run(t, a, calls)
		})
	}
}

func TestAutoSettleLoopRetriesInitialSnapshotWithoutBlockingEvents(t *testing.T) {
	t.Parallel()

	cfg := &clientTypes.Config{SessionDuration: 60}
	retryBackoff := 50 * time.Millisecond
	firstSnapshot := make(chan struct{}, 1)
	retriedSnapshot := make(chan struct{}, 1)
	listCalls := &atomic.Int32{}

	hooks, _ := stubHooks(false)
	hooks.getConfigData = func(ctx context.Context) (*clientTypes.Config, error) {
		return cfg, nil
	}
	hooks.listSpendableVtxos = func(ctx context.Context) ([]clientTypes.Vtxo, error) {
		switch listCalls.Add(1) {
		case 1:
			firstSnapshot <- struct{}{}
			return nil, errors.New("boom")
		default:
			select {
			case retriedSnapshot <- struct{}{}:
			default:
			}
			return nil, nil
		}
	}
	hooks.listUnspentBoardingUtxos = func(ctx context.Context) ([]clientTypes.Utxo, error) {
		return nil, nil
	}

	a := newTestClient(hooks)
	a.syncMu = &sync.Mutex{}
	a.syncDone = true
	a.vtxoBroadcaster = newBroadcaster[types.VtxoEvent]()
	a.utxoBroadcaster = newBroadcaster[types.UtxoEvent]()
	a.autoSettlement.initialRetryBackoff = retryBackoff
	a.autoSettlement.maxRetryBackoff = retryBackoff

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go a.autoSettleLoop(ctx)

	receiveSignal(t, firstSnapshot, 500*time.Millisecond)

	expiresAt := time.Now().Add(30 * time.Minute)
	a.vtxoBroadcaster.publish(types.VtxoEvent{
		Type:  types.VtxosAdded,
		Vtxos: []clientTypes.Vtxo{{ExpiresAt: expiresAt}},
	})

	waitFor(t, 500*time.Millisecond, func() bool {
		return !a.WhenNextSettlement().IsZero()
	})
	require.WithinDuration(t, settlementFireAt(expiresAt, cfg),
		a.WhenNextSettlement(), time.Second)

	receiveSignal(t, retriedSnapshot, 500*time.Millisecond)
	time.Sleep(2 * retryBackoff)
	require.Equal(t, int32(2), listCalls.Load(),
		"snapshot retry should stop after a successful read")

	cancel()
	waitFor(t, 500*time.Millisecond, func() bool {
		return a.WhenNextSettlement().IsZero()
	})
}

func TestSettlementFireAt(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	cfg := &clientTypes.Config{SessionDuration: 60 * 60}

	require.Equal(t, time.Date(2026, 4, 28, 8, 0, 0, 0, time.UTC),
		settlementFireAt(expiresAt, cfg))
}

func TestNextSettlementExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		vtxos         []clientTypes.Vtxo
		boardingUtxos []clientTypes.Utxo
		want          time.Time
		wantOK        bool
	}{
		{
			name: "empty slice",
		},
		{
			name:  "all zero expiries are skipped",
			vtxos: []clientTypes.Vtxo{{}, {}},
		},
		{
			name: "returns earliest vtxo expiry",
			vtxos: []clientTypes.Vtxo{
				{ExpiresAt: now.Add(20 * time.Minute)},
				{ExpiresAt: now.Add(5 * time.Minute)},
				{},
				{ExpiresAt: now.Add(10 * time.Minute)},
			},
			want:   now.Add(5 * time.Minute),
			wantOK: true,
		},
		{
			name: "expired vtxo wins immediately",
			vtxos: []clientTypes.Vtxo{
				{ExpiresAt: now.Add(-time.Minute)},
			},
			boardingUtxos: []clientTypes.Utxo{
				{CreatedAt: now.Add(-time.Hour), SpendableAt: now.Add(time.Hour)},
			},
			want:   now.Add(-time.Minute),
			wantOK: true,
		},
		{
			name: "includes confirmed boarding utxo expiry",
			vtxos: []clientTypes.Vtxo{
				{ExpiresAt: now.Add(2 * time.Hour)},
			},
			boardingUtxos: []clientTypes.Utxo{
				{CreatedAt: now.Add(-time.Hour), SpendableAt: now.Add(30 * time.Minute)},
			},
			want:   now.Add(30 * time.Minute),
			wantOK: true,
		},
		{
			name: "ignores unconfirmed boarding utxos",
			vtxos: []clientTypes.Vtxo{
				{ExpiresAt: now.Add(2 * time.Hour)},
			},
			boardingUtxos: []clientTypes.Utxo{
				{SpendableAt: now.Add(30 * time.Minute)},
			},
			want:   now.Add(2 * time.Hour),
			wantOK: true,
		},
		{
			name: "ignores expired boarding utxos",
			vtxos: []clientTypes.Vtxo{
				{ExpiresAt: now.Add(2 * time.Hour)},
			},
			boardingUtxos: []clientTypes.Utxo{
				{CreatedAt: now.Add(-2 * time.Hour), SpendableAt: now.Add(-time.Minute)},
			},
			want:   now.Add(2 * time.Hour),
			wantOK: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, ok := nextSettlementExpiry(now, tt.vtxos, tt.boardingUtxos)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func TestIsBoardingUtxoScheduleEvent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		eventType types.UtxoEventType
		want      bool
	}{
		{name: "added", eventType: types.UtxosAdded, want: true},
		{name: "confirmed", eventType: types.UtxosConfirmed, want: true},
		{name: "replaced", eventType: types.UtxosReplaced, want: true},
		{name: "spent", eventType: types.UtxosSpent},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, isBoardingUtxoScheduleEvent(tt.eventType))
		})
	}
}

// newTestClient returns the smallest arkClient struct that the auto-settle
// scheduler needs to operate. It deliberately leaves the parent client.ArkClient
// nil — the injected hooks replace every call site that would otherwise
// dereference it.
func newTestClient(hooks *autoSettleHooks) *arkClient {
	return &arkClient{
		autoSettlement: autoSettlementInfo{
			hooks: hooks,
		},
	}
}

// stubHooks builds a hooks struct that records the number of settle calls.
func stubHooks(locked bool) (*autoSettleHooks, *atomic.Int32) {
	calls := &atomic.Int32{}
	hooks := &autoSettleHooks{
		settle: func(ctx context.Context) error {
			calls.Add(1)
			return nil
		},
		isLocked: func(ctx context.Context) bool {
			return locked
		},
	}
	return hooks, calls
}

// waitFor polls cond every 5ms up to timeout.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	require.FailNow(t, "condition not met within timeout")
}

func receiveTime(t *testing.T, ch <-chan time.Time, timeout time.Duration) time.Time {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(timeout):
		require.FailNow(t, "timed out waiting for settle call")
		return time.Time{}
	}
}

func receiveSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(timeout):
		require.FailNow(t, "timed out waiting for signal")
	}
}
