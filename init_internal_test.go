package arksdk

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScheduleNextRenewal(t *testing.T) {
	// With auto-settle disabled (nil scheduler) it must be a safe no-op.
	t.Run("no-op when scheduler is disabled", func(t *testing.T) {
		w := &wallet{scheduleMu: &sync.Mutex{}}
		require.NotPanics(t, w.scheduleNextRenewal)
	})

	// While a batch tx is in flight, the vtxo set is about to change but the change isn't
	// committed yet: scheduling now would decide on stale state, so it must skip. The settle
	// that's running will reschedule with fresh state once it completes.
	t.Run("skips while a batch is in flight", func(t *testing.T) {
		sched := &recordingScheduler{}
		th := newTxHandler()
		// Mark a batch as active/pending.
		th.lead = &batchEntry{turn: make(chan struct{}), done: make(chan struct{})}

		w := &wallet{
			scheduler:  sched,
			txHandler:  th,
			scheduleMu: &sync.Mutex{},
		}

		w.scheduleNextRenewal()

		require.True(t, th.batchInFlight())
		require.Zero(t, sched.calls(), "must not schedule while a batch is in flight")
		require.True(t, sched.GetTaskScheduledAt().IsZero())
	})

	// Concurrent callers must not race: with a batch in flight they all take the skip path, and
	// serialized access to the scheduler leaves nothing scheduled.
	t.Run("concurrent callers do not schedule while a batch is in flight", func(t *testing.T) {
		sched := &recordingScheduler{}
		th := newTxHandler()
		th.lead = &batchEntry{turn: make(chan struct{}), done: make(chan struct{})}

		w := &wallet{
			scheduler:  sched,
			txHandler:  th,
			scheduleMu: &sync.Mutex{},
		}

		var wg sync.WaitGroup
		for range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.scheduleNextRenewal()
			}()
		}
		wg.Wait()

		require.Zero(t, sched.calls())
	})
}

// recordingScheduler is a SchedulerService test double that records the last scheduled time and
// how many times ScheduleTask was called.
type recordingScheduler struct {
	mu            sync.Mutex
	scheduledAt   time.Time
	scheduleCalls int
}

func (s *recordingScheduler) Start() {}
func (s *recordingScheduler) Stop()  {}

func (s *recordingScheduler) ScheduleTask(_ func(), at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scheduleCalls++
	s.scheduledAt = at
	return nil
}

func (s *recordingScheduler) CancelScheduledTask() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scheduledAt = time.Time{}
}

func (s *recordingScheduler) GetTaskScheduledAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scheduledAt
}

func (s *recordingScheduler) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scheduleCalls
}
