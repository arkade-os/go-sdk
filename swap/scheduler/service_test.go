package scheduler_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	gocronscheduler "github.com/arkade-os/go-sdk/swap/scheduler/gocron"
	"github.com/arkade-os/go-sdk/swap/types"
	"github.com/stretchr/testify/require"
)

const (
	pollInterval = 20 * time.Millisecond
	waitTimeout  = 3 * time.Second
)

// schedulerImpls lists the tested types.Scheduler implementations. Future
// implementations only need to be added here to be covered by the whole suite.
var schedulerImpls = []struct {
	name string
	new  func(explorerSvc explorer.Explorer, pollInterval time.Duration) types.Scheduler
}{
	{name: "gocron", new: gocronscheduler.NewScheduler},
}

func TestSchedulerService(t *testing.T) {
	for _, impl := range schedulerImpls {
		t.Run(impl.name, func(t *testing.T) {
			t.Run("schedule task at time", func(t *testing.T) {
				t.Run("in the future", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					svc.Start()
					t.Cleanup(svc.Stop)

					fired := make(chan struct{})
					err := svc.ScheduleTaskAtTime(
						time.Now().Add(500*time.Millisecond), func() { close(fired) },
					)
					require.NoError(t, err)
					requireFires(t, fired)
				})

				t.Run("in the past runs immediately", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					svc.Start()
					t.Cleanup(svc.Stop)

					fired := make(chan struct{})
					err := svc.ScheduleTaskAtTime(
						time.Now().Add(-time.Second), func() { close(fired) },
					)
					require.NoError(t, err)
					requireFires(t, fired)
				})

				t.Run("zero time fails", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					err := svc.ScheduleTaskAtTime(time.Time{}, func() {})
					require.Error(t, err)
				})
			})

			t.Run("schedule task at height", func(t *testing.T) {
				t.Run("in the future", func(t *testing.T) {
					explorerSvc := newMockExplorer(100)
					svc := impl.new(explorerSvc, pollInterval)
					svc.Start()
					t.Cleanup(svc.Stop)

					fired := make(chan struct{})
					err := svc.ScheduleTaskAtHeight(105, func() { close(fired) })
					require.NoError(t, err)
					requireNeverFires(t, fired, 10*pollInterval)

					explorerSvc.setHeight(105)
					requireFires(t, fired)
				})

				t.Run("already reached runs immediately", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					svc.Start()
					t.Cleanup(svc.Stop)

					fired := make(chan struct{})
					err := svc.ScheduleTaskAtHeight(100, func() { close(fired) })
					require.NoError(t, err)
					requireFires(t, fired)
				})

				t.Run("zero height fails", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					err := svc.ScheduleTaskAtHeight(0, func() {})
					require.Error(t, err)
				})

				t.Run("unavailable explorer fails", func(t *testing.T) {
					explorerSvc := newMockExplorer(100)
					explorerSvc.setErr(fmt.Errorf("explorer unavailable"))
					svc := impl.new(explorerSvc, pollInterval)

					err := svc.ScheduleTaskAtHeight(105, func() {})
					require.Error(t, err)
				})
			})

			t.Run("stop", func(t *testing.T) {
				t.Run("cancels pending tasks", func(t *testing.T) {
					explorerSvc := newMockExplorer(100)
					svc := impl.new(explorerSvc, pollInterval)

					t.Run("scheduled at height", func(t *testing.T) {
						svc.Start()

						fired := make(chan struct{})
						err := svc.ScheduleTaskAtHeight(105, func() { close(fired) })
						require.NoError(t, err)

						svc.Stop()
						explorerSvc.setHeight(110)
						requireNeverFires(t, fired, 10*pollInterval)
					})
					t.Run("scheduled at time", func(t *testing.T) {
						svc.Start()

						fired := make(chan struct{})
						err := svc.ScheduleTaskAtTime(
							time.Now().Add(500*time.Millisecond), func() { close(fired) },
						)
						require.NoError(t, err)

						svc.Stop()
						requireNeverFires(t, fired, time.Second)
					})
				})

				t.Run("start and stop are idempotent", func(t *testing.T) {
					svc := impl.new(newMockExplorer(100), pollInterval)
					svc.Start()
					svc.Start()
					svc.Stop()
					svc.Stop()
				})
			})
		})
	}
}

func requireFires(t *testing.T, fired <-chan struct{}) {
	t.Helper()
	select {
	case <-fired:
	case <-time.After(waitTimeout):
		t.Fatal("task did not run before timeout")
	}
}

func requireNeverFires(t *testing.T, fired <-chan struct{}, within time.Duration) {
	t.Helper()
	select {
	case <-fired:
		t.Fatal("task ran but should not have")
	case <-time.After(within):
	}
}

// mockExplorer implements the only method used by scheduler implementations,
// GetBlockHeight, with a controllable height and error. Any other method call
// panics via the embedded nil explorer.Explorer.
type mockExplorer struct {
	explorer.Explorer

	mu     sync.Mutex
	height int64
	err    error
}

func newMockExplorer(height int64) *mockExplorer {
	return &mockExplorer{height: height}
}

func (m *mockExplorer) GetBlockHeight() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.height, m.err
}

func (m *mockExplorer) setHeight(height int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.height = height
}

func (m *mockExplorer) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}
