package arksdk

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// listenerSettleTime gives a contender goroutine enough time to start waiting
// on the handler before the in-flight op is released, so the test exercises
// the contended path deterministically.
const listenerSettleTime = 100 * time.Millisecond

// TestTxHandler exercises the serialization and deduplication behaviour of
// txHandler, which prevents concurrent send/issue/reissue/burn/settle/
// collab-exit calls from overlapping and double-spending VTXOs.
func TestTxHandler(t *testing.T) {
	t.Run("concurrent settles dedup to the in-flight result", func(t *testing.T) {
		h := newTestTxHandler(t)

		resA := "commitment-A"
		started := make(chan struct{})
		release := make(chan struct{})

		var (
			got  [2]string
			errs [2]error
			wg   sync.WaitGroup
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			got[0], errs[0] = h.handleBatchTx(
				settleType, func() (string, error) {
					close(started)
					<-release
					return resA, nil
				},
			)
		}()

		<-started // first settle holds the lock and is processing

		var secondRan atomic.Bool
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[1], errs[1] = h.handleBatchTx(
				settleType, func() (string, error) {
					secondRan.Store(true)
					return "commitment-B", nil
				},
			)
		}()

		time.Sleep(listenerSettleTime)
		close(release)
		wg.Wait()

		require.NoError(t, errs[0])
		require.NoError(t, errs[1])
		require.Equal(t, resA, got[0])
		require.Equal(t, resA, got[1]) // second settle returned the first's result
		require.False(t, secondRan.Load(), "second settle must not run its own batch tx")
	})

	t.Run("collab exit is rejected while a settle is in flight", func(t *testing.T) {
		h := newTestTxHandler(t)

		started := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleBatchTx(settleType, func() (string, error) {
				close(started)
				<-release
				return "settle", nil
			})
		}()

		<-started

		var collabExitRan atomic.Bool
		res, err := h.handleBatchTx(collabExitType, func() (string, error) {
			collabExitRan.Store(true)
			return "collab-exit", nil
		})

		require.ErrorIs(t, err, ErrSettleInProgress)
		require.Empty(t, res)
		require.False(t, collabExitRan.Load(), "collab exit must not run during a settle")

		close(release)
		wg.Wait()
	})

	t.Run("collab exit waits for an in-flight send then runs its own batch tx", func(t *testing.T) {
		h := newTestTxHandler(t)

		var tracker overlapTracker

		sendStarted := make(chan struct{})
		sendRelease := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				leave := tracker.enter()
				defer leave()
				close(sendStarted)
				<-sendRelease
				return "send-txid", nil
			})
		}()

		<-sendStarted

		collabExitRes := "collab-exit"
		var collabExitRan atomic.Bool
		var (
			got    string
			gotErr error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, gotErr = h.handleBatchTx(collabExitType, func() (string, error) {
				leave := tracker.enter()
				defer leave()
				collabExitRan.Store(true)
				return collabExitRes, nil
			})
		}()

		time.Sleep(listenerSettleTime)
		require.False(
			t, collabExitRan.Load(), "collab exit must not start while a send is in flight",
		)

		close(sendRelease)
		wg.Wait()

		require.NoError(t, gotErr)
		require.True(t, collabExitRan.Load(), "collab exit must run its own batch tx after a send")
		require.Equal(t, collabExitRes, got)
		require.Equal(t, int32(1), tracker.max.Load(), "send and collab exit must not overlap")
	})

	t.Run("settle dedups to an in-flight collab exit", func(t *testing.T) {
		h := newTestTxHandler(t)

		resCE := "collab-exit"
		started := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleBatchTx(collabExitType, func() (string, error) {
				close(started)
				<-release
				return resCE, nil
			})
		}()

		<-started

		var settleRan atomic.Bool
		var (
			got    string
			gotErr error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, gotErr = h.handleBatchTx(settleType, func() (string, error) {
				settleRan.Store(true)
				return "settle", nil
			})
		}()

		time.Sleep(listenerSettleTime)
		close(release)
		wg.Wait()

		require.NoError(t, gotErr)
		require.Equal(t, resCE, got) // settle returned the collab exit's result
		require.False(t, settleRan.Load(), "settle must not run its own batch tx")
	})

	t.Run("settle waits for an in-flight send then runs its own batch tx", func(t *testing.T) {
		h := newTestTxHandler(t)

		var tracker overlapTracker

		sendStarted := make(chan struct{})
		sendRelease := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				leave := tracker.enter()
				defer leave()
				close(sendStarted)
				<-sendRelease
				return "send-txid", nil
			})
		}()

		<-sendStarted

		settleRes := "settle"
		var settleRan atomic.Bool
		var (
			got    string
			gotErr error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, gotErr = h.handleBatchTx(settleType, func() (string, error) {
				leave := tracker.enter()
				defer leave()
				settleRan.Store(true)
				return settleRes, nil
			})
		}()

		time.Sleep(listenerSettleTime)
		require.False(t, settleRan.Load(), "settle must not start while a send is in flight")

		close(sendRelease)
		wg.Wait()

		require.NoError(t, gotErr)
		require.True(t, settleRan.Load(), "settle must run its own batch tx after a send")
		require.Equal(t, settleRes, got) // not deduped: settle produced its own result
		require.Equal(t, int32(1), tracker.max.Load(), "send and settle must not overlap")
	})

	t.Run("send and issue asset do not overlap", func(t *testing.T) {
		h := newTestTxHandler(t)

		var tracker overlapTracker

		sendStarted := make(chan struct{})
		sendRelease := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				leave := tracker.enter()
				defer leave()
				close(sendStarted)
				<-sendRelease
				return "send", nil
			})
		}()

		<-sendStarted

		var issueRan atomic.Bool
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				leave := tracker.enter()
				defer leave()
				issueRan.Store(true)
				return "issue", nil
			})
		}()

		time.Sleep(listenerSettleTime)
		require.False(t, issueRan.Load(), "issue must wait for the in-flight send")

		close(sendRelease)
		wg.Wait()

		require.True(t, issueRan.Load())
		require.Equal(t, int32(1), tracker.max.Load(), "send and issue must not overlap")
	})

	t.Run(
		"two spends queued behind a settle each run once without overlapping",
		func(t *testing.T) {
			h := newTestTxHandler(t)

			var tracker overlapTracker
			var ran [2]atomic.Bool

			// Settle holds the slot.
			settleStarted := make(chan struct{})
			settleRelease := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = h.handleBatchTx(settleType, func() (string, error) {
					leave := tracker.enter()
					defer leave()
					close(settleStarted)
					<-settleRelease
					return "settle", nil
				})
			}()
			<-settleStarted

			goroutinesBefore := runtime.NumGoroutine()

			// SendOffChain and IssueAsset both queue behind the settle. The order
			// in which they run once the slot frees is not guaranteed (waiters race
			// for the slot), but they must never overlap and each must run once.
			for i := range ran {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = h.handleTx(func() (any, error) {
						leave := tracker.enter()
						defer leave()
						ran[i].Store(true)
						time.Sleep(20 * time.Millisecond)
						return "spend", nil
					})
				}()
			}

			time.Sleep(listenerSettleTime) // let both queue up behind the settle
			close(settleRelease)
			wg.Wait()

			require.True(t, ran[0].Load() && ran[1].Load(), "both queued spends must run")
			require.Equal(t, int32(1), tracker.max.Load(), "queued ops must never overlap")

			// The old broadcast queue leaked a goroutine per unlock; the cond-based
			// handler must not retain any waiters once every op has completed.
			require.Eventually(t, func() bool {
				return runtime.NumGoroutine() <= goroutinesBefore
			}, time.Second, 10*time.Millisecond, "no goroutines must leak")
		},
	)

	t.Run("two settles queued behind a send dedup to a single settlement", func(t *testing.T) {
		h := newTestTxHandler(t)

		// Send holds the slot.
		sendStarted := make(chan struct{})
		sendRelease := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				close(sendStarted)
				<-sendRelease
				return "send", nil
			})
		}()
		<-sendStarted

		var (
			settleRuns atomic.Int32
			got        [2]string
			errs       [2]error
			tracker    overlapTracker
		)
		for i := range got {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[i], errs[i] = h.handleBatchTx(
					settleType, func() (string, error) {
						leave := tracker.enter()
						defer leave()
						settleRuns.Add(1)
						time.Sleep(20 * time.Millisecond)
						return "commitment", nil
					},
				)
			}()
		}

		time.Sleep(listenerSettleTime) // both settles parked behind the send
		close(sendRelease)
		wg.Wait()

		require.NoError(t, errs[0])
		require.NoError(t, errs[1])
		require.Equal(
			t, int32(1), settleRuns.Load(),
			"only one settlement must run; the second settle must dedup",
		)
		require.NotEmpty(t, got[0])
		require.Equal(t, got[0], got[1], "both settles must return the same result")
	})

	t.Run("batch tx takes precedence over earlier-queued spends", func(t *testing.T) {
		h := newTestTxHandler(t)

		var rec orderRecorder
		var tracker overlapTracker

		// A spend holds the slot.
		started := make(chan struct{})
		release := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				leave := tracker.enter()
				defer leave()
				rec.mark("running")
				close(started)
				<-release
				return nil, nil
			})
		}()
		<-started

		// Queue two spends (A then B), staggered so their arrival order is
		// deterministic, then a settle that arrives last.
		queueSpend := func(name string) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = h.handleTx(func() (any, error) {
					leave := tracker.enter()
					defer leave()
					rec.mark(name)
					return nil, nil
				})
			}()
			time.Sleep(listenerSettleTime)
		}
		queueSpend("A")
		queueSpend("B")
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleBatchTx(settleType, func() (string, error) {
				leave := tracker.enter()
				defer leave()
				rec.mark("settle")
				return "settle", nil
			})
		}()
		time.Sleep(listenerSettleTime) // let the settle register as the lead batch

		close(release)
		wg.Wait()

		require.Equal(
			t, []string{"running", "settle", "A", "B"}, rec.snapshot(),
			"the late settle must jump ahead of earlier-queued spends, which keep FIFO order",
		)
		require.Equal(t, int32(1), tracker.max.Load(), "ops must never overlap")
	})

	t.Run("collab exit also takes precedence over a queued spend", func(t *testing.T) {
		h := newTestTxHandler(t)

		var rec orderRecorder

		started := make(chan struct{})
		release := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				rec.mark("running")
				close(started)
				<-release
				return nil, nil
			})
		}()
		<-started

		// Spend queues first; collab exit arrives later but jumps ahead.
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				rec.mark("spend")
				return nil, nil
			})
		}()
		time.Sleep(listenerSettleTime)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleBatchTx(collabExitType, func() (string, error) {
				rec.mark("collab-exit")
				return "collab-exit", nil
			})
		}()
		time.Sleep(listenerSettleTime)

		close(release)
		wg.Wait()

		require.Equal(
			t, []string{"running", "collab-exit", "spend"}, rec.snapshot(),
			"collab exit must jump ahead of the earlier-queued spend",
		)
	})

	t.Run("stop aborts a queued operation instead of running it", func(t *testing.T) {
		h := newTestTxHandler(t)

		// Occupy the slot with a blocking op.
		started := make(chan struct{})
		release := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleTx(func() (any, error) {
				close(started)
				<-release
				return nil, nil
			})
		}()
		<-started

		// Queue a second op behind it; it must not run once we stop.
		var queuedRan atomic.Bool
		var queuedErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, queuedErr = h.handleTx(func() (any, error) {
				queuedRan.Store(true)
				return nil, nil
			})
		}()
		time.Sleep(listenerSettleTime) // let it queue

		h.stop()
		close(release)
		wg.Wait()

		require.ErrorIs(t, queuedErr, ErrIsLocked)
		require.False(t, queuedRan.Load(), "queued op must abort, not run, after stop")
	})

	t.Run("stop aborts a deduping settle", func(t *testing.T) {
		h := newTestTxHandler(t)

		// A blocking settle holds the slot as the lead batch.
		started := make(chan struct{})
		release := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.handleBatchTx(settleType, func() (string, error) {
				close(started)
				<-release
				return "lead", nil
			})
		}()
		<-started

		// A second settle dedups and waits on the lead; stop must abort it.
		var dedupErr error
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, dedupErr = h.handleBatchTx(settleType, func() (string, error) {
				t.Error("deduping settle must not run its own fn")
				return "", nil
			})
		}()
		time.Sleep(listenerSettleTime)

		h.stop()
		close(release)
		wg.Wait()

		require.ErrorIs(t, dedupErr, ErrIsLocked)
	})

	t.Run("stop rejects new operations", func(t *testing.T) {
		h := newTestTxHandler(t)
		h.stop()

		_, err := h.handleTx(func() (any, error) {
			t.Error("handleTx fn must not run after stop")
			return nil, nil
		})
		require.ErrorIs(t, err, ErrIsLocked)

		res, batchErr := h.handleBatchTx(settleType, func() (string, error) {
			t.Error("handleBatchTx fn must not run after stop")
			return "", nil
		})
		require.ErrorIs(t, batchErr, ErrIsLocked)
		require.Empty(t, res)
	})
}

func newTestTxHandler(t *testing.T) *txHandler {
	t.Helper()
	return newTxHandler()
}

// overlapTracker records the maximum number of functions that were ever
// running at the same time, so a test can assert two operations never
// overlapped (max == 1).
type overlapTracker struct {
	active atomic.Int32
	max    atomic.Int32
}

func (o *overlapTracker) enter() (leave func()) {
	n := o.active.Add(1)
	for {
		m := o.max.Load()
		if n <= m || o.max.CompareAndSwap(m, n) {
			break
		}
	}
	return func() { o.active.Add(-1) }
}

// orderRecorder captures the order in which operations run, so a test can
// assert the handler dispatches them by priority and FIFO within a class.
type orderRecorder struct {
	mu    sync.Mutex
	order []string
}

func (r *orderRecorder) mark(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order = append(r.order, name)
}

func (r *orderRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.order...)
}
