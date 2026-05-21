package arksdk

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTryStartSpendOp(t *testing.T) {
	t.Parallel()

	t.Run("first caller acquires", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		h, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.True(t, acquired)
		require.NotNil(t, h)
		require.Equal(t, spendTypeSettle, h.opType)
		w.finishSpendOp(h, "tx1", nil)
	})

	t.Run("second caller blocked with in-flight type", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		hA, _ := w.tryStartSpendOp(spendTypeSettle)

		hB, acquired := w.tryStartSpendOp(spendTypeSendOffchain)
		require.False(t, acquired)
		require.NotNil(t, hB)
		require.NotNil(t, hB.done)
		require.Equal(t, spendTypeSettle, hB.opType)
		// Contender receives the same in-flight handle as the acquirer.
		require.Same(t, hA, hB)

		w.finishSpendOp(hA, "tx1", nil)
	})

	t.Run("can acquire again after finish", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		hA, _ := w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp(hA, "tx1", nil)

		hB, acquired := w.tryStartSpendOp(spendTypeSendOffchain)
		require.True(t, acquired)
		require.NotSame(t, hA, hB)
		w.finishSpendOp(hB, "tx2", nil)
	})
}

func TestSpendOpHandleResult(t *testing.T) {
	t.Parallel()

	t.Run("reads completed result", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		h, _ := w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp(h, "commitment-abc", nil)

		require.Equal(t, spendTypeSettle, h.opType)
		require.Equal(t, "commitment-abc", h.txid)
		require.NoError(t, h.err)
	})

	t.Run("reads error result", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		opErr := errors.New("failed")
		h, _ := w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp(h, "", opErr)

		require.ErrorIs(t, h.err, opErr)
	})
}

func TestSpendOpSettle(t *testing.T) {
	t.Parallel()

	t.Run("settle dedups with in-flight settle", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		ready := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _ := w.tryStartSpendOp(spendTypeSettle)
			close(ready)
			<-release
			w.finishSpendOp(h, "commitment-abc", nil)
		}()

		<-ready

		// Second settle sees spendTypeSettle in flight, waits, reads result.
		h, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.False(t, acquired)
		require.Equal(t, spendTypeSettle, h.opType)
		close(release)
		<-h.done

		require.Equal(t, "commitment-abc", h.txid)
		require.NoError(t, h.err)

		wg.Wait()
	})

	t.Run("settle retries after in-flight send", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		ready := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _ := w.tryStartSpendOp(spendTypeSendOffchain)
			close(ready)
			<-release
			w.finishSpendOp(h, "ark-tx-123", nil)
		}()

		<-ready

		// Settle sees send in flight — waits, then retries.
		h, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.False(t, acquired)
		require.Equal(t, spendTypeSendOffchain, h.opType)
		close(release)
		<-h.done

		// Now can acquire.
		hRetry, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.True(t, acquired)
		w.finishSpendOp(hRetry, "commitment-xyz", nil)

		wg.Wait()
	})
}

func TestSpendOpCollabExit(t *testing.T) {
	t.Parallel()

	t.Run("rejects immediately on in-flight settle", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		ready := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _ := w.tryStartSpendOp(spendTypeSettle)
			close(ready)
			<-release
			w.finishSpendOp(h, "commitment-abc", nil)
		}()

		<-ready

		h, acquired := w.tryStartSpendOp(spendTypeCollabExit)
		require.False(t, acquired)
		require.Equal(t, spendTypeSettle, h.opType)
		// Caller can inspect opType and reject immediately without waiting.

		close(release)
		wg.Wait()
	})

	t.Run("waits and retries after in-flight send", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		ready := make(chan struct{})
		release := make(chan struct{})

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, _ := w.tryStartSpendOp(spendTypeSendOffchain)
			close(ready)
			<-release
			w.finishSpendOp(h, "ark-tx-123", nil)
		}()

		<-ready

		h, acquired := w.tryStartSpendOp(spendTypeCollabExit)
		require.False(t, acquired)
		require.Equal(t, spendTypeSendOffchain, h.opType)
		close(release)
		<-h.done

		hRetry, acquired := w.tryStartSpendOp(spendTypeCollabExit)
		require.True(t, acquired)
		w.finishSpendOp(hRetry, "commitment-exit", nil)

		wg.Wait()
	})
}

func TestWaitForSpendOp(t *testing.T) {
	t.Parallel()

	t.Run("ctx cancellation", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		h, _ := w.tryStartSpendOp(spendTypeSettle)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		// Second op contends — its handle.done is the same as h.done.
		contender, _ := w.tryStartSpendOp(spendTypeSendOffchain)
		err := waitForSpendOp(ctx, contender.done)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		w.finishSpendOp(h, "", nil)
	})

	t.Run("nil ctx does not panic", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		h, _ := w.tryStartSpendOp(spendTypeSettle)

		done := make(chan error, 1)
		go func() {
			// nil context is treated as background; the call returns when
			// the producer goroutine closes h.done. This test deliberately
			// passes nil to cover the nil-ctx safety in waitForSpendOp.
			done <- waitForSpendOp(nil, h.done) //nolint:staticcheck // SA1012: intentional nil ctx
		}()

		w.finishSpendOp(h, "tx", nil)
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(2 * time.Second):
			t.Fatal("waitForSpendOp did not return on nil ctx + closed done")
		}
	})
}

// TestSpendOpResultIsolation is the F1 TOCTOU regression test.
//
// The original bug (before the *spendOpHandle refactor) was that
// tryStartSpendOp/finishSpendOp/readSpendResult shared mutable wallet
// fields (spendOpTxid, spendOpErr, spendOpInFlight). A waiter that woke
// up after <-done would re-read those fields — but if another goroutine
// raced through tryStartSpendOp in the gap between finishSpendOp's
// `close(done)` and the waiter's read, the fields had already been
// cleared and the waiter would see "" / nil instead of the original
// result. This caused settle-dedup callers to return an empty
// commitment txid.
//
// This test reproduces that interleave: goroutine A acquires the lock,
// goroutine B contends and captures A's handle, A finishes, C immediately
// re-acquires the lock for a different opType, and only then does B read
// its result. With the handle-struct refactor, B reads its own *spendOpHandle
// (h.txid / h.err) which is never mutated by C's acquisition.
func TestSpendOpResultIsolation(t *testing.T) {
	t.Parallel()

	w := &wallet{}

	readyA := make(chan struct{})
	releaseA := make(chan struct{})
	bCaptured := make(chan *spendOpHandle, 1)
	cAcquired := make(chan struct{})

	var wg sync.WaitGroup

	// Goroutine A: acquire spendTypeSettle and hold until releaseA.
	wg.Add(1)
	go func() {
		defer wg.Done()
		hA, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.True(t, acquired)
		close(readyA)
		<-releaseA
		w.finishSpendOp(hA, "tx-A", nil)
	}()

	// Goroutine B: contend, capture handleA, wait on handleA.done.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-readyA
		hB, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.False(t, acquired)
		bCaptured <- hB
		// Wait until C has re-acquired the spend lock, then read hB's result.
		<-hB.done
		<-cAcquired
		// h.txid must still be "tx-A" — C's acquisition must NOT clobber
		// this contender's view of the completed result.
		require.Equal(
			t,
			"tx-A",
			hB.txid,
			"F1 regression: contender saw cleared txid after C acquired",
		)
		require.NoError(t, hB.err)
	}()

	// Wait until B has captured the in-flight handle, then start the race.
	hB := <-bCaptured

	// Release A and immediately race to acquire as C. C must succeed because
	// finishSpendOp releases the lock before the close(done) on the OLD code
	// (and the order is irrelevant on the new code — what matters is that
	// hB.txid is read from its OWN handle, not from a shared wallet field).
	close(releaseA)

	// Try repeatedly until C acquires — finishSpendOp clears the lock then
	// closes done, so there is a brief window before B unblocks.
	var hC *spendOpHandle
	deadline := time.Now().Add(5 * time.Second)
	for {
		var ok bool
		hC, ok = w.tryStartSpendOp(spendTypeSendOffchain)
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("C never acquired the spend lock")
		}
		// Yield to let A's finishSpendOp finish.
		runtime.Gosched()
	}
	close(cAcquired)
	// Sanity assertion on B's snapshot.
	require.Equal(t, "tx-A", hB.txid)
	require.NoError(t, hB.err)

	w.finishSpendOp(hC, "tx-C", nil)
	wg.Wait()
}

// TestSpendOpAsset verifies that an asset op waits when a settle is in flight
// and proceeds after the settle completes (no dedup — fresh acquire).
func TestSpendOpAsset(t *testing.T) {
	t.Parallel()
	w := &wallet{}

	ready := make(chan struct{})
	release := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h, _ := w.tryStartSpendOp(spendTypeSettle)
		close(ready)
		<-release
		w.finishSpendOp(h, "commitment-abc", nil)
	}()

	<-ready

	// Asset op sees settle in flight — must NOT dedup; it must wait & retry.
	h, acquired := w.tryStartSpendOp(spendTypeAsset)
	require.False(t, acquired)
	require.Equal(t, spendTypeSettle, h.opType)
	close(release)
	<-h.done

	// Now retry — should acquire.
	hRetry, acquired := w.tryStartSpendOp(spendTypeAsset)
	require.True(t, acquired)
	require.Equal(t, spendTypeAsset, hRetry.opType)
	w.finishSpendOp(hRetry, "asset-tx-1", nil)

	wg.Wait()
}

// TestSpendOpUnroll verifies that an unroll op waits when a settle is in
// flight and proceeds after the settle completes (no dedup — fresh acquire).
func TestSpendOpUnroll(t *testing.T) {
	t.Parallel()
	w := &wallet{}

	ready := make(chan struct{})
	release := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h, _ := w.tryStartSpendOp(spendTypeSettle)
		close(ready)
		<-release
		w.finishSpendOp(h, "commitment-abc", nil)
	}()

	<-ready

	h, acquired := w.tryStartSpendOp(spendTypeUnroll)
	require.False(t, acquired)
	require.Equal(t, spendTypeSettle, h.opType)
	close(release)
	<-h.done

	hRetry, acquired := w.tryStartSpendOp(spendTypeUnroll)
	require.True(t, acquired)
	require.Equal(t, spendTypeUnroll, hRetry.opType)
	w.finishSpendOp(hRetry, "", nil) // Unroll has no txid; pass "".

	wg.Wait()
}

// TestErrSettleInProgress sanity-checks the F4 rename and message.
func TestErrSettleInProgress(t *testing.T) {
	t.Parallel()
	require.NotNil(t, ErrSettleInProgress)
	require.Equal(t, "settle in progress, retry later", ErrSettleInProgress.Error())
}
