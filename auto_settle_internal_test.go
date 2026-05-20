package arksdk

import (
	"context"
	"errors"
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
		_, _, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.True(t, acquired)
		w.finishSpendOp("tx1", nil)
	})

	t.Run("second caller blocked with in-flight type", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		w.tryStartSpendOp(spendTypeSettle)

		done, inFlightType, acquired := w.tryStartSpendOp(spendTypeSendOffchain)
		require.False(t, acquired)
		require.NotNil(t, done)
		require.Equal(t, spendTypeSettle, inFlightType)

		w.finishSpendOp("tx1", nil)
	})

	t.Run("can acquire again after finish", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp("tx1", nil)

		_, _, acquired := w.tryStartSpendOp(spendTypeSendOffchain)
		require.True(t, acquired)
		w.finishSpendOp("tx2", nil)
	})
}

func TestReadSpendResult(t *testing.T) {
	t.Parallel()

	t.Run("reads completed result", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp("commitment-abc", nil)

		result := w.readSpendResult()
		require.Equal(t, spendTypeSettle, result.OpType)
		require.Equal(t, "commitment-abc", result.Txid)
		require.NoError(t, result.Err)
	})

	t.Run("reads error result", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		opErr := errors.New("failed")
		w.tryStartSpendOp(spendTypeSettle)
		w.finishSpendOp("", opErr)

		result := w.readSpendResult()
		require.ErrorIs(t, result.Err, opErr)
	})
}

func TestSpendOpSettle(t *testing.T) {
	t.Parallel()

	t.Run("settle dedups with in-flight settle", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.tryStartSpendOp(spendTypeSettle)
			time.Sleep(50 * time.Millisecond)
			w.finishSpendOp("commitment-abc", nil)
		}()

		time.Sleep(10 * time.Millisecond)

		// Second settle sees spendTypeSettle in flight, waits, reads result.
		done, inFlightType, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.False(t, acquired)
		require.Equal(t, spendTypeSettle, inFlightType)
		<-done

		result := w.readSpendResult()
		require.Equal(t, "commitment-abc", result.Txid)
		require.NoError(t, result.Err)

		wg.Wait()
	})

	t.Run("settle retries after in-flight send", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.tryStartSpendOp(spendTypeSendOffchain)
			time.Sleep(50 * time.Millisecond)
			w.finishSpendOp("ark-tx-123", nil)
		}()

		time.Sleep(10 * time.Millisecond)

		// Settle sees send in flight — waits, then retries.
		done, inFlightType, acquired := w.tryStartSpendOp(spendTypeSettle)
		require.False(t, acquired)
		require.Equal(t, spendTypeSendOffchain, inFlightType)
		<-done

		// Now can acquire.
		_, _, acquired = w.tryStartSpendOp(spendTypeSettle)
		require.True(t, acquired)
		w.finishSpendOp("commitment-xyz", nil)

		wg.Wait()
	})
}

func TestSpendOpCollabExit(t *testing.T) {
	t.Parallel()

	t.Run("rejects immediately on in-flight settle", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.tryStartSpendOp(spendTypeSettle)
			time.Sleep(50 * time.Millisecond)
			w.finishSpendOp("commitment-abc", nil)
		}()

		time.Sleep(10 * time.Millisecond)

		start := time.Now()
		_, inFlightType, acquired := w.tryStartSpendOp(spendTypeCollabExit)
		require.False(t, acquired)
		require.Equal(t, spendTypeSettle, inFlightType)
		// Should reject immediately — not wait for 50ms settle.
		require.Less(t, time.Since(start), 20*time.Millisecond)

		wg.Wait()
	})

	t.Run("waits and retries after in-flight send", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.tryStartSpendOp(spendTypeSendOffchain)
			time.Sleep(50 * time.Millisecond)
			w.finishSpendOp("ark-tx-123", nil)
		}()

		time.Sleep(10 * time.Millisecond)

		done, inFlightType, acquired := w.tryStartSpendOp(spendTypeCollabExit)
		require.False(t, acquired)
		require.Equal(t, spendTypeSendOffchain, inFlightType)
		<-done

		_, _, acquired = w.tryStartSpendOp(spendTypeCollabExit)
		require.True(t, acquired)
		w.finishSpendOp("commitment-exit", nil)

		wg.Wait()
	})
}

func TestWaitForSpendOp(t *testing.T) {
	t.Parallel()

	t.Run("ctx cancellation", func(t *testing.T) {
		t.Parallel()
		w := &wallet{}
		w.tryStartSpendOp(spendTypeSettle)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		done, _, _ := w.tryStartSpendOp(spendTypeSendOffchain)
		err := waitForSpendOp(ctx, done)
		require.ErrorIs(t, err, context.DeadlineExceeded)

		w.finishSpendOp("", nil)
	})
}
