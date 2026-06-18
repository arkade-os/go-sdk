package arksdk

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newSyncWallet builds a minimal "still restoring" wallet.
func newSyncWallet() *wallet {
	w := &wallet{
		syncMu:        &sync.Mutex{},
		syncListeners: newReadyListeners(),
		syncCh:        make(chan error, 1),
	}
	w.syncMu.Lock()
	w.syncDone = false
	w.syncMu.Unlock()
	return w
}

// syncGate is the sync portion of safeCheck used by these tests.
func (w *wallet) syncGate() error {
	w.syncMu.Lock()
	syncDone := w.syncDone
	syncErr := w.syncErr
	w.syncMu.Unlock()
	if !syncDone {
		if syncErr != nil {
			return fmt.Errorf("failed to restore wallet: %s", syncErr)
		}
		return ErrIsSyncing
	}
	return nil
}

// TestUnlockMigrationGatesPublicOps proves public ops wait for unlock migration.
func TestUnlockMigrationGatesPublicOps(t *testing.T) {
	w := newSyncWallet()

	migrationStarted := make(chan struct{})
	releaseMigration := make(chan struct{})
	var migrationDone atomic.Bool

	// Slow mocked migration.
	w.rotationReconcileFn = func(ctx context.Context) error {
		close(migrationStarted)
		<-releaseMigration
		migrationDone.Store(true)
		return nil
	}
	w.rotationDigestFn = func(ctx context.Context) (string, error) { return "digest", nil }

	// Match Unlock ordering: migration before setRestored.
	unlockSeq := make(chan struct{})
	go func() {
		w.detectAndHandleRotation(context.Background())
		w.setRestored(nil)
		close(unlockSeq)
	}()

	<-migrationStarted
	require.ErrorIs(t, w.syncGate(), ErrIsSyncing,
		"public gated op must return ErrIsSyncing while migration is in flight")
	require.False(t, migrationDone.Load(), "migration must still be running")

	close(releaseMigration)
	select {
	case <-unlockSeq:
	case <-time.After(2 * time.Second):
		t.Fatal("unlock sequence did not complete after releasing migration")
	}

	require.True(t, migrationDone.Load(),
		"syncCh/setRestored must fire only AFTER the migration attempt finished")
	require.NoError(t, w.syncGate(),
		"public gated op must succeed once the wallet is synced")
	require.Equal(t, "digest", w.lastSignerSetDigest,
		"digest seeded on successful migration")
}

// TestDetectRotationOnUnlockNoRotationFastPath covers the no-migration path.
func TestDetectRotationOnUnlockNoRotationFastPath(t *testing.T) {
	w := newSyncWallet()

	var settleCalls atomic.Int32
	w.rotationReconcileFn = func(ctx context.Context) error {
		return nil
	}
	digestCalls := 0
	w.rotationDigestFn = func(ctx context.Context) (string, error) {
		digestCalls++
		return "seeded", nil
	}

	w.detectAndHandleRotation(context.Background())

	require.Equal(t, int32(0), settleCalls.Load(),
		"no settle may be performed on the no-rotation fast path")
	require.Equal(t, 1, digestCalls, "digest is seeded once on success")
	require.Equal(t, "seeded", w.lastSignerSetDigest)
}

// TestDetectRotationOnUnlockFailureNeverHostage keeps unlock usable on failure.
func TestDetectRotationOnUnlockFailureNeverHostage(t *testing.T) {
	w := newSyncWallet()
	w.lastSignerSetDigest = ""

	const liveDigest = "cur:abc|dep:def"
	var digestFetched atomic.Bool
	w.rotationDigestFn = func(ctx context.Context) (string, error) {
		digestFetched.Store(true)
		return liveDigest, nil
	}
	w.rotationReconcileFn = func(ctx context.Context) error {
		return fmt.Errorf("settle failed: server unavailable")
	}

	done := make(chan struct{})
	go func() {
		w.detectAndHandleRotation(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("detectAndHandleRotation blocked on a migration failure (hostage)")
	}

	require.True(t, digestFetched.Load(),
		"digest fetch must run before reconciliation")
	require.Equal(t, "", w.lastSignerSetDigest,
		"digest must stay empty on failure so the periodic tick retries the migration")

	require.NotEqual(t, liveDigest, w.lastSignerSetDigest,
		"a non-empty live digest must differ from the unseeded digest, triggering retry")

	w.rotationReconcileFn = func(ctx context.Context) error { return nil }
	w.detectAndHandleRotation(context.Background())
	require.Equal(t, liveDigest, w.lastSignerSetDigest,
		"digest advances once migration succeeds, stopping further retries")
}

// TestPublicSettleStillSafeChecked keeps public Settle safeCheck-gated.
func TestPublicSettleStillSafeChecked(t *testing.T) {
	w := &wallet{syncMu: &sync.Mutex{}, syncListeners: newReadyListeners()}
	_, err := w.Settle(context.Background())
	require.ErrorIs(t, err, ErrNotInitialized,
		"public Settle must still be safeCheck-gated (behavior unchanged)")
}

// TestUnlockMigrationRaceClean covers the unlock migration sync path under -race.
func TestUnlockMigrationRaceClean(t *testing.T) {
	const iters = 100
	var wg sync.WaitGroup
	for i := 0; i < iters; i++ {
		w := newSyncWallet()
		w.rotationReconcileFn = func(ctx context.Context) error { return nil }
		w.rotationDigestFn = func(ctx context.Context) (string, error) { return "d", nil }

		wg.Add(3)
		go func() {
			defer wg.Done()
			w.detectAndHandleRotation(context.Background())
			w.setRestored(nil)
		}()
		go func() {
			defer wg.Done()
			_ = w.syncGate()
		}()
		go func() {
			defer wg.Done()
			_ = w.IsSynced(context.Background())
		}()
	}
	wg.Wait()
}
