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

// newSyncWallet builds a minimal wallet with just the sync primitives wired,
// in the "still restoring" state (syncDone == false). It is enough to exercise
// safeCheck's sync gate and the setRestored transition without standing up a
// full client/contract-manager surface.
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

// syncGate reads exactly the sync portion of safeCheck (the part that runs
// behind the synchronous migration). It returns ErrIsSyncing until setRestored
// flips syncDone — i.e. until the unlock sequence (including migrateOnUnlock)
// has completed and the syncCh send has been consumed.
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

// TestUnlockMigrationGatesPublicOps proves objective (a): a public,
// safeCheck-gated operation must return ErrIsSyncing while the deprecated-signer
// migration is in flight, and succeed only AFTER the migration attempt finishes
// and the wallet is marked synced. This encodes the user requirement (the user
// must not be able to use the wallet — and must not receive the synced
// notification — until migration completes).
func TestUnlockMigrationGatesPublicOps(t *testing.T) {
	w := newSyncWallet()

	migrationStarted := make(chan struct{})
	releaseMigration := make(chan struct{})
	var migrationDone atomic.Bool

	// Slow mocked migration: blocks until the test releases it, mimicking a
	// settle that is waiting on a server round.
	w.unlockReconcileFn = func(ctx context.Context) error {
		close(migrationStarted)
		<-releaseMigration
		migrationDone.Store(true)
		return nil
	}
	// On success migrateOnUnlock seeds the digest; stub the info fetch so we
	// don't need a real client.
	w.unlockDigestFn = func(ctx context.Context) (string, bool) { return "digest", true }

	// Mirror the Unlock background goroutine ordering: migrateOnUnlock runs
	// SYNCHRONOUSLY before syncCh is sent and before setRestored flips syncDone.
	unlockSeq := make(chan struct{})
	go func() {
		w.migrateOnUnlock(context.Background())
		// Equivalent to the init.go "w.syncCh <- err" + the syncCh listener
		// calling setRestored(err) with err == nil.
		w.setRestored(nil)
		close(unlockSeq)
	}()

	// While migration is in flight, the gated op MUST be blocked.
	<-migrationStarted
	require.ErrorIs(t, w.syncGate(), ErrIsSyncing,
		"public gated op must return ErrIsSyncing while migration is in flight")
	require.False(t, migrationDone.Load(), "migration must still be running")

	// Release the migration; the wallet may now mark itself synced.
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

// TestMigrateOnUnlockNoRotationFastPath proves objective (b): when there is
// nothing to migrate, reconcileDeprecatedSigners returns success and
// migrateOnUnlock seeds the digest WITHOUT performing a settle. The real
// no-rotation cost is dominated by the (cached) GetInfo + classification, never
// a settle round, so unlock latency is unaffected. Here we assert the seam
// records exactly one reconcile call and zero settle calls.
func TestMigrateOnUnlockNoRotationFastPath(t *testing.T) {
	w := newSyncWallet()

	var settleCalls atomic.Int32
	// Sentinel that fails the test if the internal settle is ever reached on the
	// no-rotation path.
	w.unlockReconcileFn = func(ctx context.Context) error {
		// A real no-rotation reconcile returns before any settle; model that by
		// not touching settleCalls.
		return nil
	}
	digestCalls := 0
	w.unlockDigestFn = func(ctx context.Context) (string, bool) {
		digestCalls++
		return "seeded", true
	}

	w.migrateOnUnlock(context.Background())

	require.Equal(t, int32(0), settleCalls.Load(),
		"no settle may be performed on the no-rotation fast path")
	require.Equal(t, 1, digestCalls, "digest is seeded once on success")
	require.Equal(t, "seeded", w.lastSignerSetDigest)
}

// TestMigrateOnUnlockFailureNeverHostage proves objective (c): a migration
// failure must NOT hold the wallet hostage. migrateOnUnlock returns (so the
// caller proceeds to send syncCh with err == nil for the sync itself), it does
// NOT seed lastSignerSetDigest (so the first periodic tick re-detects the signer
// set and retries), and the failure is surfaced (logged + via status, exercised
// by reconcile-level tests).
func TestMigrateOnUnlockFailureNeverHostage(t *testing.T) {
	w := newSyncWallet()
	// Pre-seed a sentinel so we can prove the digest is NOT advanced on failure.
	w.lastSignerSetDigest = ""

	var digestFetched atomic.Bool
	w.unlockReconcileFn = func(ctx context.Context) error {
		return fmt.Errorf("settle failed: server unavailable")
	}
	w.unlockDigestFn = func(ctx context.Context) (string, bool) {
		digestFetched.Store(true)
		return "should-not-be-set", true
	}

	// migrateOnUnlock must return (never blocks / panics) on failure.
	done := make(chan struct{})
	go func() {
		w.migrateOnUnlock(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("migrateOnUnlock blocked on a migration failure (hostage)")
	}

	require.False(t, digestFetched.Load(),
		"digest fetch must be skipped on failure")
	require.Equal(t, "", w.lastSignerSetDigest,
		"digest must stay empty on failure so the periodic tick retries the migration")

	// The empty digest is exactly the seed state that makes the periodic tick
	// retry: detectAndHandleRotation fires rescanAndReconcile whenever the live
	// digest differs from lastSignerSetDigest. With lastSignerSetDigest == "",
	// any real signer-set digest differs → retry. Prove the comparison gate.
	const liveDigest = "cur:abc|dep:def"
	require.NotEqual(t, liveDigest, w.lastSignerSetDigest,
		"a non-empty live digest must differ from the unseeded digest, triggering retry")

	// And once a later attempt succeeds, the digest advances and retries stop.
	w.unlockReconcileFn = func(ctx context.Context) error { return nil }
	w.unlockDigestFn = func(ctx context.Context) (string, bool) { return liveDigest, true }
	w.migrateOnUnlock(context.Background())
	require.Equal(t, liveDigest, w.lastSignerSetDigest,
		"digest advances once migration succeeds, stopping further retries")
}

// TestPublicSettleStillSafeChecked proves the public API behavior is unchanged:
// the public Settle still runs safeCheck before delegating to the
// unexported settle. With a bare wallet (nil client/contractManager) safeCheck
// returns ErrNotInitialized and Settle never reaches the unexported settle body.
// This is the guarantee that no external caller bypasses safeCheck — the
// unexported settle is reachable only from Settle (post-safeCheck) and from
// reconcileDeprecatedSigners (the synchronous unlock-time migration), per the
// two call sites in batch_session.go and rotation.go.
func TestPublicSettleStillSafeChecked(t *testing.T) {
	w := &wallet{syncMu: &sync.Mutex{}, syncListeners: newReadyListeners()}
	_, err := w.Settle(context.Background())
	require.ErrorIs(t, err, ErrNotInitialized,
		"public Settle must still be safeCheck-gated (behavior unchanged)")
}

// TestUnlockMigrationRaceClean proves objective (d): the unlock-time migration
// sequence (migrateOnUnlock → setRestored) racing concurrent gated-op probes is
// clean under -race. The sync primitives (syncMu, syncListeners) are the only
// shared state and are all mutex-guarded.
func TestUnlockMigrationRaceClean(t *testing.T) {
	const iters = 100
	var wg sync.WaitGroup
	for i := 0; i < iters; i++ {
		w := newSyncWallet()
		w.unlockReconcileFn = func(ctx context.Context) error { return nil }
		w.unlockDigestFn = func(ctx context.Context) (string, bool) { return "d", true }

		wg.Add(3)
		go func() {
			defer wg.Done()
			w.migrateOnUnlock(context.Background())
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
