package arksdk

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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

	// Slow mocked migration. Seed "old" so the live "digest" set looks rotated.
	withMockedServices(w, "old", "digest", func(ctx context.Context, _ *client.Info) error {
		close(migrationStarted)
		<-releaseMigration
		migrationDone.Store(true)
		return nil
	})

	// Match Unlock ordering: migration before setRestored.
	unlockSeq := make(chan struct{})
	go func() {
		w.detectAndHandleSignerRotation(context.Background())
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
	require.Equal(t, "digest", w.lastSignerSet,
		"digest seeded on successful migration")
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
		withMockedServices(
			w, "old", "d", func(ctx context.Context, _ *client.Info) error { return nil },
		)

		wg.Add(3)
		go func() {
			defer wg.Done()
			w.detectAndHandleSignerRotation(context.Background())
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

// validSignerKeyHex is the secp256k1 generator point: a parseable compressed
// pubkey used wherever rotation unit tests need a non-nil, on-curve signer.
const validSignerKeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// mockWallet stubs the single clientwallet.Wallet method updateConfig touches.
// All other methods panic if called, which is fine: these tests never reach them.
type mockWallet struct {
	clientwallet.Wallet
	cfg *clienttypes.Config
}

func (f *mockWallet) GetConfigData(context.Context) (*clienttypes.Config, error) {
	return f.cfg, nil
}

// mockConfigStore stubs clienttypes.ConfigStore; AddData is a no-op.
type mockConfigStore struct {
	clienttypes.ConfigStore
}

func (f *mockConfigStore) AddData(context.Context, clienttypes.Config) error { return nil }

// mockClientStore exposes only the ConfigStore that updateConfig persists into.
type mockClientStore struct {
	clienttypes.Store
	configStore clienttypes.ConfigStore
}

func (s *mockClientStore) ConfigStore() clienttypes.ConfigStore { return s.configStore }

// withMockedServices wires the minimal dependencies detectAndHandleSignerRotation
// needs to run the full detect -> updateConfig -> migrate path under test: a
// non-nil server params, a stub client/clientStore for updateConfig, the seeded
// last signer set, and the mocked migration seam.
func withMockedServices(
	w *wallet, lastSet, liveSet string, migrate func(context.Context, *client.Info) error,
) {
	info := &client.Info{
		SignerPubKey:            validSignerKeyHex,
		DeprecatedSignerPubKeys: []client.DeprecatedSigner{{PubKey: validSignerKeyHex}},
	}
	w.lastSignerSet = lastSet
	w.client = &mockWallet{cfg: &clienttypes.Config{}}
	w.clientStore = &mockClientStore{configStore: &mockConfigStore{}}
	w.fetchSignerSetFn = func(context.Context) (*client.Info, string, error) {
		return info, liveSet, nil
	}
	w.migrateFundsAfterSignerRotationFn = migrate
}
