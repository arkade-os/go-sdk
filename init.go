package arksdk

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

var (
	defaultExplorerUrl = map[string]string{
		arklib.Bitcoin.Name:          "https://mempool.space/api",
		arklib.BitcoinRegTest.Name:   "http://127.0.0.1:3000",
		arklib.BitcoinTestNet.Name:   "https://mempool.space/testnet/api",
		arklib.BitcoinSigNet.Name:    "https://mempool.space/signet/api",
		arklib.BitcoinMutinyNet.Name: "https://mutinynet.com/api",
	}
)

func (w *wallet) Init(
	ctx context.Context, serverUrl, seed, password string, opts ...InitOption,
) error {
	identitySvc := w.Identity()
	if identitySvc == nil {
		return ErrNotInitialized
	}

	transportClient, err := grpcclient.NewClient(serverUrl)
	if err != nil {
		return err
	}
	info, err := transportClient.GetInfo(ctx)
	if err != nil {
		return err
	}
	network := networkFromString(info.Network)

	initOpts, err := applyInitOptions(opts...)
	if err != nil {
		return fmt.Errorf("invalid options: %v", err)
	}

	explorerUrl := initOpts.explorerUrl
	if initOpts.explorerUrl == "" {
		explorerUrl = defaultExplorerUrl[info.Network]
	}
	explorerOpts := []mempoolexplorer.Option{mempoolexplorer.WithTracker(true)}
	if info.Network == arklib.BitcoinRegTest.Name {
		explorerOpts = append(explorerOpts, mempoolexplorer.WithPollInterval(2*time.Second))
	}
	explorer, err := mempoolexplorer.NewExplorer(
		explorerUrl, network, explorerOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to init explorer: %v", err)
	}

	if err := w.client.Init(ctx, clientwallet.InitArgs{
		ServerUrl: serverUrl,
		Seed:      seed,
		Password:  password,
		Explorer:  explorer,
	}); err != nil {
		return err
	}

	w.network = network
	w.dustAmount = info.Dust

	return nil
}

func (w *wallet) Unlock(ctx context.Context, password string) error {
	if w.client == nil {
		return ErrNotInitialized
	}

	// If already unlocked, nothing to do
	if id := w.Identity(); id != nil && !id.IsLocked() && w.contractManager != nil {
		return nil
	}

	if err := w.client.Unlock(ctx, password); err != nil {
		return err
	}

	w.logMu.Lock()
	log.SetLevel(log.DebugLevel)
	if !w.verbose {
		log.SetLevel(log.ErrorLevel)
	}
	w.logMu.Unlock()

	mgrOpts := make([]contract.ManagerOption, 0, len(w.customHandlers))
	for t, h := range w.customHandlers {
		mgrOpts = append(mgrOpts, contract.WithHandler(t, h))
	}
	mgr, err := contract.NewManager(contract.Args{
		Store:       w.store.ContractStore(),
		KeyProvider: w.Identity(),
		Client:      w.Client(),
		Indexer:     w.Indexer(),
		Explorer:    w.Explorer(),
		Network:     w.network,
	}, mgrOpts...)
	if err != nil {
		if lockErr := w.Identity().Lock(ctx); lockErr != nil {
			return fmt.Errorf(
				"unlock: init contract manager: %w (rollback lock failed: %v)", err, lockErr,
			)
		}
		return fmt.Errorf("failed to init contract manager: %w", err)
	}

	w.contractManager = mgr
	w.resetSyncStateForUnlock()
	w.utxoBroadcaster = newBroadcaster[types.UtxoEvent]()
	w.vtxoBroadcaster = newBroadcaster[types.VtxoEvent]()
	w.txBroadcaster = newBroadcaster[types.TransactionEvent]()

	go func() {
		err := <-w.syncCh
		w.setRestored(err)
	}()

	bgCtx, cancel := context.WithCancel(context.Background())
	w.stopFn = cancel
	w.stopCtx = bgCtx
	w.txHandler = newTxHandler()

	w.bgWg.Go(func() {
		w.Explorer().Start()
		if w.scheduler != nil {
			w.scheduler.Start()
		}

		ctx := bgCtx

		// Look for missing contracts to track: the wallet restores at every unlock.
		if err := w.contractManager.ScanContracts(ctx, w.hdGapLimit); err != nil {
			w.syncCh <- err
			close(w.syncCh)
			return
		}

		// Finalize any pending txs that were submitted before this restore.
		// Call client-lib directly (not the go-sdk wrapper) to avoid a second
		// refreshDb before the primary one below runs.
		// TODO: For this is a best-effort attempt to finalize any pending txs. Find a way to let
		// the user aware of this so he can proceed with a manual finalization
		if _, err := w.finalizePendingTxs(ctx, nil); err != nil {
			log.WithError(err).Warn("failed to finalize pending txs")
		}

		err := w.refreshDb(ctx)
		if err == nil {
			w.scheduleNextSettlement()

			// Migrate actionable deprecated-signer vtxos onto current-signer
			// outputs SYNCHRONOUSLY, before the wallet is marked synced. The user
			// requirement is that the wallet must be usable only after the
			// migration attempt completes: no public (safeCheck-gated) operation
			// may proceed, and the caller must not receive the synced
			// notification, until reconcile has finished. reconcile calls the
			// unexported settle (no safeCheck), so it does not hit ErrIsSyncing
			// even though syncDone is still false here.
			//
			// Item A discovery (ScanContracts above) has already persisted any
			// pre-rotation deprecated-signer contracts and refreshDb has pulled
			// their vtxos, so migration has a consistent view.
			//
			// The live-rotation digest is initialized ONLY when reconcile
			// succeeds. This keeps the unlock path consistent with F4's
			// advance-after-success rule (wallet.go detectAndHandleRotation): if
			// reconcile fails here, lastSignerSetDigest is left at its zero value
			// so the first periodic tick sees a signer-set change and retries the
			// rescan+reconcile. Seeding the digest unconditionally would suppress
			// that retry and leave a failed migration stuck until a restart.
			//
			// A reconcile failure must NEVER hold the wallet hostage: the error is
			// logged and surfaced via DeprecatedSignerStatus, but the wallet still
			// proceeds to mark itself synced below (err stays the refreshDb error,
			// which is nil here).
			w.migrateOnUnlock(ctx)
		}
		w.syncCh <- err
		close(w.syncCh)

		w.bgWg.Go(func() { w.listenForArkTxs(ctx) })
		w.bgWg.Go(func() { w.listenForOnchainTxs(ctx, w.network) })
		w.bgWg.Go(func() { w.listenDbEvents(ctx) })
		w.bgWg.Go(func() { w.periodicRefreshDb(ctx) })
	})

	return nil
}

// migrateOnUnlock runs the deprecated-signer migration synchronously during
// Unlock (before the wallet is marked synced) and seeds the live-rotation
// digest only when the migration attempt succeeds. It is split out of the
// Unlock goroutine so the reconcile-vs-digest interaction is unit-testable via
// the unlockReconcileFn seam without standing up a full client.
//
// Digest semantics (consistent with detectAndHandleRotation's
// advance-after-success rule):
//   - success  → seed lastSignerSetDigest from the current signer set, so the
//     periodic rotation detector does not redundantly re-scan the same set.
//   - failure  → leave lastSignerSetDigest at its zero value, so the first
//     periodic tick sees a signer-set change and retries rescan+reconcile.
//
// It never returns an error: a migration failure is logged and surfaced via
// DeprecatedSignerStatus but must not block the caller (never-hostage rule).
func (w *wallet) migrateOnUnlock(ctx context.Context) {
	reconcile := w.unlockReconcileFn
	if reconcile == nil {
		reconcile = func(ctx context.Context) error {
			_, err := w.reconcileDeprecatedSigners(ctx)
			return err
		}
	}
	if err := reconcile(ctx); err != nil {
		// Never-hostage: log + surface via status, but do not seed the digest so
		// the periodic tick retries the migration.
		log.WithError(err).Warn("deprecated signer reconciliation failed")
		return
	}

	digest := w.unlockDigestFn
	if digest == nil {
		digest = func(ctx context.Context) (string, bool) {
			info, err := w.Client().GetInfo(ctx)
			if err != nil {
				return "", false
			}
			return signerSetDigest(info), true
		}
	}
	if d, ok := digest(ctx); ok {
		w.lastSignerSetDigest = d
	}
}

func (w *wallet) Lock(ctx context.Context) error {
	if err := w.client.Lock(ctx); err != nil {
		return err
	}

	w.Explorer().Stop()
	if w.scheduler != nil {
		w.scheduler.Stop()
	}

	// Abort any queued tx operations before tearing down shared state, so a
	// waiter can't resume and run against a nil contractManager / stopCtx.
	if w.txHandler != nil {
		w.txHandler.stop()
	}

	if w.stopFn != nil {
		w.stopFn()
	}
	w.stopCtx = nil

	if w.contractManager != nil {
		w.contractManager.Close()
		w.contractManager = nil
	}

	w.syncMu.Lock()
	w.syncDone = false
	w.syncErr = nil
	w.syncMu.Unlock()
	if w.syncListeners != nil {
		w.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
		w.syncListeners.clear()
	}
	return nil
}

func (w *wallet) IsLocked(_ context.Context) bool {
	if w.client == nil {
		return true
	}
	return w.client.Identity().IsLocked()
}

func (w *wallet) scheduleNextSettlement() {
	// If auto-settle is disabled, nothing to do
	if w.scheduler == nil {
		return
	}

	nextSettlement := w.scheduler.GetTaskScheduledAt()

	vtxos, err := w.store.VtxoStore().GetSpendableOrRecoverableVtxos(context.Background())
	if err != nil {
		log.WithError(err).Warn("failed to get spendable vtxos while scheduling next settlement")
		return
	}

	// Nothing to do
	if len(vtxos) <= 0 {
		return
	}

	sort.SliceStable(vtxos, func(i, j int) bool {
		return vtxos[i].ExpiresAt.Before(vtxos[j].ExpiresAt)
	})

	// Reduce the real vtxo expiration date of 10%
	expiry := time.Until(vtxos[0].ExpiresAt)
	nextExpiration := time.Now().Add(expiry * 9 / 10)
	if nextSettlement.IsZero() || nextExpiration.Before(nextSettlement) {
		task := func() {
			if _, err := w.Settle(context.Background()); err != nil {
				if errors.Is(err, ErrNoFundsToSettle) {
					log.Debugf("no vtxos to auto-settle, skipping")
					return
				}
				log.WithError(err).Error("failed to auto-settle vtxos close to expiration")
			}
		}
		if err := w.scheduler.ScheduleTask(task, nextExpiration); err != nil {
			log.WithError(err).Warn("failed to schedule next settlement")
			return
		}
		log.Debugf("scheduled next settlement at %s", nextExpiration.Format(time.RFC3339))
	}
}
