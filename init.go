package arksdk

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

const HeaderVersion = "go-sdk/0.10.1"

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

	transportClient, err := grpcclient.NewClient(serverUrl, HeaderVersion)
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
	w.lastSignerSet = signerSet(info)

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

	cfgData, err := w.client.GetConfigData(ctx)
	if err != nil {
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

	deprecatedSigners := make([]client.DeprecatedSigner, 0, len(cfgData.DeprecatedSigners))
	for _, signer := range cfgData.DeprecatedSigners {
		var cutoff int64
		if !signer.CutoffDate.IsZero() {
			cutoff = signer.CutoffDate.Unix()
		}
		deprecatedSigners = append(deprecatedSigners, client.DeprecatedSigner{
			PubKey:     hex.EncodeToString(signer.PubKey.SerializeCompressed()),
			CutoffDate: cutoff,
		})
	}
	serverParams := &client.Info{
		SignerPubKey:            hex.EncodeToString(cfgData.SignerPubKey.SerializeCompressed()),
		DeprecatedSignerPubKeys: deprecatedSigners,
	}

	w.dustAmount = cfgData.Dust
	w.network = cfgData.Network
	w.lastSignerSet = signerSet(serverParams)
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
		} else {
			// TODO: drop me and handle wait in finalizePendingTxs
			time.Sleep(time.Second)
		}

		err := w.refreshDb(ctx)
		if err == nil {
			w.detectAndHandleSignerRotation(ctx)
			w.scheduleNextRefresh()
		}
		w.syncCh <- err
		close(w.syncCh)

		w.bgWg.Go(func() { w.listenForArkTxs(ctx) })
		w.bgWg.Go(func() { w.listenForOnchainTxs(ctx, w.network) })
		w.bgWg.Go(func() { w.listenDbEvents(ctx) })
		w.bgWg.Go(func() { w.periodicRefreshDb(ctx) })
		w.bgWg.Go(func() { w.periodicScheduleNextRefresh(ctx) })
	})

	return nil
}

func (w *wallet) Lock(ctx context.Context) error {
	if err := w.client.Lock(ctx); err != nil {
		return err
	}

	// Abort any queued tx operations before tearing down shared state, so a
	// waiter can't resume and run against a nil contractManager / stopCtx.
	if w.txHandler != nil {
		w.txHandler.stop()
	}

	w.syncMu.Lock()
	w.syncDone = false
	w.syncErr = nil
	w.syncMu.Unlock()

	if w.stopFn != nil {
		w.stopFn()
	}
	if w.syncListeners != nil {
		w.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
		w.syncListeners.clear()
	}

	// Wait for the background workers spawned by Unlock to exit before tearing down the
	// services they use and the contract manager they dereference. Mirrors Stop().
	w.waitForBackground(5 * time.Second)

	w.stopCtx = nil

	w.Explorer().Stop()
	if w.scheduler != nil {
		w.scheduler.Stop()
	}

	if w.contractManager != nil {
		w.contractManager.Close()
		w.contractManager = nil
	}

	return nil
}

func (w *wallet) IsLocked(_ context.Context) bool {
	if w.client == nil {
		return true
	}
	return w.client.Identity().IsLocked()
}

// scheduleNextRefresh recomputes the next auto-refresh from the current vtxo set and
// (re)schedules it. It runs at unlock, whenever the vtxo set changes, and periodically as a
// safety net. If the earliest vtxo is already expired, it settles immediately to renew it
// instead of scheduling a refresh in the past.
func (w *wallet) scheduleNextRefresh() {
	// If auto-settle is disabled, nothing to do.
	if w.scheduler == nil {
		return
	}

	// Serialize concurrent callers (unlock, the periodic job, the tx listener) so the
	// read-decide-schedule sequence below is atomic. The rare settle-now branch runs while
	// holding the lock too, which is fine: settling default vtxos is infrequent.
	w.scheduleMu.Lock()
	defer w.scheduleMu.Unlock()

	// A batch is in flight: its db writes aren't committed yet, so deciding now would be based
	// on stale state (eg. a vtxo the settle is about to renew still looks about to expire). The
	// scheduleNextRefresh call the settle triggers on completion reschedules with fresh state.
	if w.txHandler != nil && w.txHandler.batchInFlight() {
		return
	}

	// Only settle-eligible vtxos drive the schedule: vtxos the wallet can't settle (eg. vhtlc
	// contract vtxos) must not be considered, otherwise an expired one Settle can't consume
	// would wedge the auto-settle loop. Recoverable vtxos are included so already-expired own
	// vtxos still trigger a renewal.
	vtxos, err := w.getSpendableVtxos(context.Background(), true)
	if err != nil {
		log.WithError(err).Warn("failed to get spendable vtxos while scheduling next refresh")
		return
	}
	// Nothing to settle.
	if len(vtxos) <= 0 {
		return
	}

	refreshVtxos := func() {
		txid, err := w.Settle(context.Background())
		if err != nil {
			log.WithError(err).Error("failed to renew vtxos")
			return
		}
		log.Debugf("refreshed vtxos in batch %s", txid)
	}

	// Find the earliest expiration across the current vtxo set.
	earliest := vtxos[0].ExpiresAt
	for _, vtxo := range vtxos[1:] {
		if vtxo.ExpiresAt.Before(earliest) {
			earliest = vtxo.ExpiresAt
		}
	}

	// The earliest vtxo is already expired: settle now to renew it rather than scheduling a
	// refresh in the past.
	if !earliest.After(time.Now()) {
		refreshVtxos()
		return
	}

	// Schedule the refresh slightly before the earliest expiration (proportional lead), but
	// only if it's sooner than the one already scheduled.
	expiry := time.Until(earliest)
	nextExpiration := time.Now().Add(expiry * 9 / 10)
	nextRefresh := w.scheduler.GetTaskScheduledAt()
	if !nextRefresh.IsZero() && !nextExpiration.Before(nextRefresh) {
		return
	}

	if err := w.scheduler.ScheduleTask(refreshVtxos, nextExpiration); err != nil {
		log.WithError(err).Warn("failed to schedule next refresh")
		return
	}
	log.Debugf("scheduled next refresh at %s", nextExpiration.Format(time.RFC3339))
}

// periodicScheduleNextRefresh recomputes the next refresh from the full vtxo set at a
// fixed interval, as a safety net: it recovers the auto-settle loop if a vtxo event was missed
// or a previous refresh couldn't be scheduled (eg. an already-expired vtxo appeared while no
// event was fired).
func (w *wallet) periodicScheduleNextRefresh(ctx context.Context) {
	if w.scheduler == nil || w.refreshVtxosScheduleInterval == 0 {
		return
	}
	ticker := time.NewTicker(w.refreshVtxosScheduleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.scheduleNextRefresh()
		}
	}
}
