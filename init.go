package arksdk

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	clientexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/go-sdk/contract"
	electrum_explorer "github.com/arkade-os/go-sdk/explorer/electrum"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

var (
	defaultExplorerUrl = map[string]string{
		arklib.Bitcoin.Name:          "https://mempool.space/api",
		arklib.BitcoinRegTest.Name:   "tcp://127.0.0.1:50001",
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
	if explorerUrl == "" {
		explorerUrl = defaultExplorerUrl[info.Network]
	}
	if initOpts.electrumEsploraURL != "" &&
		!strings.HasPrefix(explorerUrl, "tcp://") &&
		!strings.HasPrefix(explorerUrl, "ssl://") {
		return fmt.Errorf(
			"WithElectrumPackageBroadcastURL requires the main explorer to be an electrum node (set explorer URL to tcp:// or ssl://)",
		)
	}
	var pollInterval time.Duration
	if info.Network == arklib.BitcoinRegTest.Name {
		pollInterval = 2 * time.Second
	}
	explorerSvc, err := newExplorer(
		explorerUrl,
		networkFromString(info.Network),
		true,
		pollInterval,
		initOpts.electrumEsploraURL,
	)
	if err != nil {
		return fmt.Errorf("failed to init explorer: %v", err)
	}

	if err := w.client.Init(ctx, clientwallet.InitArgs{
		ServerUrl: serverUrl,
		Seed:      seed,
		Password:  password,
		Explorer:  explorerSvc,
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

	mgr, err := contract.NewManager(contract.Args{
		Store:       w.store.ContractStore(),
		KeyProvider: w.Identity(),
		Client:      w.Client(),
		Indexer:     w.Indexer(),
		Explorer:    w.Explorer(),
		Network:     w.network,
	})
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

	go func() {
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
		}
		w.syncCh <- err
		close(w.syncCh)

		go w.listenForArkTxs(ctx)
		go w.listenForOnchainTxs(ctx, w.network)
		go w.listenDbEvents(ctx)
		go w.periodicRefreshDb(ctx)
	}()

	return nil
}

func (w *wallet) Lock(ctx context.Context) error {
	if err := w.client.Lock(ctx); err != nil {
		return err
	}

	if w.stopFn != nil {
		w.stopFn()
	}
	w.Explorer().Stop()
	if w.scheduler != nil {
		w.scheduler.Stop()
	}

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

// newExplorer creates either an ElectrumX or mempool.space Explorer depending
// on the URL scheme. URLs starting with "tcp://" or "ssl://" use ElectrumX;
// all others use the mempool.space REST/WebSocket implementation.
func newExplorer(
	url string, net arklib.Network, tracker bool, pollInterval time.Duration, esploraURL string,
) (clientexplorer.Explorer, error) {
	if strings.HasPrefix(url, "tcp://") || strings.HasPrefix(url, "ssl://") {
		opts := []electrum_explorer.Option{electrum_explorer.WithTracker(tracker)}
		if pollInterval > 0 {
			opts = append(opts, electrum_explorer.WithPollInterval(pollInterval))
		}
		if esploraURL != "" {
			opts = append(opts, electrum_explorer.WithEsploraURL(esploraURL))
		}
		return electrum_explorer.NewExplorer(url, net, opts...)
	}
	opts := []mempool_explorer.Option{mempool_explorer.WithTracker(tracker)}
	if pollInterval > 0 {
		opts = append(opts, mempool_explorer.WithPollInterval(pollInterval))
	}
	return mempool_explorer.NewExplorer(url, net, opts...)
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

	vtxos, err := w.store.VtxoStore().GetSpendableVtxos(context.Background())
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
