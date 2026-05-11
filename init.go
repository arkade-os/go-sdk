package arksdk

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
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

func (a *arkClient) Init(
	ctx context.Context, serverUrl, seed, password string, opts ...InitOption,
) error {
	walletSvc := a.Wallet()
	if walletSvc == nil {
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

	return a.ArkClient.Init(ctx, client.InitArgs{
		ServerUrl: serverUrl,
		Seed:      seed,
		Password:  password,
		Explorer:  explorerSvc,
	})
}

func (a *arkClient) Unlock(ctx context.Context, password string) error {
	walletSvc := a.Wallet()
	if walletSvc == nil {
		return ErrNotInitialized
	}

	if _, err := walletSvc.Unlock(ctx, password); err != nil {
		return err
	}

	a.logMu.Lock()
	log.SetLevel(log.DebugLevel)
	if !a.verbose {
		log.SetLevel(log.ErrorLevel)
	}
	a.logMu.Unlock()

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf("unlock: get config: %w (rollback lock failed: %v)", err, lockErr)
		}
		return fmt.Errorf("unlock: get config: %w", err)
	}
	mgr, err := contract.NewManager(contract.Args{
		Store:       a.store.ContractStore(),
		KeyProvider: a.Wallet(),
		Client:      a.Transport(),
		Indexer:     a.Indexer(),
		Explorer:    a.Explorer(),
		Network:     cfg.Network,
	})
	if err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf(
				"unlock: init contract manager: %w (rollback lock failed: %v)", err, lockErr,
			)
		}
		return fmt.Errorf("failed to init contract manager: %w", err)
	}

	a.contractManager = mgr
	a.resetSyncStateForUnlock()
	a.utxoBroadcaster = newBroadcaster[types.UtxoEvent]()
	a.vtxoBroadcaster = newBroadcaster[types.VtxoEvent]()
	a.txBroadcaster = newBroadcaster[types.TransactionEvent]()

	go func() {
		err := <-a.syncCh
		a.setRestored(err)
	}()

	bgCtx, cancel := context.WithCancel(context.Background())
	a.stopFn = cancel
	a.bgCtx = bgCtx

	go func() {
		a.Explorer().Start()
		if a.scheduler != nil {
			a.scheduler.Start()
		}

		ctx := bgCtx

		// Look for missing contracts to track: the wallet restores at every unlock.
		if err := a.contractManager.ScanContracts(ctx, a.hdGapLimit); err != nil {
			a.syncCh <- err
			close(a.syncCh)
			return
		}

		// Finalize any pending txs that were submitted before this restore.
		// Call client-lib directly (not the go-sdk wrapper) to avoid a second
		// refreshDb before the primary one below runs.
		// TODO: For this is a best-effort attempt to finalize any pending txs. Find a way to let
		// the user aware of this so he can proceed with a manual finalization
		if _, err := a.finalizePendingTxs(ctx, nil); err != nil {
			log.WithError(err).Warn("failed to finalize pending txs")
		}

		err := a.refreshDb(ctx)
		// Register the explorer listener before signaling IsSynced so events fired
		// immediately after (e.g. from NewBoardingAddress) are not dropped before
		// listenForOnchainTxs can start consuming.
		explorerCh := a.Explorer().GetAddressesEvents()
		if err == nil {
			a.scheduleNextSettlement()
		}
		a.syncCh <- err
		close(a.syncCh)

		go a.listenForArkTxs(ctx)
		go a.listenForOnchainTxs(ctx, cfg.Network, explorerCh)
		go a.listenDbEvents(ctx)
		go a.periodicRefreshDb(ctx)
	}()

	return nil
}

func (a *arkClient) Lock(ctx context.Context) error {
	if err := a.ArkClient.Lock(ctx); err != nil {
		return err
	}

	if a.stopFn != nil {
		a.stopFn()
	}
	a.Explorer().Stop()
	if a.scheduler != nil {
		a.scheduler.Stop()
	}

	if a.contractManager != nil {
		a.contractManager.Close()
		a.contractManager = nil
	}

	a.syncMu.Lock()
	a.syncDone = false
	a.syncErr = nil
	a.syncMu.Unlock()
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
		a.syncListeners.clear()
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

func (a *arkClient) scheduleNextSettlement() {
	// If auto-settle is disabled, nothing to do
	if a.scheduler == nil {
		return
	}

	nextSettlement := a.scheduler.GetTaskScheduledAt()

	vtxos, err := a.store.VtxoStore().GetSpendableVtxos(context.Background())
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
			if _, err := a.Settle(context.Background()); err != nil {
				if errors.Is(err, ErrNoFundsToSettle) {
					log.Debugf("no vtxos to auto-settle, skipping")
					return
				}
				log.WithError(err).Error("failed to auto-settle vtxos close to expiration")
			}
		}
		if err := a.scheduler.ScheduleTask(task, nextExpiration); err != nil {
			log.WithError(err).Warn("failed to schedule next settlement")
			return
		}
		log.Debugf("scheduled next settlement at %s", nextExpiration.Format(time.RFC3339))
	}
}
