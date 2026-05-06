package arksdk

import (
	"context"
	"fmt"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	clientexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
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

	go func() {
		a.Explorer().Start()

		ctx := bgCtx

		if _, err := a.discoverHDWalletKeys(ctx); err != nil {
			a.syncCh <- err
			close(a.syncCh)
			return
		}

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
		a.syncCh <- err
		close(a.syncCh)

		// start listening to stream events
		go a.listenForArkTxs(ctx)
		go a.listenForOnchainTxs(ctx, explorerCh)
		go a.listenDbEvents(ctx)

		// start periodic refresh db
		go a.periodicRefreshDb(ctx)
	}()

	return nil
}

func (a *arkClient) Lock(ctx context.Context) error {
	if err := a.ArkClient.Lock(ctx); err != nil {
		return err
	}

	a.Explorer().Stop()

	a.syncMu.Lock()
	a.syncDone = false
	a.syncErr = nil
	a.syncMu.Unlock()

	if a.stopFn != nil {
		a.stopFn()
	}
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
