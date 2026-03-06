package arksdk

import (
	"context"
	"fmt"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

func (a *arkClient) Init(
	ctx context.Context, serverUrl, seed, password string, opts ...InitOption,
) error {
	transportClient, err := grpcclient.NewClient(serverUrl)
	if err != nil {
		return err
	}
	info, err := transportClient.GetInfo(ctx)
	if err != nil {
		return err
	}

	initOpts := newDefaultInitOptions()
	for _, opt := range opts {
		if err := opt(initOpts); err != nil {
			return fmt.Errorf("invalid options: %v", err)
		}
	}

	if initOpts.wallet != nil {
		explorer := initOpts.explorer
		if initOpts.explorerUrl != "" {
			explorerOpts := []mempool_explorer.Option{mempool_explorer.WithTracker(true)}
			if info.Network == arklib.BitcoinRegTest.Name {
				interval := 2 * time.Second
				if initOpts.explorerPollInterval > 0 {
					interval = initOpts.explorerPollInterval
				}
				explorerOpts = append(explorerOpts, mempool_explorer.WithPollInterval(interval))

				net := networkFromString(info.Network)
				var err error
				explorer, err = mempool_explorer.NewExplorer(
					initOpts.explorerUrl, net, explorerOpts...,
				)
				if err != nil {
					return fmt.Errorf("failed to init explorer: %v", err)
				}
			}
		}
		return a.InitWithWallet(ctx, client.InitWithWalletArgs{
			ServerUrl: serverUrl,
			Seed:      seed,
			Password:  password,
			Wallet:    initOpts.wallet,
			Explorer:  explorer,
		})
	}

	explorer := initOpts.explorer
	if initOpts.explorerUrl != "" {
		explorerOpts := []mempool_explorer.Option{mempool_explorer.WithTracker(true)}
		if info.Network == arklib.BitcoinRegTest.Name && initOpts.explorerPollInterval > 0 {
			explorerOpts = append(explorerOpts, mempool_explorer.WithPollInterval(
				initOpts.explorerPollInterval,
			))

			net := networkFromString(info.Network)
			var err error
			explorer, err = mempool_explorer.NewExplorer(
				initOpts.explorerUrl, net, explorerOpts...,
			)
			if err != nil {
				return fmt.Errorf("failed to init explorer: %v", err)
			}
		}
	}

	walletType := client.SingleKeyWallet
	if initOpts.walletType != "" {
		walletType = initOpts.walletType
	}

	return a.ArkClient.Init(ctx, client.InitArgs{
		ServerUrl:  serverUrl,
		Seed:       seed,
		Password:   password,
		WalletType: walletType,
		Explorer:   explorer,
	})
}

func (a *arkClient) Unlock(ctx context.Context, password string) error {
	if err := a.ArkClient.Unlock(ctx, password); err != nil {
		return err
	}

	log.SetLevel(log.DebugLevel)
	if !a.verbose {
		log.SetLevel(log.ErrorLevel)
	}

	a.dbMu = &sync.Mutex{}

	a.syncDone = false
	a.syncErr = nil
	a.syncCh = make(chan error)
	a.syncMu = &sync.Mutex{}
	a.utxoBroadcaster = newBroadcaster[types.UtxoEvent]()
	a.vtxoBroadcaster = newBroadcaster[types.VtxoEvent]()
	a.txBroadcaster = newBroadcaster[types.TransactionEvent]()

	go func() {
		err := <-a.syncCh
		a.setRestored(err)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	a.stopFn = cancel

	a.ArkClient.Explorer().Start()

	err := a.refreshDb(ctx)
	a.syncCh <- err
	close(a.syncCh)

	// start listening to stream events
	go a.listenForArkTxs(ctx)
	go a.listenForOnchainTxs(ctx)
	go a.listenDbEvents(ctx)

	// start periodic refresh db
	go a.periodicRefreshDb(ctx)

	return nil
}

func (a *arkClient) Lock(ctx context.Context) error {
	if err := a.ArkClient.Lock(ctx); err != nil {
		return err
	}

	a.ArkClient.Explorer().Stop()

	a.syncMu.Lock()
	a.syncDone = false
	a.syncErr = nil

	if a.stopFn != nil {
		a.stopFn()
	}
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
		a.syncListeners.clear()
	}
	return nil
}
