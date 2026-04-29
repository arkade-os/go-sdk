package arksdk

import (
	"context"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
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

	initOpts, err := applyInitOptions(opts...)
	if err != nil {
		return fmt.Errorf("invalid options: %v", err)
	}

	explorerUrl := initOpts.explorerUrl
	if initOpts.explorerUrl == "" {
		explorerUrl = defaultExplorerUrl[info.Network]
	}
	explorerOpts := []mempool_explorer.Option{mempool_explorer.WithTracker(true)}
	if info.Network == arklib.BitcoinRegTest.Name {
		explorerOpts = append(explorerOpts, mempool_explorer.WithPollInterval(2*time.Second))
	}
	explorer, err := mempool_explorer.NewExplorer(
		explorerUrl, networkFromString(info.Network), explorerOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to init explorer: %v", err)
	}

	if initOpts.wallet != nil {
		return a.InitWithWallet(ctx, client.InitWithWalletArgs{
			ServerUrl: serverUrl,
			Seed:      seed,
			Password:  password,
			Wallet:    initOpts.wallet,
			Explorer:  explorer,
		})
	}

	return a.ArkClient.Init(ctx, client.InitArgs{
		ServerUrl:  serverUrl,
		Seed:       seed,
		Password:   password,
		WalletType: client.SingleKeyWallet,
		Explorer:   explorer,
	})
}

func (a *arkClient) Unlock(ctx context.Context, password string) error {
	if err := a.ArkClient.Unlock(ctx, password); err != nil {
		return err
	}

	a.logMu.Lock()
	log.SetLevel(log.DebugLevel)
	if !a.verbose {
		log.SetLevel(log.ErrorLevel)
	}
	a.logMu.Unlock()

	a.syncDone = false
	a.syncErr = nil
	a.syncCh = make(chan error)
	a.utxoBroadcaster = newBroadcaster[types.UtxoEvent]()
	a.vtxoBroadcaster = newBroadcaster[types.VtxoEvent]()
	a.txBroadcaster = newBroadcaster[types.TransactionEvent]()

	go func() {
		err := <-a.syncCh
		a.setRestored(err)
	}()

	bgCtx, cancel := context.WithCancel(context.Background())
	a.stopFn = cancel

	a.goroutineWg.Add(4)
	go func() {
		a.Explorer().Start()

		ctx := bgCtx

		err := a.refreshDb(ctx)
		a.syncCh <- err
		close(a.syncCh)

		// start listening to stream events
		go a.listenForArkTxs(ctx)
		go a.listenForOnchainTxs(ctx)
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
		a.goroutineWg.Wait()
	}
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("wallet locked while restoring"))
		a.syncListeners.clear()
	}
	return nil
}
