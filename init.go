package arksdk

import (
	"context"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	client "github.com/arkade-os/arkd/pkg/client-lib"
	grpcclient "github.com/arkade-os/arkd/pkg/client-lib/client/grpc"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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

	return a.ArkClient.Init(ctx, client.InitArgs{
		ServerUrl:  serverUrl,
		Seed:       seed,
		Password:   password,
		WalletType: client.SingleKeyWallet,
		Explorer:   explorer,
	})
}

func (a *arkClient) Unlock(ctx context.Context, password string) error {
	// Unlock the wallet directly first so we can derive at least one key
	// before calling a.ArkClient.Unlock. The client-lib Unlock runs
	// finalizePendingTxs, which calls GetAddresses; on a fresh wallet with
	// no derived keys that produces an empty script set and the indexer
	// rejects it. Deriving key-0 here ensures the script set is non-empty.
	if _, err := a.Wallet().Unlock(ctx, password); err != nil {
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
	mgr := contract.NewManager(a.Wallet(), cfg, a.store.ContractStore())
	if err := mgr.Load(ctx); err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf("unlock: load contracts: %w (rollback lock failed: %v)", err, lockErr)
		}
		return fmt.Errorf("unlock: load contracts: %w", err)
	}
	// NewDefault is idempotent: reuses the existing contract when one already
	// exists, and re-derives the deterministic key-0 on restore. This ensures
	// the wallet has at least one derived key before a.ArkClient.Unlock runs
	// finalizePendingTxs.
	if _, err := mgr.NewDefault(ctx); err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf(
				"unlock: init default contract: %w (rollback lock failed: %v)",
				err,
				lockErr,
			)
		}
		return fmt.Errorf("unlock: init default contract: %w", err)
	}

	if err := a.ArkClient.Unlock(ctx, password); err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf("unlock: %w (rollback lock failed: %v)", err, lockErr)
		}
		return err
	}

	a.cmMu.Lock()
	a.contractManager = mgr
	a.cmMu.Unlock()

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

	go func() {
		a.Explorer().Start()

		ctx := bgCtx

		// Gap-limit scan: discover wallet keys that had vtxos from before this
		// restore session. Non-fatal: a failure just means the restored history
		// will be incomplete, not that the unlock itself fails.
		if err := a.scanAndRegisterKeys(ctx, mgr, cfg); err != nil {
			log.WithError(err).Warn("key gap scan failed during restore")
		}

		// Finalize any pending txs that were submitted before this restore.
		// Call client-lib directly (not the go-sdk wrapper) to avoid a second
		// refreshDb before the primary one below runs.
		if signingKeys, err := a.signingKeysByScript(ctx); err != nil {
			log.WithError(err).Warn("could not build signing keys for restore finalization")
		} else if _, err := a.ArkClient.FinalizePendingTxs(
			ctx, nil, client.WithKeys(signingKeys),
		); err != nil {
			log.WithError(err).Warn("pending tx finalization failed during restore")
		}

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

// scanAndRegisterKeys performs a BIP44-style gap-limit scan to discover wallet
// keys that have vtxos on the indexer beyond the currently allocated frontier.
// This is needed on restore: the original wallet may have derived additional
// keys internally (e.g. via RedeemNotes, SendOffChain), and a fresh datadir
// only knows key-0 until the scan rediscovers those keys.
func (a *arkClient) scanAndRegisterKeys(
	ctx context.Context,
	mgr contract.Manager,
	cfg *clientTypes.Config,
) error {
	if cfg == nil {
		return nil
	}
	indexerSvc := a.ArkClient.Indexer()
	if indexerSvc == nil {
		return nil
	}

	w := a.Wallet()
	currentIdx, err := w.NextIndex(ctx)
	if err != nil {
		return err
	}
	if currentIdx == 0 {
		return nil
	}

	const gapLimit = uint32(20)

	h := &contract.DefaultHandler{}
	scriptToIndex := make(map[string]uint32, gapLimit)
	scripts := make([]string, 0, gapLimit)

	for i := currentIdx; i < currentIdx+gapLimit; i++ {
		keyID := fmt.Sprintf("m/0/%d", i)
		keyRef, err := w.GetKey(ctx, keyID)
		if err != nil {
			return err
		}
		contracts, err := h.DeriveContracts(ctx, *keyRef, cfg)
		if err != nil {
			return err
		}
		for _, c := range contracts {
			if c.Type == contract.TypeDefault && !c.IsOnchain {
				scripts = append(scripts, c.Script)
				scriptToIndex[c.Script] = i
				break
			}
		}
	}

	if len(scripts) == 0 {
		return nil
	}

	resp, err := indexerSvc.GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		return err
	}

	maxFoundIndex := currentIdx - 1
	for _, vtxo := range resp.Vtxos {
		if idx, ok := scriptToIndex[vtxo.Script]; ok && idx > maxFoundIndex {
			maxFoundIndex = idx
		}
	}

	if maxFoundIndex < currentIdx {
		return nil // no new keys found
	}

	// Advance nextKeyIndex to cover all discovered keys.
	for {
		nextIdx, err := w.NextIndex(ctx)
		if err != nil {
			return err
		}
		if nextIdx > maxFoundIndex {
			break
		}
		if _, err := w.NewKey(ctx); err != nil {
			return err
		}
	}

	return mgr.Load(ctx)
}

func (a *arkClient) Lock(ctx context.Context) error {
	if err := a.ArkClient.Lock(ctx); err != nil {
		return err
	}

	a.Explorer().Stop()

	if a.stopFn != nil {
		a.stopFn()
	}

	a.cmMu.Lock()
	if a.contractManager != nil {
		if err := a.contractManager.Close(); err != nil {
			log.WithError(err).Warn("failed to close contract manager on lock")
		}
		a.contractManager = nil
	}
	a.cmMu.Unlock()

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
