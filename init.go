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
	"github.com/arkade-os/go-sdk/contract"
	"github.com/arkade-os/go-sdk/internal/utils"
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
		ServerUrl: serverUrl,
		Seed:      seed,
		Password:  password,
		Explorer:  explorer,
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
	mgr, err := contract.NewManager(
		a.store.ContractStore(), cfg.Network, a.Transport(), a.Wallet(),
	)
	if err != nil {
		if lockErr := a.Wallet().Lock(ctx); lockErr != nil {
			return fmt.Errorf("unlock: get config: %w (rollback lock failed: %v)", err, lockErr)
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

	go func() {
		a.Explorer().Start()

		ctx := bgCtx

		// Restore: check for non-stored contracts with funds and update the contract store
		// refreshDb will take care of updating the vtxo store.
		if err := a.scanAndRegisterKeys(ctx); err != nil {
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
		a.syncCh <- err
		close(a.syncCh)

		go a.listenForArkTxs(ctx)
		go a.listenForOnchainTxs(ctx, cfg.Network)
		go a.listenDbEvents(ctx)
		go a.periodicRefreshDb(ctx)
	}()

	return nil
}

// scanAndRegisterKeys performs a BIP44-style gap-limit scan to discover contracts that own vtxos
// beyond the currently allocated frontier by fetching data from the indexer.
//
// For each supported contract type the scan walks BIP32 child indices in
// gap-limit-sized batches, asking the indexer which derived scripts have
// VTXO activity. Scanning stops when `hdGapLimit` consecutive unused indices
// are seen. Only contracts up to (and including) the highest *actually used*
// index are then persisted — a fresh wallet with no activity allocates
// nothing, and a fresh wallet with activity at m/0/0 still picks it up
// because the scan starts at index 0 (not at NextKeyID("m/0/0")).
func (a *arkClient) scanAndRegisterKeys(
	ctx context.Context,
) error {
	allContractTypes := a.contractManager.GetSupportedContractTypes(ctx)
	for _, contractType := range allContractTypes {
		if err := a.scanContracts(ctx, contractType); err != nil {
			return err
		}
		if contractType == types.ContractTypeDefault {
			if err := a.scanBoardingContracts(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

func (a *arkClient) Lock(ctx context.Context) error {
	if err := a.ArkClient.Lock(ctx); err != nil {
		return err
	}

	a.Explorer().Stop()

	if a.stopFn != nil {
		a.stopFn()
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

func (a *arkClient) scanContracts(
	ctx context.Context, contractType types.ContractType,
) error {
	currentLastUsedKeyID, err := a.contractManager.GetLatestContractKeyId(
		ctx, contractType,
	)
	if err != nil {
		return fmt.Errorf(
			"failed to get latest key id for contract type %s: %w", contractType, err,
		)
	}

	// Where to start scanning. For a fresh wallet (no contracts of this
	// type stored yet) we scan from index 0; otherwise strictly after
	// the last stored index, since everything up to it is already
	// allocated.
	var startIdx uint32
	if currentLastUsedKeyID != "" {
		currentIdx, err := utils.ParseDerivationIndex(currentLastUsedKeyID)
		if err != nil {
			return fmt.Errorf("failed to parse latest key id: %w", err)
		}
		startIdx = currentIdx + 1
	}

	// Gap-limit scan. `lastUsedIdx` stays at the sentinel value until
	// an indexer hit promotes it; if no key is ever flagged as used we
	// leave the contract store untouched.
	const noUsage int64 = -1
	var (
		scanIdx           = startIdx
		lastUsedIdx       = noUsage
		consecutiveUnused uint32
	)
scan:
	for consecutiveUnused < a.hdGapLimit {
		contractBatch := make([]types.Contract, 0, a.hdGapLimit)
		keyIndexByScript := make(map[string]uint32, a.hdGapLimit)
		for k := range a.hdGapLimit {
			idx := scanIdx + k
			keyID := fmt.Sprintf("m/0/%d", idx)
			keyRef, err := a.Wallet().GetKey(ctx, keyID)
			if err != nil {
				return err
			}
			c, err := a.contractManager.NewContract(
				ctx, contractType, *keyRef, contract.WithDryRun(),
			)
			if err != nil {
				return fmt.Errorf("failed to derive contract for key %s: %w", keyID, err)
			}
			contractBatch = append(contractBatch, *c)
			keyIndexByScript[c.Script] = idx
		}

		used, err := a.fetchUsedContracts(ctx, contractBatch)
		if err != nil {
			return err
		}

		for _, c := range contractBatch {
			idx := keyIndexByScript[c.Script]
			if _, isUsed := used[c.Script]; isUsed {
				if int64(idx) > lastUsedIdx {
					lastUsedIdx = int64(idx)
				}
				consecutiveUnused = 0
				continue
			}
			consecutiveUnused++
			if consecutiveUnused >= a.hdGapLimit {
				break scan
			}
		}

		scanIdx += a.hdGapLimit
	}

	if lastUsedIdx == noUsage {
		return nil
	}

	// Persist contracts from the start of the scan range up to the
	// highest used index (inclusive).
	for i := startIdx; i <= uint32(lastUsedIdx); i++ {
		keyRef, err := a.Wallet().GetKey(ctx, fmt.Sprintf("m/0/%d", i))
		if err != nil {
			return err
		}
		if _, err := a.contractManager.NewContract(ctx, contractType, *keyRef); err != nil {
			return err
		}
	}

	return nil
}

func (a *arkClient) scanBoardingContracts(
	ctx context.Context,
) error {
	contractType := types.ContractTypeDefault
	currentLastUsedKeyID, err := a.contractManager.GetKeyIDUsedForLatestContract(
		ctx, contractType, contract.WithIsOnchain(),
	)
	if err != nil {
		return fmt.Errorf(
			"failed to get latest key id for boarding contract type: %w", err,
		)
	}

	// Where to start scanning. For a fresh wallet (no contracts of this
	// type stored yet) we scan from index 0; otherwise strictly after
	// the last stored index, since everything up to it is already
	// allocated.
	var startIdx uint32
	if currentLastUsedKeyID != "" {
		currentIdx, err := utils.ParseDerivationIndex(currentLastUsedKeyID)
		if err != nil {
			return fmt.Errorf("failed to parse latest key id: %w", err)
		}
		startIdx = currentIdx + 1
	}

	// Gap-limit scan. `lastUsedIdx` stays at the sentinel value until
	// an indexer hit promotes it; if no key is ever flagged as used we
	// leave the contract store untouched.
	const noUsage int64 = -1
	var (
		scanIdx           = startIdx
		lastUsedIdx       = noUsage
		consecutiveUnused uint32
	)
scan:
	for consecutiveUnused < a.hdGapLimit {
		contractBatch := make([]types.Contract, 0, a.hdGapLimit)
		keyIndexByScript := make(map[string]uint32, a.hdGapLimit)
		for k := range a.hdGapLimit {
			idx := scanIdx + k
			keyID := fmt.Sprintf("m/0/%d", idx)
			keyRef, err := a.Wallet().GetKey(ctx, keyID)
			if err != nil {
				return err
			}
			c, err := a.contractManager.NewContract(
				ctx, contractType, *keyRef, contract.WithIsOnchain(), contract.WithDryRun(),
			)
			if err != nil {
				return fmt.Errorf("failed to derive contract for key %s: %w", keyID, err)
			}
			contractBatch = append(contractBatch, *c)
			keyIndexByScript[c.Script] = idx
		}

		used, err := a.fetchUsedBoardingContracts(ctx, contractBatch)
		if err != nil {
			return err
		}

		for _, c := range contractBatch {
			idx := keyIndexByScript[c.Script]
			if _, isUsed := used[c.Script]; isUsed {
				if int64(idx) > lastUsedIdx {
					lastUsedIdx = int64(idx)
				}
				consecutiveUnused = 0
				continue
			}
			consecutiveUnused++
			if consecutiveUnused >= a.hdGapLimit {
				break scan
			}
		}

		scanIdx += a.hdGapLimit
	}

	if lastUsedIdx == noUsage {
		return nil
	}

	// Persist contracts from the start of the scan range up to the
	// highest used index (inclusive).
	for i := startIdx; i <= uint32(lastUsedIdx); i++ {
		keyRef, err := a.Wallet().GetKey(ctx, fmt.Sprintf("m/0/%d", i))
		if err != nil {
			return err
		}
		if _, err := a.contractManager.NewContract(
			ctx, contractType, *keyRef, contract.WithIsOnchain(),
		); err != nil {
			return err
		}
	}

	return nil
}

func (a *arkClient) fetchUsedContracts(
	ctx context.Context, contracts []types.Contract,
) (map[string]struct{}, error) {
	if len(contracts) <= 0 {
		return nil, nil
	}

	scripts := make([]string, 0, len(contracts))
	for _, c := range contracts {
		scripts = append(scripts, c.Script)
	}

	resp, err := a.ArkClient.Indexer().GetVtxos(ctx, indexer.WithScripts(scripts))
	if err != nil {
		return nil, err
	}

	used := make(map[string]struct{})
	for _, vtxo := range resp.Vtxos {
		used[vtxo.Script] = struct{}{}
	}
	return used, nil
}

func (a *arkClient) fetchUsedBoardingContracts(
	ctx context.Context, contracts []types.Contract,
) (map[string]struct{}, error) {
	used := make(map[string]struct{})
	for i, c := range contracts {
		txs, err := a.Explorer().GetTxs(c.Address)
		if err != nil {
			return nil, err
		}

		if len(txs) > 0 {
			used[c.Script] = struct{}{}
		}

		// Throttle to avoid rate limiting (20 reqs/sec)
		if (i+1)%20 == 0 {
			time.Sleep(time.Second)
		}
	}
	return used, nil
}
