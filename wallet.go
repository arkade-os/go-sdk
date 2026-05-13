package arksdk

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	clientwallet "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempoolexplorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	"github.com/arkade-os/arkd/pkg/client-lib/identity"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientstore "github.com/arkade-os/arkd/pkg/client-lib/store"
	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/contract"
	hdidentity "github.com/arkade-os/go-sdk/identity"
	"github.com/arkade-os/go-sdk/scheduler"
	cronscheduler "github.com/arkade-os/go-sdk/scheduler/gocron"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

var (
	ErrNotInitialized = fmt.Errorf("wallet not initialized")
	ErrIsLocked       = fmt.Errorf("wallet is locked")
	ErrIsSyncing      = fmt.Errorf("wallet is still syncing")
)

type wallet struct {
	client          clientwallet.Wallet
	clientStore     clienttypes.Store
	store           types.Store
	contractManager contract.Manager
	scheduler       scheduler.SchedulerService

	syncMu        *sync.Mutex
	syncCh        chan error
	syncDone      bool
	syncErr       error
	syncListeners *syncListeners
	stopFn        context.CancelFunc
	stopOnce      sync.Once
	bgWg          sync.WaitGroup
	dbMu          *sync.Mutex
	logMu         *sync.Mutex

	verbose           bool
	refreshDbInterval time.Duration
	lastUpdate        time.Time
	hdGapLimit        uint32
	network           arklib.Network
	dustAmount        uint64

	utxoBroadcaster *broadcaster[types.UtxoEvent]
	vtxoBroadcaster *broadcaster[types.VtxoEvent]
	txBroadcaster   *broadcaster[types.TransactionEvent]
}

func NewWallet(datadir string, opts ...WalletOption) (Wallet, error) {
	o, err := applyWalletOptions(opts...)
	if err != nil {
		return nil, err
	}

	datadir = strings.TrimSpace(datadir)
	if len(datadir) == 0 {
		return nil, errors.New("datadir must be specified")
	}

	clientDbConfig := clientstore.Config{
		ConfigStoreType: clienttypes.FileStore,
		BaseDir:         datadir,
	}
	dbConfig := store.Config{
		StoreType: types.SQLStore,
		Args:      datadir,
	}

	clientDb, err := clientstore.NewStore(clientDbConfig)
	if err != nil {
		return nil, err
	}
	db, err := store.NewStore(dbConfig)
	if err != nil {
		return nil, err
	}

	if o.scheduler == nil {
		o.scheduler = cronscheduler.NewScheduler()
	}
	if o.disableAutoSettle {
		o.scheduler = nil
	}

	// Disable underlying finalization of pending txs as we are handling that ourselves
	clientOpts := []clientwallet.ServiceOption{
		clientwallet.WithoutFinalizePendingTxs(),
	}
	if o.verbose {
		clientOpts = append(clientOpts, clientwallet.WithVerbose())
	}

	if o.identity == nil {
		hdIdentity, err := newDefaultHDIdentity(datadir)
		if err != nil {
			return nil, fmt.Errorf("failed to setup wallet: %s", err)
		}
		o.identity = hdIdentity
	}
	clientOpts = append(clientOpts, clientwallet.WithIdentity(o.identity))

	cli, err := clientwallet.NewWallet(clientDb, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &wallet{
		client:            cli,
		verbose:           o.verbose,
		store:             db,
		clientStore:       clientDb,
		syncMu:            &sync.Mutex{},
		syncListeners:     newReadyListeners(),
		syncCh:            make(chan error),
		dbMu:              &sync.Mutex{},
		logMu:             &sync.Mutex{},
		refreshDbInterval: o.refreshDbInterval,
		hdGapLimit:        o.hdGapLimit,
		scheduler:         o.scheduler,
	}, nil
}

func LoadWallet(datadir string, opts ...WalletOption) (Wallet, error) {
	o, err := applyWalletOptions(opts...)
	if err != nil {
		return nil, err
	}

	datadir = strings.TrimSpace(datadir)
	if len(datadir) == 0 {
		return nil, errors.New("datadir must be specified")
	}

	clientDbConfig := clientstore.Config{
		ConfigStoreType: clienttypes.FileStore,
		BaseDir:         datadir,
	}
	dbConfig := store.Config{
		StoreType: types.SQLStore,
		Args:      datadir,
	}

	clientDb, err := clientstore.NewStore(clientDbConfig)
	if err != nil {
		return nil, err
	}
	db, err := store.NewStore(dbConfig)
	if err != nil {
		return nil, err
	}

	if o.scheduler == nil {
		o.scheduler = cronscheduler.NewScheduler()
	}
	if o.disableAutoSettle {
		o.scheduler = nil
	}

	// Disable underlying finalization of pending txs as we are handling that ourselves
	clientOpts := []clientwallet.ServiceOption{
		clientwallet.WithoutFinalizePendingTxs(),
	}
	var explorerSvc explorer.Explorer
	if o.verbose {
		clientOpts = append(clientOpts, clientwallet.WithVerbose())
	}

	// client.LoadArkClient defaults to noTracking=true, which leaves the explorer's
	// listeners field nil. When listenForOnchainTxs calls GetAddressesEvents() it
	// dereferences that nil field and panics. Pre-create a tracking-enabled explorer
	// from the stored config and inject it so the underlying call skips creating its own.
	cfgData, err := clientDb.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData != nil {
		explorerUrl := cfgData.ExplorerURL
		if len(explorerUrl) == 0 {
			explorerUrl = defaultExplorerUrl[cfgData.Network.Name]
		}
		explorerOpts := []mempoolexplorer.Option{mempoolexplorer.WithTracker(true)}
		if cfgData.Network.Name == arklib.BitcoinRegTest.Name {
			explorerOpts = append(explorerOpts, mempoolexplorer.WithPollInterval(2*time.Second))
		}
		explorerSvc, err = mempoolexplorer.NewExplorer(
			explorerUrl, cfgData.Network, explorerOpts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to init explorer: %v", err)
		}
		clientOpts = append(clientOpts, clientwallet.WithExplorer(explorerSvc))
	}

	if o.identity == nil {
		identityStore, err := newHDIdentityStore(datadir)
		if err != nil {
			return nil, fmt.Errorf("failed to setup identity store: %w", err)
		}
		data, err := identityStore.Load(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to load identity data from store: %w", err)
		}
		if data == nil {
			return nil, ErrNotInitialized
		}
		hdIdentity, err := hdidentity.NewIdentity(identityStore)
		if err != nil {
			return nil, fmt.Errorf("failed to setup identity: %s", err)
		}
		o.identity = hdIdentity
	}
	clientOpts = append(clientOpts, clientwallet.WithIdentity(o.identity))

	cli, err := clientwallet.LoadWallet(clientDb, clientOpts...)
	if err != nil {
		return nil, err
	}

	return &wallet{
		client:            cli,
		verbose:           o.verbose,
		store:             db,
		clientStore:       clientDb,
		syncMu:            &sync.Mutex{},
		syncListeners:     newReadyListeners(),
		syncCh:            make(chan error),
		dbMu:              &sync.Mutex{},
		logMu:             &sync.Mutex{},
		refreshDbInterval: o.refreshDbInterval,
		hdGapLimit:        o.hdGapLimit,
		scheduler:         o.scheduler,
		network:           cfgData.Network,
	}, nil
}

func (w *wallet) Store() types.Store {
	return w.store
}

func (w *wallet) Explorer() explorer.Explorer {
	if w.client == nil {
		return nil
	}
	return w.client.Explorer()
}

func (w *wallet) Indexer() indexer.Indexer {
	if w.client == nil {
		return nil
	}
	return w.client.Indexer()
}

func (w *wallet) Client() client.Client {
	if w.client == nil {
		return nil
	}
	return w.client.Client()
}

func (w *wallet) Identity() identity.Identity {
	if w.client == nil {
		return nil
	}
	return w.client.Identity()
}

func (w *wallet) ContractManager() contract.Manager {
	return w.contractManager
}

func (w *wallet) IsSynced(ctx context.Context) <-chan types.SyncEvent {
	ch := make(chan types.SyncEvent, 1)

	w.syncMu.Lock()
	syncDone := w.syncDone
	syncErr := w.syncErr
	w.syncMu.Unlock()

	if syncDone {
		go func() {
			ch <- types.SyncEvent{
				Synced: syncErr == nil,
				Err:    syncErr,
			}
		}()
		return ch
	}

	w.syncListeners.add(ch)
	return ch
}

func (w *wallet) Reset(ctx context.Context) {
	if w.client == nil {
		return
	}

	w.client.Reset(ctx)
	if exp := w.client.Explorer(); exp != nil {
		exp.Stop()
	}

	w.syncMu.Lock()
	w.syncDone = false
	w.syncErr = nil
	w.syncMu.Unlock()

	if w.stopFn != nil {
		w.stopFn()
	}
	if w.syncListeners != nil {
		w.syncListeners.broadcast(fmt.Errorf("wallet reset while restoring"))
		w.syncListeners.clear()
	}
	if w.store != nil {
		w.store.Clean(ctx)
	}
	w.lastUpdate = time.Time{}
}

func (w *wallet) Dump(ctx context.Context) (string, error) {
	if w.client == nil {
		return "", ErrNotInitialized
	}
	return w.client.Dump(ctx)
}

func (w *wallet) Version() string {
	return Version
}

func (w *wallet) Stop() {
	if w.client == nil {
		return
	}

	w.stopOnce.Do(func() {
		w.client.Stop()

		if explorer := w.Explorer(); explorer != nil {
			explorer.Stop()
		}
		// Tear down the auto-settle scheduler before the store closes,
		// otherwise an already-scheduled refresh task can fire after Stop()
		// and try to begin a transaction on a closed DB. Mirrors what Lock()
		// already does.
		if w.scheduler != nil {
			w.scheduler.Stop()
		}

		w.syncMu.Lock()
		w.syncDone = false
		w.syncErr = nil
		w.syncMu.Unlock()

		if w.stopFn != nil {
			w.stopFn()
		}
		if w.syncListeners != nil {
			w.syncListeners.broadcast(fmt.Errorf("service stopped while restoring"))
			w.syncListeners.clear()
		}

		// Wait for background listeners (listenForArkTxs / listenForOnchainTxs /
		// listenDbEvents / periodicRefreshDb) to exit before closing the store —
		// otherwise an in-flight handler write can race the Close and leave
		// SQLite WAL/Badger vlog tempfiles behind.
		w.waitForBackground(5 * time.Second)

		w.store.Close()
	})
}

func (w *wallet) waitForBackground(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		w.bgWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		log.Warn("timed out waiting for background workers to exit")
	}
}

func (w *wallet) GetTransactionHistory(ctx context.Context) ([]clienttypes.Transaction, error) {
	if err := w.safeCheck(); err != nil {
		return nil, err
	}

	w.dbMu.Lock()
	history, err := w.store.TransactionStore().GetAllTransactions(ctx)
	w.dbMu.Unlock()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.IsZero() || history[i].CreatedAt.After(history[j].CreatedAt)
	})
	return history, nil
}

func (w *wallet) GetTransactionEventChannel(_ context.Context) <-chan types.TransactionEvent {
	if w.txBroadcaster != nil {
		return w.txBroadcaster.subscribe(0)
	}
	return nil
}

func (w *wallet) GetVtxoEventChannel(_ context.Context) <-chan types.VtxoEvent {
	if w.vtxoBroadcaster != nil {
		return w.vtxoBroadcaster.subscribe(0)
	}
	return nil
}

func (w *wallet) GetUtxoEventChannel(_ context.Context) <-chan types.UtxoEvent {
	if w.utxoBroadcaster != nil {
		return w.utxoBroadcaster.subscribe(0)
	}
	return nil
}

// WhenNextSettlement returns the time at which the next automatic settlement
// is scheduled to fire. It returns the zero time when auto-settle is disabled
// or no settlement is currently scheduled.
func (w *wallet) WhenNextSettlement() time.Time {
	if w.scheduler == nil {
		return time.Time{}
	}
	return w.scheduler.GetTaskScheduledAt()
}

func (w *wallet) setRestored(err error) {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()

	w.syncDone = true
	w.syncErr = err

	w.syncListeners.broadcast(err)
	w.syncListeners.clear()
}

// resetSyncStateForUnlock clears the sync flags and re-creates syncCh so the
// next Unlock cycle can publish its own sync result without colliding with
// readers (e.g. IsSynced). The mutex matches every other writer of these
// fields (Lock, Reset, setRestored).
func (w *wallet) resetSyncStateForUnlock() {
	w.syncMu.Lock()
	defer w.syncMu.Unlock()

	w.syncDone = false
	w.syncErr = nil
	w.syncCh = make(chan error)
}

func (w *wallet) refreshDb(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	allContracts, err := w.contractManager.GetContracts(ctx)
	if err != nil {
		return err
	}

	if len(allContracts) <= 0 {
		return nil
	}

	offchainContracts := make([]types.Contract, 0, len(allContracts))
	boardingContracts := make([]types.Contract, 0, len(allContracts))
	for _, contract := range allContracts {
		if contract.Type == types.ContractTypeBoarding {
			boardingContracts = append(boardingContracts, contract)
			continue
		}
		offchainContracts = append(offchainContracts, contract)
	}

	updateTime := time.Now()
	var spendableVtxos, spentVtxos []clienttypes.Vtxo
	// Fetch new and spent vtxos in time range, or full list at startup.
	if len(offchainContracts) > 0 {
		scripts := make([]string, 0, len(offchainContracts))
		for _, contract := range offchainContracts {
			scripts = append(scripts, contract.Script)
		}
		opts := []indexer.GetVtxosOption{indexer.WithScripts(scripts)}
		if !w.lastUpdate.IsZero() {
			updateUnix := updateTime.Unix()
			lastUpdateUnix := w.lastUpdate.Unix()
			if updateUnix > lastUpdateUnix {
				opts = append(opts, indexer.WithTimeRange(updateUnix, lastUpdateUnix))
			}
		}

		res, err := w.Indexer().GetVtxos(ctx, opts...)
		if err != nil {
			return err
		}

		for _, vtxo := range res.Vtxos {
			if vtxo.Spent || vtxo.Unrolled {
				spentVtxos = append(spentVtxos, vtxo)
				continue
			}
			spendableVtxos = append(spendableVtxos, vtxo)
		}
	}

	var (
		spendableUtxos, spentUtxos []clienttypes.Utxo
		onchainHistory             []clienttypes.Transaction
		commitmentTxsToIgnore      = make(map[string]struct{})
	)
	if len(boardingContracts) > 0 {
		// Fetch new and spent boarding utxos.
		type params struct {
			exitDelay  arklib.RelativeLocktime
			tapscripts []string
		}
		boardingAddresses := make([]string, 0, len(boardingContracts))
		addrParams := make(map[string]params, len(boardingContracts))
		for _, contract := range boardingContracts {
			boardingAddresses = append(boardingAddresses, contract.Address)
			handler, err := w.contractManager.GetHandler(ctx, contract)
			if err != nil {
				return err
			}
			exitDelay, err := handler.GetExitDelay(contract)
			if err != nil {
				return err
			}
			tapscripts, err := handler.GetTapscripts(contract)
			if err != nil {
				return err
			}
			addrParams[contract.Script] = params{*exitDelay, tapscripts}
		}

		utxos, err := w.Explorer().GetUtxos(boardingAddresses)
		if err != nil {
			return err
		}

		allUtxos := make([]clienttypes.Utxo, 0, len(utxos))
		for _, utxo := range utxos {
			params := addrParams[utxo.Script]
			allUtxos = append(allUtxos, utxo.ToUtxo(params.exitDelay, params.tapscripts))
		}

		for _, utxo := range allUtxos {
			if utxo.Spent {
				spentUtxos = append(spentUtxos, utxo)
				commitmentTxsToIgnore[utxo.SpentBy] = struct{}{}
				continue
			}
			spendableUtxos = append(spendableUtxos, utxo)
		}

		// Rebuild tx history.
		unconfirmedTxs := make([]clienttypes.Transaction, 0)
		confirmedTxs := make([]clienttypes.Transaction, 0)
		for _, u := range allUtxos {
			tx := clienttypes.Transaction{
				TransactionKey: clienttypes.TransactionKey{
					BoardingTxid: u.Txid,
				},
				Amount:    u.Amount,
				Type:      clienttypes.TxReceived,
				CreatedAt: u.CreatedAt,
				SettledBy: u.SpentBy,
				Hex:       u.Tx,
			}

			if u.CreatedAt.IsZero() {
				unconfirmedTxs = append(unconfirmedTxs, tx)
				continue
			}
			confirmedTxs = append(confirmedTxs, tx)
		}

		onchainHistory = append(unconfirmedTxs, confirmedTxs...)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TODO tx packet handling ?
	offchainHistory, err := w.vtxosToTxs(ctx, spendableVtxos, spentVtxos, commitmentTxsToIgnore)
	if err != nil {
		return err
	}

	history := append(onchainHistory, offchainHistory...)
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.After(history[j].CreatedAt)
	})

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TODO make DB queries transactional

	// TODO goroutines

	// Update tx history in db.
	if err := w.refreshTxDb(ctx, history); err != nil {
		return err
	}

	// Update utxos in db.
	if err := w.refreshUtxoDb(ctx, spendableUtxos, spentUtxos); err != nil {
		return err
	}

	// Update vtxos in db.
	if err := w.refreshVtxoDb(ctx, spendableVtxos, spentVtxos); err != nil {
		return err
	}

	w.lastUpdate = updateTime

	return nil
}

func (w *wallet) refreshTxDb(ctx context.Context, newTxs []clienttypes.Transaction) error {
	// Fetch old data.
	oldTxs, err := w.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return err
	}

	// Index the old data for quick lookups.
	oldTxsMap := make(map[string]clienttypes.Transaction, len(oldTxs))
	updateTxsMap := make(map[string]clienttypes.Transaction, 0)
	unconfirmedTxsMap := make(map[string]clienttypes.Transaction, 0)
	for _, tx := range oldTxs {
		if tx.CreatedAt.IsZero() {
			unconfirmedTxsMap[tx.TransactionKey.String()] = tx
		} else if tx.SettledBy == "" {
			updateTxsMap[tx.TransactionKey.String()] = tx
		}
		oldTxsMap[tx.TransactionKey.String()] = tx
	}

	txsToAdd := make([]clienttypes.Transaction, 0, len(newTxs))
	txsToSettle := make([]clienttypes.Transaction, 0, len(newTxs))
	txsToConfirm := make([]clienttypes.Transaction, 0, len(newTxs))
	for _, tx := range newTxs {
		if _, ok := oldTxsMap[tx.TransactionKey.String()]; !ok {
			txsToAdd = append(txsToAdd, tx)
			continue
		}

		if _, ok := unconfirmedTxsMap[tx.TransactionKey.String()]; ok && !tx.CreatedAt.IsZero() {
			txsToConfirm = append(txsToConfirm, tx)
			continue
		}
		if _, ok := updateTxsMap[tx.TransactionKey.String()]; ok && tx.SettledBy != "" {
			txsToSettle = append(txsToSettle, tx)
		}
	}

	if len(txsToAdd) > 0 {
		count, err := w.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new transaction(s)", count)
		}
	}
	if len(txsToSettle) > 0 {
		count, err := w.store.TransactionStore().UpdateTransactions(ctx, txsToSettle)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}
	if len(txsToConfirm) > 0 {
		count, err := w.store.TransactionStore().UpdateTransactions(ctx, txsToConfirm)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("confirmed %d transaction(s)", count)
		}
	}

	return nil
}

func (w *wallet) refreshUtxoDb(
	ctx context.Context, spendableUtxos, spentUtxos []clienttypes.Utxo,
) error {
	// Fetch old data.
	oldSpendableUtxos, _, err := w.store.UtxoStore().GetAllUtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableUtxoMap := make(map[clienttypes.Outpoint]clienttypes.Utxo, 0)
	for _, u := range oldSpendableUtxos {
		oldSpendableUtxoMap[u.Outpoint] = u
	}

	utxosToAdd := make([]clienttypes.Utxo, 0, len(spendableUtxos))
	utxosToConfirm := make(map[clienttypes.Outpoint]int64)
	for _, utxo := range spendableUtxos {
		if _, ok := oldSpendableUtxoMap[utxo.Outpoint]; !ok {
			utxosToAdd = append(utxosToAdd, utxo)
		} else {
			var confirmedAt int64
			if !utxo.CreatedAt.IsZero() {
				confirmedAt = utxo.CreatedAt.Unix()
				utxosToConfirm[utxo.Outpoint] = confirmedAt
			}
		}
	}

	// Spent vtxos include swept and redeemed, let's make sure to update any vtxo that was
	// previously spendable.
	utxosToSpend := make(map[clienttypes.Outpoint]string)
	for _, utxo := range spentUtxos {
		if _, ok := oldSpendableUtxoMap[utxo.Outpoint]; ok {
			utxosToSpend[utxo.Outpoint] = utxo.SpentBy
		}
	}

	if len(utxosToAdd) > 0 {
		count, err := w.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new boarding utxo(s)", count)
		}
	}
	if len(utxosToConfirm) > 0 {
		count, err := w.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("confirmed %d boarding utxo(s)", count)
		}
	}
	if len(utxosToSpend) > 0 {
		count, err := w.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d boarding utxo(s)", count)
		}
	}

	return nil
}

func (w *wallet) refreshVtxoDb(
	ctx context.Context, spendableVtxos, spentVtxos []clienttypes.Vtxo,
) error {
	// Fetch old data.
	oldSpendableVtxos, _, err := w.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableVtxoMap := make(map[clienttypes.Outpoint]clienttypes.Vtxo, 0)
	for _, v := range oldSpendableVtxos {
		oldSpendableVtxoMap[v.Outpoint] = v
	}

	vtxosToAdd := make([]clienttypes.Vtxo, 0, len(spendableVtxos))
	for _, vtxo := range spendableVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendableVtxoMap)

	if len(vtxosToAdd) > 0 {
		count, err := w.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new vtxo(s)", count)
		}
	}
	totalSpent := 0
	for arkTxid, spent := range vtxosToSpend {
		count, err := w.store.VtxoStore().SpendVtxos(ctx, spent, arkTxid)
		if err != nil {
			return err
		}
		totalSpent += count
	}
	if totalSpent > 0 {
		log.Debugf("updated %d spent vtxo(s)", totalSpent)
	}

	totalSettled := 0
	for settledBy, spent := range vtxosToSettle {
		count, err := w.store.VtxoStore().SettleVtxos(ctx, spent, settledBy)
		if err != nil {
			return err
		}
		totalSettled += count
	}
	if totalSettled > 0 {
		log.Debugf("updated %d settled vtxo(s)", totalSettled)
	}

	return nil
}

func (w *wallet) listenForArkTxs(ctx context.Context) {
	wallet := w.client.Identity()
	if wallet == nil {
		// Should be unreachable
		log.Error("failed to listen for offchain txs, wallet is nil")
		return
	}
	client := w.Client()
	if client == nil {
		// Should be unreachable
		log.Error("failed to listen for offchain txs, client is nil")
		return
	}

	eventChan, closeFunc, err := client.GetTransactionsStream(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get transaction stream")
		return
	}
	defer closeFunc()

	log.Debugf("listening for ark txs")
	for {
		select {
		case <-ctx.Done():
			log.Debugf("stopping ark tx listener")
			return
		case event, ok := <-eventChan:
			if !ok {
				continue
			}
			if errors.Is(event.Err, io.EOF) {
				closeFunc()
				return
			}

			if event.Err != nil {
				log.WithError(event.Err).Warn("received error in transaction stream")
				continue
			}

			// Drop events that raced past a shutdown — handlers below would hit
			// a closed DB or canceled context and surface noisy errors.
			if ctx.Err() != nil {
				return
			}

			mgr := w.contractManager
			if mgr == nil {
				continue
			}
			contracts, err := mgr.GetContracts(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.WithError(err).Error("failed to get contracts for ark tx listener")
				continue
			}

			myScripts := make(map[string]struct{})
			for _, contract := range contracts {
				myScripts[contract.Script] = struct{}{}
			}

			if event.CommitmentTx != nil {
				if err := w.handleCommitmentTx(ctx, myScripts, event.CommitmentTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process commitment tx")
					continue
				}
				w.scheduleNextSettlement()
			}

			if event.ArkTx != nil {
				if err := w.handleArkTx(ctx, myScripts, event.ArkTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process ark tx")
					continue
				}
				w.scheduleNextSettlement()
			}

			if event.SweepTx != nil {
				if err := w.handleSweepTx(ctx, event.SweepTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process sweep tx")
					continue
				}
			}
		}
	}
}

func (w *wallet) listenForOnchainTxs(ctx context.Context, network arklib.Network) {
	explorer := w.client.Explorer()
	if explorer == nil {
		// Should be unreachable
		log.Error("failed to listen for onchain txs, explorer is nil")
		return
	}

	boardingContracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeBoarding),
	)
	if err != nil {
		log.WithError(err).Error("failed to get contracts for boarding addresses")
		return
	}

	offchainContracts, err := w.contractManager.GetContracts(
		ctx, contract.WithType(types.ContractTypeDefault),
	)
	if err != nil {
		log.WithError(err).Error("failed to get contracts for offchain addresses")
		return
	}
	addresses := make([]string, 0, len(boardingContracts)+len(offchainContracts))

	// Listen for boarding addresses to catch "boarding" events
	for _, contract := range boardingContracts {
		addresses = append(addresses, contract.Address)
	}
	// Listen for offchain addresses to catch "unrolling" events
	for _, contract := range offchainContracts {
		addresses = append(addresses, toOnchainAddress(contract.Address, network))
	}

	if err := explorer.SubscribeForAddresses(addresses); err != nil {
		log.WithError(err).Error("failed to subscribe for onchain addresses")
		return
	}

	ch := explorer.GetAddressesEvents()

	log.Debugf("subscribed for %d addresses", len(addresses))
	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping onchain transaction listener")
			if err := explorer.UnsubscribeForAddresses(addresses); err != nil {
				log.WithError(err).Error("failed to unsubscribe for onchain addresses")
			}
			return
		case update := <-ch:
			// TODO: we may want to forward this error so the user can try to reconnect.
			if update.Error != nil {
				log.WithError(update.Error).Error("received error from explorer")
				continue
			}
			txsToAdd := make([]clienttypes.Transaction, 0)
			txsToConfirm := make([]string, 0)
			utxosToConfirm := make(map[clienttypes.Outpoint]int64)
			utxosToSpend := make(map[clienttypes.Outpoint]string)
			if len(update.NewUtxos) > 0 {
				for _, u := range update.NewUtxos {
					txsToAdd = append(txsToAdd, clienttypes.Transaction{
						TransactionKey: clienttypes.TransactionKey{
							BoardingTxid: u.Txid,
						},
						Amount:    u.Amount,
						Type:      clienttypes.TxReceived,
						CreatedAt: u.CreatedAt,
					})
				}
			}
			if len(update.ConfirmedUtxos) > 0 {
				for _, u := range update.ConfirmedUtxos {
					txsToConfirm = append(txsToConfirm, u.Txid)
					utxosToConfirm[u.Outpoint] = u.CreatedAt.Unix()
				}
			}
			if len(update.SpentUtxos) > 0 {
				for _, u := range update.SpentUtxos {
					utxosToSpend[u.Outpoint] = u.SpentBy
				}
			}

			if len(txsToAdd) > 0 {
				w.dbMu.Lock()
				count, err := w.store.TransactionStore().AddTransactions(
					ctx, txsToAdd,
				)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("added %d boarding transaction(s)", count)
				}
			}

			if len(txsToConfirm) > 0 {
				w.dbMu.Lock()
				count, err := w.store.TransactionStore().ConfirmTransactions(
					ctx, txsToConfirm, time.Now(),
				)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to update boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding transaction(s)", count)
				}
			}

			if len(update.Replacements) > 0 {
				w.dbMu.Lock()
				count, err := w.store.TransactionStore().RbfTransactions(ctx, update.Replacements)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to update rbf boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("replaced %d boarding transaction(s)", count)
				}

				for replacedTxid, replacementTxid := range update.Replacements {
					newTransaction, err := explorer.GetTxHex(replacementTxid)
					if err != nil {
						log.WithError(err).Error("failed to get boarding replacement transaction")
						continue
					}
					var tx wire.MsgTx
					if err := tx.Deserialize(
						hex.NewDecoder(strings.NewReader(newTransaction)),
					); err != nil {
						log.WithError(err).
							Error("failed to deserialize boarding replacement transaction")
						continue
					}

					utxoStore := w.store.UtxoStore()

					w.dbMu.Lock()
					storedUtxos, err := utxoStore.GetUtxosByTxid(ctx, replacedTxid)
					w.dbMu.Unlock()
					if err != nil {
						log.WithError(err).Error("failed to get stored utxos")
						continue
					}

					// Match stored UTXOs to replacement tx outputs by script
					// rather than by index. bumpfee can reorder outputs so a
					// naive index-based mapping would point to the wrong output.
					utxoReplacements := matchReplacementOutputs(
						storedUtxos, replacementTxid, &tx,
					)
					for _, r := range utxoReplacements {
						w.dbMu.Lock()
						err := utxoStore.ReplaceUtxo(ctx, r.from, r.to)
						w.dbMu.Unlock()
						if err != nil {
							log.WithError(err).Error("failed to replace boarding utxo")
						} else {
							log.Debugf(
								"replaced utxo: %v:%v with %v:%v",
								r.from.Txid, r.from.VOut, r.to.Txid, r.to.VOut,
							)
						}
					}
				}
			}

			if len(update.NewUtxos) > 0 {
				utxosToAdd := make([]clienttypes.Utxo, 0, len(update.NewUtxos))
				for _, u := range update.NewUtxos {
					contracts, err := w.contractManager.GetContracts(
						ctx, contract.WithScripts([]string{u.Script}),
					)
					if err != nil {
						log.WithError(err).Warnf("failed to get contract for utxo %s", u.Outpoint)
						continue
					}
					if len(contracts) <= 0 {
						log.Warnf("contract not found for utxo %s", u.Outpoint)
						continue
					}

					txHex, err := explorer.GetTxHex(u.Txid)
					if err != nil {
						log.WithError(err).Warnf("failed to fetch tx for utxo %s", u.Outpoint)
						continue
					}

					handler, err := w.contractManager.GetHandler(ctx, contracts[0])
					if err != nil {
						log.WithError(err).Warnf(
							"failed to get handler for utxo %s", u.Outpoint,
						)
						continue
					}

					exitDelay, err := handler.GetExitDelay(contracts[0])
					if err != nil {
						log.WithError(err).Warnf(
							"failed to get exit delay for utxo %s", u.Outpoint,
						)
						continue
					}

					tapscripts, err := handler.GetTapscripts(contracts[0])
					if err != nil {
						log.WithError(err).Warnf(
							"failed to get tapscripts for utxo %s", u.Outpoint,
						)
						continue
					}

					var spendableAt time.Time
					if !u.CreatedAt.IsZero() {
						spendableAt = u.CreatedAt.Add(
							time.Duration(exitDelay.Seconds()) * time.Second,
						)
					}

					utxosToAdd = append(utxosToAdd, clienttypes.Utxo{
						Outpoint:    u.Outpoint,
						Amount:      u.Amount,
						Script:      u.Script,
						Delay:       *exitDelay,
						Tx:          txHex,
						Tapscripts:  tapscripts,
						CreatedAt:   u.CreatedAt,
						SpendableAt: spendableAt,
					})
				}

				w.dbMu.Lock()
				count, err := w.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("added %d new boarding utxo(s)", count)
				}
			}

			if len(utxosToConfirm) > 0 {
				w.dbMu.Lock()
				count, err := w.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding utxo(s)", count)
				}
			}
			if len(utxosToSpend) > 0 {
				w.dbMu.Lock()
				count, err := w.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
				w.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to mark boarding utxos as spent")
					continue
				}
				if count > 0 {
					log.Debugf("spent %d boarding utxo(s)", count)
				}
			}
		}
	}
}

func (w *wallet) listenDbEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			time.Sleep(100 * time.Millisecond)
			if w.utxoBroadcaster != nil {
				w.utxoBroadcaster.close()
			}
			if w.vtxoBroadcaster != nil {
				w.vtxoBroadcaster.close()
			}
			if w.txBroadcaster != nil {
				w.txBroadcaster.close()
			}
			return
		case event, ok := <-w.store.UtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := w.utxoBroadcaster.publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send utxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-w.store.VtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := w.vtxoBroadcaster.publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send vtxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-w.store.TransactionStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := w.txBroadcaster.publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send utxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		}
	}
}

func (w *wallet) periodicRefreshDb(ctx context.Context) {
	if w.refreshDbInterval == 0 {
		return
	}
	ticker := time.NewTicker(w.refreshDbInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Debugf("refreshing db (last update %s)...", w.lastUpdate.Format(time.RFC3339))
			if err := w.refreshDb(ctx); err != nil {
				log.WithError(err).Error("failed to refresh db")
				continue
			}
		}
	}
}

func (w *wallet) handleCommitmentTx(
	ctx context.Context, myScripts map[string]struct{}, commitmentTx *client.TxNotification,
) error {
	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	vtxosToAdd := make([]clienttypes.Vtxo, 0)
	vtxosToSpend := make(map[clienttypes.Outpoint]string, 0)
	txsToAdd := make([]clienttypes.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range commitmentTx.SpendableVtxos {
		if _, ok := myScripts[vtxo.Script]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]clienttypes.Outpoint, 0, len(commitmentTx.SpentVtxos))
	indexedSpentVtxos := make(map[clienttypes.Outpoint]clienttypes.Vtxo)
	for _, vtxo := range commitmentTx.SpentVtxos {
		if _, ok := myScripts[vtxo.Script]; ok {
			spentVtxos = append(spentVtxos, clienttypes.Outpoint{
				Txid: vtxo.Txid,
				VOut: vtxo.VOut,
			})
			indexedSpentVtxos[vtxo.Outpoint] = vtxo
		}
	}
	myVtxos, err := w.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}

	rawTx := &wire.MsgTx{}
	reader := hex.NewDecoder(strings.NewReader(commitmentTx.Tx))
	if err := rawTx.Deserialize(reader); err != nil {
		return err
	}

	// Check if any of the claimed boarding utxos is ours.
	boardingTxids := make([]string, 0, len(rawTx.TxIn))
	for _, in := range rawTx.TxIn {
		boardingTxids = append(boardingTxids, in.PreviousOutPoint.Hash.String())
	}
	pendingBoardingTxs, err := w.store.TransactionStore().GetTransactions(
		ctx, boardingTxids,
	)
	if err != nil {
		return err
	}
	pendingBoardingTxids := make([]string, 0, len(pendingBoardingTxs))
	for _, tx := range pendingBoardingTxs {
		pendingBoardingTxids = append(pendingBoardingTxids, tx.BoardingTxid)
	}

	// Add all our pending boarding txs to the list of those to settle.
	txsToSettle = append(txsToSettle, pendingBoardingTxids...)

	// Add also our preconfirmed txs to the list of those to settle, and also add the related
	// vtxos to the list of those to mark as spent.
	for _, vtxo := range myVtxos {
		vtxosToSpend[vtxo.Outpoint] = indexedSpentVtxos[vtxo.Outpoint].ArkTxid
		if !vtxo.Preconfirmed {
			continue
		}
		txsToSettle = append(txsToSettle, vtxo.Txid)
	}

	// If no vtxos have been spent, add a new tx record.
	if len(vtxosToSpend) <= 0 {
		if len(vtxosToAdd) > 0 && len(pendingBoardingTxs) <= 0 {
			amount := uint64(0)
			for _, v := range vtxosToAdd {
				amount += v.Amount
			}
			txsToAdd = append(txsToAdd, clienttypes.Transaction{
				TransactionKey: clienttypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      clienttypes.TxReceived,
				CreatedAt: time.Now(),
				Hex:       commitmentTx.Tx,
			})
		} else {
			vtxosToAddAmount := uint64(0)
			for _, v := range vtxosToAdd {
				vtxosToAddAmount += v.Amount
			}
			settledBoardingAmount := uint64(0)
			for _, tx := range pendingBoardingTxs {
				settledBoardingAmount += tx.Amount
			}
			if vtxosToAddAmount > 0 && vtxosToAddAmount < settledBoardingAmount {
				txsToAdd = append(txsToAdd, clienttypes.Transaction{
					TransactionKey: clienttypes.TransactionKey{
						CommitmentTxid: commitmentTx.Txid,
					},
					Amount:    settledBoardingAmount - vtxosToAddAmount,
					Type:      clienttypes.TxSent,
					CreatedAt: time.Now(),
					Hex:       commitmentTx.Tx,
				})
			}
		}
	} else {
		amount := uint64(0)
		for _, v := range myVtxos {
			amount += v.Amount
		}
		for _, v := range vtxosToAdd {
			amount -= v.Amount
		}

		if amount > 0 {
			txsToAdd = append(txsToAdd, clienttypes.Transaction{
				TransactionKey: clienttypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      clienttypes.TxSent,
				CreatedAt: time.Now(),
				Hex:       commitmentTx.Tx,
			})
		}
	}

	if len(txsToAdd) > 0 {
		count, err := w.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d transaction(s)", count)
		}
	}

	if len(txsToSettle) > 0 {
		count, err := w.store.TransactionStore().
			SettleTransactions(ctx, txsToSettle, commitmentTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := w.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	if len(vtxosToSpend) > 0 {
		count, err := w.store.VtxoStore().SettleVtxos(ctx, vtxosToSpend, commitmentTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d vtxo(s)", count)
		}
	}

	return nil
}

func (w *wallet) handleArkTx(
	ctx context.Context, myScripts map[string]struct{}, arkTx *client.TxNotification,
) error {
	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	arkPtx, err := psbt.NewFromRawBytes(strings.NewReader(arkTx.Tx), true)
	if err != nil {
		return err
	}

	// ignore error since we can still handle the ark tx without the asset packet
	ext, _ := extension.NewExtensionFromTx(arkPtx.UnsignedTx)
	var assetPacket asset.Packet
	if len(ext) > 0 {
		assetPacket = ext.GetAssetPacket()
	}

	vtxosToAdd := make([]clienttypes.Vtxo, 0)
	vtxosToSpend := make(map[clienttypes.Outpoint]string)
	txsToAdd := make([]clienttypes.Transaction, 0)

	for _, vtxo := range arkTx.SpendableVtxos {
		if _, ok := myScripts[vtxo.Script]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]clienttypes.Outpoint, 0, len(arkTx.SpentVtxos))
	for _, vtxo := range arkTx.SpentVtxos {
		spentVtxos = append(spentVtxos, clienttypes.Outpoint{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := w.store.VtxoStore().GetVtxos(ctx, spentVtxos)
	if err != nil {
		return err
	}
	txsToSettle := make([]string, 0, len(vtxosToSpend))
	for _, vtxo := range myVtxos {
		vtxosToSpend[vtxo.Outpoint] = arkTx.CheckpointTxs[vtxo.Outpoint].Txid
		txsToSettle = append(txsToSettle, vtxo.Txid)
	}

	// If not spent vtxos, add a new received tx to the history.
	if len(vtxosToSpend) <= 0 {
		if len(vtxosToAdd) > 0 {
			amount := uint64(0)
			for _, v := range vtxosToAdd {
				amount += v.Amount
			}
			txsToAdd = append(txsToAdd, clienttypes.Transaction{
				TransactionKey: clienttypes.TransactionKey{
					ArkTxid: arkTx.Txid,
				},
				Amount:      amount,
				Type:        clienttypes.TxReceived,
				CreatedAt:   time.Now(),
				Hex:         arkTx.Tx,
				AssetPacket: assetPacket,
			})
		}
	} else {
		// Otherwise, add a new spent tx to the history.
		inAmount := uint64(0)
		for _, vtxo := range myVtxos {
			inAmount += vtxo.Amount
		}
		outAmount := uint64(0)
		for _, vtxo := range vtxosToAdd {
			outAmount += vtxo.Amount
		}
		txsToAdd = append(txsToAdd, clienttypes.Transaction{
			TransactionKey: clienttypes.TransactionKey{
				ArkTxid: arkTx.Txid,
			},
			Amount:      inAmount - outAmount,
			Type:        clienttypes.TxSent,
			CreatedAt:   time.Now(),
			AssetPacket: assetPacket,
			Hex:         arkTx.Tx,
		})
	}

	if len(txsToAdd) > 0 {
		count, err := w.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d transaction(s)", count)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := w.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	if len(vtxosToSpend) > 0 {
		count, err := w.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, arkTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d vtxo(s)", count)
		}

		count, err = w.store.TransactionStore().SettleTransactions(ctx, txsToSettle, "")
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}

	return nil
}

func (w *wallet) handleSweepTx(ctx context.Context, sweepTx *client.TxNotification) error {
	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	if len(sweepTx.SweptVtxos) == 0 {
		return nil
	}

	myVtxos, err := w.store.VtxoStore().GetVtxos(ctx, sweepTx.SweptVtxos)
	if err != nil {
		return err
	}

	vtxosToSweep := make([]clienttypes.Vtxo, 0, len(myVtxos))
	for _, vtxo := range myVtxos {
		if vtxo.Swept {
			continue
		}
		vtxosToSweep = append(vtxosToSweep, vtxo)
	}

	if len(vtxosToSweep) == 0 {
		return nil
	}

	count, err := w.store.VtxoStore().SweepVtxos(ctx, vtxosToSweep)
	if err != nil {
		return err
	}
	if count > 0 {
		log.Debugf("marked %d vtxo(s) as swept", count)
	}

	return nil
}

func (w *wallet) safeCheck() error {
	if w.client == nil || w.contractManager == nil {
		return ErrNotInitialized
	}
	if w.client.Identity().IsLocked() {
		return ErrIsLocked
	}

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

func (w *wallet) vtxosToTxs(
	ctx context.Context,
	spendable, spent []clienttypes.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]clienttypes.Transaction, error) {
	indexerSvc := w.client.Indexer()
	if indexerSvc == nil {
		return nil, fmt.Errorf("indexer not initialized")
	}

	txs := make([]clienttypes.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx or a collaborative exit
	vtxosLeftToCheck := append([]clienttypes.Vtxo{}, spent...)
	for _, vtxo := range append(spendable, spent...) {
		if _, ok := commitmentTxsToIgnore[vtxo.CommitmentTxids[0]]; !vtxo.Preconfirmed && ok {
			continue
		}

		settleVtxos := findVtxosSpentInSettlement(vtxosLeftToCheck, vtxo)
		settleAmount := reduceVtxosAmount(settleVtxos)
		if vtxo.Amount <= settleAmount {
			continue // settlement, ignore
		}

		spentVtxos := findVtxosSpentInPayment(vtxosLeftToCheck, vtxo)
		spentAmount := reduceVtxosAmount(spentVtxos)
		if vtxo.Amount <= spentAmount {
			continue // change, ignore
		}

		commitmentTxid := vtxo.CommitmentTxids[0]
		arkTxid := ""
		settledBy := ""
		if vtxo.Preconfirmed {
			arkTxid = vtxo.Txid
			commitmentTxid = ""
			settledBy = vtxo.SettledBy
		}

		txs = append(txs, clienttypes.Transaction{
			TransactionKey: clienttypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      clienttypes.TxReceived,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: settledBy,
		})
	}

	// Sendings

	// All spent vtxos are payments unless they are settlements of boarding utxos or refreshes

	// aggregate settled vtxos by "settledBy" (commitment txid)
	vtxosBySettledBy := make(map[string][]clienttypes.Vtxo)
	// aggregate spent vtxos by "arkTxid"
	vtxosBySpentBy := make(map[string][]clienttypes.Vtxo)
	for _, v := range spent {
		if v.SettledBy != "" {
			if _, ok := commitmentTxsToIgnore[v.SettledBy]; !ok {
				if _, ok := vtxosBySettledBy[v.SettledBy]; !ok {
					vtxosBySettledBy[v.SettledBy] = make([]clienttypes.Vtxo, 0)
				}
				vtxosBySettledBy[v.SettledBy] = append(vtxosBySettledBy[v.SettledBy], v)
				continue
			}
		}

		if len(v.ArkTxid) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]clienttypes.Vtxo, 0)
		}
		vtxosBySpentBy[v.ArkTxid] = append(vtxosBySpentBy[v.ArkTxid], v)
	}

	for sb := range vtxosBySettledBy {
		resultedVtxos := findVtxosResultedFromSettledBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		forfeitAmount := reduceVtxosAmount(vtxosBySettledBy[sb])
		// If the forfeit amount is bigger than the resulted amount, we have a collaborative exit
		if forfeitAmount > resultedAmount {
			vtxo := getVtxo(resultedVtxos, vtxosBySettledBy[sb])

			txs = append(txs, clienttypes.Transaction{
				TransactionKey: clienttypes.TransactionKey{
					CommitmentTxid: vtxo.CommitmentTxids[0],
				},
				Amount:    forfeitAmount - resultedAmount,
				Type:      clienttypes.TxSent,
				CreatedAt: vtxo.CreatedAt,
			})
		}
	}

	for sb := range vtxosBySpentBy {
		resultedVtxos := findVtxosResultedFromSpentBy(append(spendable, spent...), sb)
		resultedAmount := reduceVtxosAmount(resultedVtxos)
		spentAmount := reduceVtxosAmount(vtxosBySpentBy[sb])
		if spentAmount <= resultedAmount {
			continue // settlement, ignore
		}
		vtxo := getVtxo(resultedVtxos, vtxosBySpentBy[sb])
		if resultedAmount == 0 {
			// send all: fetch the created vtxo to source creation and expiration timestamps
			resp, err := indexerSvc.GetVtxos(
				ctx, indexer.WithOutpoints([]clienttypes.Outpoint{{Txid: sb, VOut: 0}}),
			)
			if err != nil {
				return nil, err
			}
			// Pending tx, skip
			// TODO: maybe we want to handle this somehow?
			if len(resp.Vtxos) <= 0 {
				continue
			}
			vtxo = resp.Vtxos[0]
		}

		commitmentTxid := vtxo.CommitmentTxids[0]
		arkTxid := ""
		if vtxo.Preconfirmed {
			arkTxid = vtxo.Txid
			commitmentTxid = ""
		}

		txs = append(txs, clienttypes.Transaction{
			TransactionKey: clienttypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    spentAmount - resultedAmount,
			Type:      clienttypes.TxSent,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: vtxo.SettledBy,
		})
	}

	return txs, nil
}

func (w *wallet) saveSendTransaction(
	ctx context.Context, res clientwallet.OffchainTxRes,
) error {
	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	cfg, err := w.client.GetConfigData(ctx)
	if err != nil {
		return err
	}

	contracts, err := w.contractManager.GetContracts(ctx)
	if err != nil {
		return err
	}
	myPubkeys := make(map[string]struct{}, len(contracts))
	for _, c := range contracts {
		if c.Type == types.ContractTypeBoarding {
			continue
		}
		decoded, err := arklib.DecodeAddressV0(c.Address)
		if err != nil {
			continue
		}
		myPubkeys[hex.EncodeToString(schnorr.SerializePubKey(decoded.VtxoTapKey))] = struct{}{}
	}

	arkTx, err := psbt.NewFromRawBytes(strings.NewReader(res.Tx), true)
	if err != nil {
		return fmt.Errorf("failed to parse ark tx: %w", err)
	}

	txId := arkTx.UnsignedTx.TxHash().String()

	spentVtxos := make(map[clienttypes.Outpoint]string)
	spentAmount := uint64(0)
	commitmentTxids := make(map[string]struct{}, 0)
	smallestExpiration := time.Time{}

	// mark input vtxos as spent
	for i, vtxo := range res.Inputs {
		if len(res.Checkpoints) <= i {
			return fmt.Errorf("missing signed checkpoint tx for vtxo %s", vtxo.Outpoint.String())
		}

		checkpointTx, err := psbt.NewFromRawBytes(strings.NewReader(res.Checkpoints[i]), true)
		if err != nil {
			return err
		}

		// store vtxo outpoint spent by checkpoint txid
		spentVtxos[vtxo.Outpoint] = checkpointTx.UnsignedTx.TxID()
		// Keep track of all the spent amount for the tx record to be added
		spentAmount += vtxo.Amount
		// Kepp track of all commitment txids for the new vtxos to be added
		for _, commitmentTxid := range vtxo.CommitmentTxids {
			commitmentTxids[commitmentTxid] = struct{}{}
		}

		if vtxo.ExpiresAt.IsZero() {
			continue
		}

		// Keep track of the smallest expiration for the new vtxos to be added
		if smallestExpiration.IsZero() {
			smallestExpiration = vtxo.ExpiresAt
			continue
		}

		if smallestExpiration.After(vtxo.ExpiresAt) {
			smallestExpiration = vtxo.ExpiresAt
		}
	}

	if smallestExpiration.IsZero() {
		log.Warnf("no expiration time found, skipping adding change vtxo")
		return nil
	}

	createdAt := time.Now()

	// Prepare the commitment txids for the new vtxos to be added
	commitmentTxidsList := make([]string, 0, len(commitmentTxids))
	for commitmentTxid := range commitmentTxids {
		commitmentTxidsList = append(commitmentTxidsList, commitmentTxid)
	}

	// Prepare the new vtxos to be added to DB
	newVtxos := make([]clienttypes.Vtxo, 0, len(res.Outputs))
	for _, rcv := range res.Outputs {
		// Only save change outputs that belong to us.
		addr, err := arklib.DecodeAddressV0(rcv.To)
		if err != nil {
			return err
		}
		tapkey := hex.EncodeToString(schnorr.SerializePubKey(addr.VtxoTapKey))
		if _, ok := myPubkeys[tapkey]; !ok {
			continue
		}
		// Keep track of the spent amount for the tx record to be added
		spentAmount -= rcv.Amount

		var pkScript []byte
		if rcv.Amount < cfg.Dust {
			pkScript, err = script.SubDustScript(addr.VtxoTapKey)
		} else {
			pkScript, err = addr.GetPkScript()
		}
		if err != nil {
			return err
		}

		// Find the actual PSBT output index by matching pkScript and amount against TxOut.
		vout := -1
		for i, txOut := range arkTx.UnsignedTx.TxOut {
			if bytes.Equal(txOut.PkScript, pkScript) && uint64(txOut.Value) == rcv.Amount {
				vout = i
				break
			}
		}
		if vout < 0 {
			log.Warnf("change output %s not found in ark tx, skipping", rcv.To)
			continue
		}

		// save change vtxo to DB
		newVtxos = append(newVtxos, clienttypes.Vtxo{
			Outpoint: clienttypes.Outpoint{
				Txid: txId,
				VOut: uint32(vout),
			},
			Amount:          rcv.Amount,
			Unrolled:        false,
			Spent:           false,
			Swept:           rcv.Amount < cfg.Dust, // make it recoverable if sub-dust
			Preconfirmed:    true,
			CreatedAt:       createdAt,
			ExpiresAt:       smallestExpiration,
			Script:          hex.EncodeToString(pkScript),
			CommitmentTxids: commitmentTxidsList,
			Assets:          rcv.Assets,
		})
	}

	// Add new vtxos to DB
	if len(newVtxos) > 0 {
		count, err := w.store.VtxoStore().AddVtxos(ctx, newVtxos)
		if err != nil {
			return err
		}
		log.Debugf("added %d vtxo(s)", count)
	}

	// Mark vtxos as spent in DB
	count, err := w.store.VtxoStore().SpendVtxos(ctx, spentVtxos, txId)
	if err != nil {
		return fmt.Errorf("failed to update vtxos: %s, skipping marking vtxo as spent", err)
	}
	if count > 0 {
		log.Debugf("spent %d vtxos", len(spentVtxos))
	}

	// Add sent transaction to DB
	if _, err := w.store.TransactionStore().AddTransactions(ctx, []clienttypes.Transaction{
		{
			TransactionKey: clienttypes.TransactionKey{
				ArkTxid: txId,
			},
			Amount:      spentAmount,
			Type:        clienttypes.TxSent,
			CreatedAt:   createdAt,
			Hex:         res.Tx,
			AssetPacket: res.Extension.GetAssetPacket(),
		},
	}); err != nil {
		log.Warnf("failed to add transactions: %s, skipping adding sent transaction", err)
		return nil
	}

	return nil
}

func (w *wallet) saveBatchTransaction(
	ctx context.Context, res clientwallet.BatchTxRes,
) error {
	w.dbMu.Lock()
	defer w.dbMu.Unlock()

	// 4. Add a sent tx record if the batch was a collaborative exit.
	if len(res.UtxoOutputs) > 0 {
		sentAmount := uint64(0)
		for _, vtxo := range res.VtxoInputs {
			sentAmount += vtxo.Amount
		}
		for _, vtxo := range res.VtxoOutputs {
			sentAmount -= vtxo.Amount
		}
		if sentAmount > 0 {
			if _, err := w.store.TransactionStore().AddTransactions(ctx, []clienttypes.Transaction{
				{
					TransactionKey: clienttypes.TransactionKey{
						CommitmentTxid: res.CommitmentTxid,
					},
					Amount:      sentAmount,
					Type:        clienttypes.TxSent,
					CreatedAt:   time.Now(),
					Hex:         res.CommitmentTx,
					AssetPacket: res.Extension.GetAssetPacket(),
				},
			}); err != nil {
				log.Warnf("failed to add sent transaction: %s, skipping", err)
			}
		}
	}

	// 5. Settle the pending boarding txs related to the spent utxos.
	if len(res.UtxoInputs) > 0 {
		boardingTxids := make([]string, 0, len(res.UtxoInputs))
		for _, utxo := range res.UtxoInputs {
			boardingTxids = append(boardingTxids, utxo.Txid)
		}
		pendingBoardingTxs, err := w.store.TransactionStore().GetTransactions(ctx, boardingTxids)
		if err != nil {
			return err
		}
		if len(pendingBoardingTxs) > 0 {
			pendingBoardingTxids := make([]string, 0, len(pendingBoardingTxs))
			for _, tx := range pendingBoardingTxs {
				pendingBoardingTxids = append(pendingBoardingTxids, tx.BoardingTxid)
			}
			count, err := w.store.TransactionStore().SettleTransactions(
				ctx, pendingBoardingTxids, res.CommitmentTxid,
			)
			if err != nil {
				return err
			}
			if count > 0 {
				log.Debugf("settled %d boarding transaction(s)", count)
			}
		}
	}

	// 1. Add new vtxos to the db.
	if len(res.VtxoOutputs) > 0 {
		count, err := w.store.VtxoStore().AddVtxos(ctx, res.VtxoOutputs)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	// 2. Settle the vtxos spent in the batch.
	if len(res.VtxoInputs) > 0 {
		vtxosToSettle := make(map[clienttypes.Outpoint]string, len(res.VtxoInputs))
		for _, vtxo := range res.VtxoInputs {
			vtxosToSettle[vtxo.Outpoint] = res.CommitmentTxid
		}
		count, err := w.store.VtxoStore().SettleVtxos(ctx, vtxosToSettle, res.CommitmentTxid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d vtxo(s)", count)
		}
	}

	// 3. Spend the boarding utxos spent in the batch.
	if len(res.UtxoInputs) > 0 {
		utxosToSpend := make(map[clienttypes.Outpoint]string, len(res.UtxoInputs))
		for _, utxo := range res.UtxoInputs {
			utxosToSpend[utxo.Outpoint] = res.CommitmentTxid
		}
		count, err := w.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d boarding utxo(s)", count)
		}
	}

	// 4. For note redemptions (no vtxo or utxo inputs), record a received tx.
	// handleCommitmentTx only recognises vtxos matching known contract keys, so
	// vtxos created at freshly-derived keys (e.g. the change address from
	// RedeemNotes) are never picked up there, leaving the tx store empty and
	// any listener on GetTransactionEventChannel blocked forever.
	if len(res.VtxoInputs) == 0 && len(res.UtxoInputs) == 0 && len(res.VtxoOutputs) > 0 {
		amount := uint64(0)
		for _, v := range res.VtxoOutputs {
			amount += v.Amount
		}
		if _, err := w.store.TransactionStore().AddTransactions(ctx, []clienttypes.Transaction{
			{
				TransactionKey: clienttypes.TransactionKey{
					CommitmentTxid: res.CommitmentTxid,
				},
				Amount:    amount,
				Type:      clienttypes.TxReceived,
				CreatedAt: time.Now(),
				Hex:       res.CommitmentTx,
			},
		}); err != nil {
			log.Warnf("failed to add received note transaction: %s", err)
		}
	}

	return nil
}
