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
	client "github.com/arkade-os/arkd/pkg/client-lib"
	transport "github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	clientStore "github.com/arkade-os/arkd/pkg/client-lib/store"
	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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

type arkClient struct {
	client.ArkClient

	verbose     bool
	store       types.Store
	clientStore clientTypes.Store

	syncMu *sync.Mutex
	// TODO drop the channel
	syncCh            chan error
	syncDone          bool
	syncErr           error
	syncListeners     *syncListeners
	stopFn            context.CancelFunc
	stopOnce          sync.Once
	refreshDbInterval time.Duration
	dbMu              *sync.Mutex
	logMu             *sync.Mutex
	lastUpdate        time.Time
	hdGapLimit        uint32
	onchainRegistry   *onchainAddressRegistry

	utxoBroadcaster *broadcaster[types.UtxoEvent]
	vtxoBroadcaster *broadcaster[types.VtxoEvent]
	txBroadcaster   *broadcaster[types.TransactionEvent]
}

func NewArkClient(datadir string, opts ...ClientOption) (ArkClient, error) {
	o, err := applyClientOptions(opts...)
	if err != nil {
		return nil, err
	}

	datadir = strings.TrimSpace(datadir)
	clientDbConfig := clientStore.Config{
		ConfigStoreType: clientTypes.InMemoryStore,
	}
	dbConfig := store.Config{
		AppDataStoreType: types.KVStore,
		BaseDir:          datadir,
	}
	if len(datadir) > 0 {
		clientDbConfig = clientStore.Config{
			ConfigStoreType: clientTypes.FileStore,
			BaseDir:         datadir,
		}
		dbConfig = store.Config{
			AppDataStoreType: types.SQLStore,
			BaseDir:          datadir,
		}
	}

	clientDb, err := clientStore.NewStore(clientDbConfig)
	if err != nil {
		return nil, err
	}
	db, err := store.NewStore(dbConfig)
	if err != nil {
		return nil, err
	}

	clientOpts := make([]client.ServiceOption, 0)
	if o.verbose {
		clientOpts = append(clientOpts, client.WithVerbose())
	}

	if o.wallet == nil {
		hdWallet, err := newDefaultHDWallet(datadir)
		if err != nil {
			return nil, fmt.Errorf("failed to setup wallet: %s", err)
		}
		o.wallet = hdWallet
	}
	clientOpts = append(clientOpts, client.WithWallet(o.wallet))

	cli, err := client.NewArkClient(clientDb, clientOpts...)
	if err != nil {
		return nil, err
	}

	client := &arkClient{
		ArkClient:         cli,
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
		onchainRegistry:   newOnchainAddressRegistry(),
	}

	return client, nil
}

func LoadArkClient(datadir string, opts ...ClientOption) (ArkClient, error) {
	o, err := applyClientOptions(opts...)
	if err != nil {
		return nil, err
	}

	datadir = strings.TrimSpace(datadir)
	clientDbConfig := clientStore.Config{
		ConfigStoreType: clientTypes.InMemoryStore,
	}
	dbConfig := store.Config{
		AppDataStoreType: types.KVStore,
		BaseDir:          datadir,
	}
	if len(datadir) > 0 {
		clientDbConfig = clientStore.Config{
			ConfigStoreType: clientTypes.FileStore,
			BaseDir:         datadir,
		}
		dbConfig = store.Config{
			AppDataStoreType: types.SQLStore,
			BaseDir:          datadir,
		}
	}

	clientDb, err := clientStore.NewStore(clientDbConfig)
	if err != nil {
		return nil, err
	}
	db, err := store.NewStore(dbConfig)
	if err != nil {
		return nil, err
	}

	clientOpts := make([]client.ServiceOption, 0)
	var explorerSvc explorer.Explorer
	if o.verbose {
		clientOpts = append(clientOpts, client.WithVerbose())
	}

	// Pre-create a tracking-enabled explorer from the stored config and inject it
	// so GetAddressesEvents() works correctly after Unlock. Pre-registering before
	// the sync sequence avoids the event-drop race on boarding address creation.
	cfgData, err := clientDb.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}
	if cfgData != nil {
		explorerUrl := cfgData.ExplorerURL
		if len(explorerUrl) == 0 {
			explorerUrl = defaultExplorerUrl[cfgData.Network.Name]
		}
		var pollInterval time.Duration
		if cfgData.Network.Name == arklib.BitcoinRegTest.Name {
			pollInterval = 2 * time.Second
		}
		explorerSvc, err = newExplorer(explorerUrl, cfgData.Network, true, pollInterval, "")
		if err != nil {
			return nil, fmt.Errorf("failed to init explorer: %v", err)
		}
		clientOpts = append(clientOpts, client.WithExplorer(explorerSvc))
	}

	if o.wallet == nil {
		hdWallet, err := newDefaultHDWallet(datadir)
		if err != nil {
			return nil, fmt.Errorf("failed to setup wallet: %s", err)
		}
		o.wallet = hdWallet
	}
	clientOpts = append(clientOpts, client.WithWallet(o.wallet))

	cli, err := client.LoadArkClient(clientDb, clientOpts...)
	if err != nil {
		return nil, err
	}

	client := &arkClient{
		ArkClient:         cli,
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
		onchainRegistry:   newOnchainAddressRegistry(),
	}

	return client, nil
}

func (a *arkClient) Explorer() explorer.Explorer {
	return a.ArkClient.Explorer()
}

func (a *arkClient) Indexer() indexer.Indexer {
	return a.ArkClient.Indexer()
}

func (a *arkClient) Client() transport.TransportClient {
	return a.Transport()
}

func (a *arkClient) Store() types.Store {
	return a.store
}

func (a *arkClient) GetConfigStore() clientTypes.ConfigStore {
	return a.clientStore.ConfigStore()
}

func (a *arkClient) IsSynced(ctx context.Context) <-chan types.SyncEvent {
	ch := make(chan types.SyncEvent, 1)

	a.syncMu.Lock()
	syncDone := a.syncDone
	syncErr := a.syncErr
	a.syncMu.Unlock()

	if syncDone {
		go func() {
			ch <- types.SyncEvent{
				Synced: syncErr == nil,
				Err:    syncErr,
			}
		}()
		return ch
	}

	a.syncListeners.add(ch)
	return ch
}

func (a *arkClient) Reset(ctx context.Context) {
	a.ArkClient.Reset(ctx)
	if exp := a.ArkClient.Explorer(); exp != nil {
		exp.Stop()
	}

	a.syncMu.Lock()
	a.syncDone = false
	a.syncErr = nil
	a.syncMu.Unlock()

	if a.stopFn != nil {
		a.stopFn()
	}
	if a.syncListeners != nil {
		a.syncListeners.broadcast(fmt.Errorf("wallet reset while restoring"))
		a.syncListeners.clear()
	}
	if a.store != nil {
		a.store.Clean(ctx)
	}
	a.lastUpdate = time.Time{}
}

func (a *arkClient) Stop() {
	a.stopOnce.Do(func() {
		a.ArkClient.Stop()
		a.Explorer().Stop()

		a.syncMu.Lock()
		a.syncDone = false
		a.syncErr = nil
		a.syncMu.Unlock()

		if a.stopFn != nil {
			a.stopFn()
		}
		if a.syncListeners != nil {
			a.syncListeners.broadcast(fmt.Errorf("service stopped while restoring"))
			a.syncListeners.clear()
		}

		a.store.Close()
	})
}

func (a *arkClient) GetTransactionHistory(ctx context.Context) ([]clientTypes.Transaction, error) {
	if err := a.safeCheck(); err != nil {
		return nil, err
	}

	a.dbMu.Lock()
	history, err := a.store.TransactionStore().GetAllTransactions(ctx)
	a.dbMu.Unlock()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].CreatedAt.IsZero() || history[i].CreatedAt.After(history[j].CreatedAt)
	})
	return history, nil
}

func (a *arkClient) GetTransactionEventChannel(_ context.Context) <-chan types.TransactionEvent {
	if a.txBroadcaster != nil {
		return a.txBroadcaster.subscribe(0)
	}
	return nil
}

func (a *arkClient) GetVtxoEventChannel(_ context.Context) <-chan types.VtxoEvent {
	if a.vtxoBroadcaster != nil {
		return a.vtxoBroadcaster.subscribe(0)
	}
	return nil
}

func (a *arkClient) GetUtxoEventChannel(_ context.Context) <-chan types.UtxoEvent {
	if a.utxoBroadcaster != nil {
		return a.utxoBroadcaster.subscribe(0)
	}
	return nil
}

func (a *arkClient) setRestored(err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	a.syncDone = true
	a.syncErr = err

	a.syncListeners.broadcast(err)
	a.syncListeners.clear()
}

// resetSyncStateForUnlock clears the sync flags and re-creates syncCh so the
// next Unlock cycle can publish its own sync result without colliding with
// readers (e.g. IsSynced). The mutex matches every other writer of these
// fields (Lock, Reset, setRestored).
func (a *arkClient) resetSyncStateForUnlock() {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	a.syncDone = false
	a.syncErr = nil
	a.syncCh = make(chan error)
}

func (a *arkClient) walletHasKeys(ctx context.Context) (bool, error) {
	walletSvc := a.Wallet()
	if walletSvc == nil {
		return false, ErrNotInitialized
	}

	keys, err := walletSvc.ListKeys(ctx)
	if err != nil {
		return false, err
	}

	return len(keys) > 0, nil
}

func (a *arkClient) refreshDb(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	updateTime := time.Now()
	opts := []client.ListVtxosOption{}
	if !a.lastUpdate.IsZero() {
		updateUnix := updateTime.Unix()
		lastUpdateUnix := a.lastUpdate.Unix()
		if updateUnix > lastUpdateUnix {
			opts = append(opts, client.WithTimeRange(updateUnix, lastUpdateUnix))
		}
	}

	spendableVtxos := make([]clientTypes.Vtxo, 0)
	spentVtxos := make([]clientTypes.Vtxo, 0)
	hasKeys, err := a.walletHasKeys(ctx)
	if err != nil {
		return err
	}
	if hasKeys {
		// Fetch new and spent vtxos.
		spendableVtxos, spentVtxos, err = a.ArkClient.ListVtxos(ctx, opts...)
		if err != nil {
			return err
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// Fetch new and spent utxos.
	allUtxos, err := a.getTrackedOnchainUtxos(ctx)
	if err != nil {
		return err
	}

	spendableUtxos := make([]clientTypes.Utxo, 0, len(allUtxos))
	spentUtxos := make([]clientTypes.Utxo, 0, len(allUtxos))
	commitmentTxsToIgnore := make(map[string]struct{})
	for _, utxo := range allUtxos {
		if utxo.Spent {
			spentUtxos = append(spentUtxos, utxo)
			commitmentTxsToIgnore[utxo.SpentBy] = struct{}{}
			continue
		}
		spendableUtxos = append(spendableUtxos, utxo)
	}

	// Rebuild tx history.
	unconfirmedTxs := make([]clientTypes.Transaction, 0)
	confirmedTxs := make([]clientTypes.Transaction, 0)
	for _, u := range allUtxos {
		tx := clientTypes.Transaction{
			TransactionKey: clientTypes.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      clientTypes.TxReceived,
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

	onchainHistory := append(unconfirmedTxs, confirmedTxs...)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// TODO tx packet handling ?
	offchainHistory, err := a.vtxosToTxs(ctx, spendableVtxos, spentVtxos, commitmentTxsToIgnore)
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
	if err := a.refreshTxDb(ctx, history); err != nil {
		return err
	}

	// Update utxos in db.
	if err := a.refreshUtxoDb(ctx, spendableUtxos, spentUtxos); err != nil {
		return err
	}

	// Update vtxos in db.
	if err := a.refreshVtxoDb(ctx, spendableVtxos, spentVtxos); err != nil {
		return err
	}

	a.lastUpdate = updateTime

	return nil
}

func (a *arkClient) refreshTxDb(ctx context.Context, newTxs []clientTypes.Transaction) error {
	// Fetch old data.
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return err
	}

	// Index the old data for quick lookups.
	oldTxsMap := make(map[string]clientTypes.Transaction, len(oldTxs))
	updateTxsMap := make(map[string]clientTypes.Transaction, 0)
	unconfirmedTxsMap := make(map[string]clientTypes.Transaction, 0)
	for _, tx := range oldTxs {
		if tx.CreatedAt.IsZero() {
			unconfirmedTxsMap[tx.TransactionKey.String()] = tx
		} else if tx.SettledBy == "" {
			updateTxsMap[tx.TransactionKey.String()] = tx
		}
		oldTxsMap[tx.TransactionKey.String()] = tx
	}

	txsToAdd := make([]clientTypes.Transaction, 0, len(newTxs))
	txsToSettle := make([]clientTypes.Transaction, 0, len(newTxs))
	txsToConfirm := make([]clientTypes.Transaction, 0, len(newTxs))
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
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new transaction(s)", count)
		}
	}
	if len(txsToSettle) > 0 {
		count, err := a.store.TransactionStore().UpdateTransactions(ctx, txsToSettle)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}
	if len(txsToConfirm) > 0 {
		count, err := a.store.TransactionStore().UpdateTransactions(ctx, txsToConfirm)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("confirmed %d transaction(s)", count)
		}
	}

	return nil
}

func (a *arkClient) refreshUtxoDb(
	ctx context.Context, spendableUtxos, spentUtxos []clientTypes.Utxo,
) error {
	// Fetch old data.
	oldSpendableUtxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableUtxoMap := make(map[clientTypes.Outpoint]clientTypes.Utxo, 0)
	for _, u := range oldSpendableUtxos {
		oldSpendableUtxoMap[u.Outpoint] = u
	}

	utxosToAdd := make([]clientTypes.Utxo, 0, len(spendableUtxos))
	utxosToConfirm := make(map[clientTypes.Outpoint]int64)
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
	utxosToSpend := make(map[clientTypes.Outpoint]string)
	for _, utxo := range spentUtxos {
		if _, ok := oldSpendableUtxoMap[utxo.Outpoint]; ok {
			utxosToSpend[utxo.Outpoint] = utxo.SpentBy
		}
	}

	if len(utxosToAdd) > 0 {
		count, err := a.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new boarding utxo(s)", count)
		}
	}
	if len(utxosToConfirm) > 0 {
		count, err := a.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("confirmed %d boarding utxo(s)", count)
		}
	}
	if len(utxosToSpend) > 0 {
		count, err := a.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d boarding utxo(s)", count)
		}
	}

	return nil
}

func (a *arkClient) refreshVtxoDb(
	ctx context.Context, spendableVtxos, spentVtxos []clientTypes.Vtxo,
) error {
	// Fetch old data.
	oldSpendableVtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableVtxoMap := make(map[clientTypes.Outpoint]clientTypes.Vtxo, 0)
	for _, v := range oldSpendableVtxos {
		oldSpendableVtxoMap[v.Outpoint] = v
	}

	vtxosToAdd := make([]clientTypes.Vtxo, 0, len(spendableVtxos))
	for _, vtxo := range spendableVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	vtxosToSpend, vtxosToSettle := groupSpentVtxosByTx(spentVtxos, oldSpendableVtxoMap)

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new vtxo(s)", count)
		}
	}
	totalSpent := 0
	for arkTxid, spent := range vtxosToSpend {
		count, err := a.store.VtxoStore().SpendVtxos(ctx, spent, arkTxid)
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
		count, err := a.store.VtxoStore().SettleVtxos(ctx, spent, settledBy)
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

func groupSpentVtxosByTx(
	spentVtxos []clientTypes.Vtxo,
	oldSpendableVtxoMap map[clientTypes.Outpoint]clientTypes.Vtxo,
) (
	map[string]map[clientTypes.Outpoint]string,
	map[string]map[clientTypes.Outpoint]string,
) {
	// Spent vtxos include swept and redeemed, let's make sure to update only vtxos
	// that were previously spendable.
	vtxosToSpend := make(map[string]map[clientTypes.Outpoint]string)
	vtxosToSettle := make(map[string]map[clientTypes.Outpoint]string)

	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			continue
		}

		if vtxo.SettledBy != "" {
			if _, ok := vtxosToSettle[vtxo.SettledBy]; !ok {
				vtxosToSettle[vtxo.SettledBy] = make(map[clientTypes.Outpoint]string)
			}
			vtxosToSettle[vtxo.SettledBy][vtxo.Outpoint] = vtxo.SpentBy
			continue
		}

		if _, ok := vtxosToSpend[vtxo.ArkTxid]; !ok {
			vtxosToSpend[vtxo.ArkTxid] = make(map[clientTypes.Outpoint]string)
		}
		vtxosToSpend[vtxo.ArkTxid][vtxo.Outpoint] = vtxo.SpentBy
	}

	return vtxosToSpend, vtxosToSettle
}

func (a *arkClient) listenForArkTxs(ctx context.Context) {
	wallet := a.Wallet()
	if wallet == nil {
		// Should be unreachable
		log.Error("failed to listen for offchain txs, wallet is nil")
		return
	}
	client := a.Transport()
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

			_, offchainAddrs, _, _, err := a.ArkClient.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get offchain addresses")
				continue
			}

			myPubkeys := make(map[string]struct{})
			for _, addr := range offchainAddrs {
				// nolint
				decoded, _ := arklib.DecodeAddressV0(addr.Address)
				pubkey := hex.EncodeToString(schnorr.SerializePubKey(decoded.VtxoTapKey))
				myPubkeys[pubkey] = struct{}{}
			}

			if event.CommitmentTx != nil {
				if err := a.handleCommitmentTx(ctx, myPubkeys, event.CommitmentTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process commitment tx")
					continue
				}
			}

			if event.ArkTx != nil {
				if err := a.handleArkTx(ctx, myPubkeys, event.ArkTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process ark tx")
					continue
				}
			}

			if event.SweepTx != nil {
				if err := a.handleSweepTx(ctx, event.SweepTx); err != nil {
					if ctx.Err() != nil {
						return
					}
					log.WithError(err).Error("failed to process sweep tx")
					continue
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *arkClient) listenForOnchainTxs(
	ctx context.Context,
	ch <-chan clientTypes.OnchainAddressEvent,
) {
	wallet := a.Wallet()
	if wallet == nil {
		// Should be unreachable
		log.Error("failed to listen for onchain txs, wallet is nil")
		return
	}
	explorer := a.ArkClient.Explorer()
	if explorer == nil {
		// Should be unreachable
		log.Error("failed to listen for onchain txs, explorer is nil")
		return
	}
	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		// Should be unreachable
		log.WithError(err).Error("failed to get config data")
		return
	}

	onchainAddrs, offchainAddrs, boardingAddrs, _, err := a.ArkClient.GetAddresses(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get boarding addresses")
		return
	}

	addresses := make([]string, 0, len(boardingAddrs)+len(onchainAddrs)+len(offchainAddrs))

	// we listen for boarding addresses to catch "boarding" events
	for _, addr := range boardingAddrs {
		addresses = append(addresses, addr.Address)
		if err := a.registerTrackedOnchainAddress(addr.Address, trackedAddressInfo{
			tapscripts: addr.Tapscripts,
			delay:      cfg.BoardingExitDelay, // TODO: ideally computed from tapscripts
		}, false, cfg.Network); err != nil {
			log.WithError(err).Error("failed to register boarding address")
		}
	}

	// we listen for classic P2TR addresses to catch onchain send/receive events
	for _, addr := range onchainAddrs {
		addresses = append(addresses, addr)
		if err := a.registerTrackedOnchainAddress(addr, trackedAddressInfo{
			tapscripts: []string{},                // no tapscripts for onchain address
			delay:      arklib.RelativeLocktime{}, // no delay for classic onchain address
		}, false, cfg.Network); err != nil {
			log.WithError(err).Error("failed to register onchain address")
		}
	}

	// we listen for offchain addresses to catch unrolling events
	for _, offchainAddr := range offchainAddrs {
		addr, err := toOnchainAddress(offchainAddr.Address, cfg.Network)
		if err != nil {
			log.WithError(err).Error("failed to get onchain address for offchain address")
			continue
		}

		addresses = append(addresses, addr)
		if err := a.registerTrackedOnchainAddress(addr, trackedAddressInfo{
			tapscripts: offchainAddr.Tapscripts,
			delay:      cfg.UnilateralExitDelay, // TODO: ideally computed from tapscripts
		}, false, cfg.Network); err != nil {
			log.WithError(err).Error("failed to register offchain address")
		}
	}

	for {
		if err := explorer.SubscribeForAddresses(addresses); err == nil {
			break
		} else {
			log.WithError(err).Warn("failed to subscribe for onchain addresses, retrying...")
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}

	log.Debugf("subscribed for %d addresses", len(addresses))
	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping onchain transaction listener")
			if err := explorer.UnsubscribeForAddresses(a.trackedOnchainAddresses()); err != nil {
				log.WithError(err).Error("failed to unsubscribe for onchain addresses")
			}
			return
		case update := <-ch:
			// TODO: we may want to forward this error so the user can try to reconnect.
			if update.Error != nil {
				log.WithError(update.Error).Error("received error from explorer")
				continue
			}
			txsToAdd := make([]clientTypes.Transaction, 0)
			txsToConfirm := make([]string, 0)
			utxosToConfirm := make(map[clientTypes.Outpoint]int64)
			utxosToSpend := make(map[clientTypes.Outpoint]string)
			if len(update.NewUtxos) > 0 {
				for _, u := range update.NewUtxos {
					_, ok := a.lookupTrackedAddressByScript(u.Script)
					if !ok {
						log.WithField("script", u.Script).
							WithField("outpoint", u.Outpoint).
							Error("failed to find address for new tx")
						continue
					}

					txsToAdd = append(txsToAdd, clientTypes.Transaction{
						TransactionKey: clientTypes.TransactionKey{BoardingTxid: u.Txid},
						Amount:         u.Amount,
						Type:           clientTypes.TxReceived,
						CreatedAt:      u.CreatedAt,
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
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().AddTransactions(
					ctx, txsToAdd,
				)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("added %d boarding transaction(s)", count)
				}
			}

			if len(txsToConfirm) > 0 {
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().ConfirmTransactions(
					ctx, txsToConfirm, time.Now(),
				)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to update boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding transaction(s)", count)
				}
			}

			if len(update.Replacements) > 0 {
				a.dbMu.Lock()
				count, err := a.store.TransactionStore().RbfTransactions(ctx, update.Replacements)
				a.dbMu.Unlock()
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

					utxoStore := a.store.UtxoStore()

					a.dbMu.Lock()
					storedUtxos, err := utxoStore.GetUtxosByTxid(ctx, replacedTxid)
					a.dbMu.Unlock()
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
						a.dbMu.Lock()
						err := utxoStore.ReplaceUtxo(ctx, r.from, r.to)
						a.dbMu.Unlock()
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
				utxosToAdd := make([]clientTypes.Utxo, 0, len(update.NewUtxos))
				for _, u := range update.NewUtxos {
					address, ok := a.lookupTrackedAddressByScript(u.Script)
					if !ok {
						log.WithField("script", u.Script).
							WithField("outpoint", u.Outpoint).
							Error("failed to find address for new utxo")
						continue
					}

					txHex, err := explorer.GetTxHex(u.Txid)
					if err != nil {
						log.WithField("txid", u.Txid).
							WithError(err).
							Error("failed to get boarding utxo transaction")
						continue
					}

					var spendableAt time.Time
					if !u.CreatedAt.IsZero() {
						spendableAt = u.CreatedAt.Add(
							time.Duration(address.delay.Seconds()) * time.Second,
						)
					}

					utxosToAdd = append(utxosToAdd, clientTypes.Utxo{
						Outpoint:    u.Outpoint,
						Amount:      u.Amount,
						Script:      u.Script,
						Delay:       address.delay,
						Spent:       false,
						SpentBy:     "",
						Tx:          txHex,
						Tapscripts:  address.tapscripts,
						CreatedAt:   u.CreatedAt,
						SpendableAt: spendableAt,
					})
				}

				a.dbMu.Lock()
				count, err := a.store.UtxoStore().AddUtxos(ctx, utxosToAdd)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("added %d new boarding utxo(s)", count)
				}
			}

			if len(utxosToConfirm) > 0 {
				a.dbMu.Lock()
				count, err := a.store.UtxoStore().ConfirmUtxos(ctx, utxosToConfirm)
				a.dbMu.Unlock()
				if err != nil {
					log.WithError(err).Error("failed to add new boarding utxos")
					continue
				}
				if count > 0 {
					log.Debugf("confirmed %d boarding utxo(s)", count)
				}
			}
			if len(utxosToSpend) > 0 {
				a.dbMu.Lock()
				count, err := a.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
				a.dbMu.Unlock()
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

func (a *arkClient) listenDbEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			time.Sleep(100 * time.Millisecond)
			if a.utxoBroadcaster != nil {
				a.utxoBroadcaster.close()
			}
			if a.vtxoBroadcaster != nil {
				a.vtxoBroadcaster.close()
			}
			if a.txBroadcaster != nil {
				a.txBroadcaster.close()
			}
			return
		case event, ok := <-a.store.UtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.utxoBroadcaster.publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send utxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-a.store.VtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.vtxoBroadcaster.publish(event)
				if closedListeners > 0 {
					log.Warnf(
						"failed to send vtxo event to %d listeners and they've been removed",
						closedListeners,
					)
				}
			}()
		case event, ok := <-a.store.TransactionStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.txBroadcaster.publish(event)
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

func (a *arkClient) periodicRefreshDb(ctx context.Context) {
	if a.refreshDbInterval == 0 {
		return
	}
	ticker := time.NewTicker(a.refreshDbInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Debugf("refreshing db (last update %s)...", a.lastUpdate.Format(time.RFC3339))
			if err := a.refreshDb(ctx); err != nil {
				log.WithError(err).Error("failed to refresh db")
				continue
			}
		}
	}
}

func (a *arkClient) handleCommitmentTx(
	ctx context.Context, myPubkeys map[string]struct{}, commitmentTx *transport.TxNotification,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxosToAdd := make([]clientTypes.Vtxo, 0)
	vtxosToSpend := make(map[clientTypes.Outpoint]string, 0)
	txsToAdd := make([]clientTypes.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range commitmentTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]clientTypes.Outpoint, 0, len(commitmentTx.SpentVtxos))
	indexedSpentVtxos := make(map[clientTypes.Outpoint]clientTypes.Vtxo)
	for _, vtxo := range commitmentTx.SpentVtxos {
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			spentVtxos = append(spentVtxos, clientTypes.Outpoint{
				Txid: vtxo.Txid,
				VOut: vtxo.VOut,
			})
			indexedSpentVtxos[vtxo.Outpoint] = vtxo
		}
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
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
	pendingBoardingTxs, err := a.store.TransactionStore().GetTransactions(
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
			txsToAdd = append(txsToAdd, clientTypes.Transaction{
				TransactionKey: clientTypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      clientTypes.TxReceived,
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
				txsToAdd = append(txsToAdd, clientTypes.Transaction{
					TransactionKey: clientTypes.TransactionKey{
						CommitmentTxid: commitmentTx.Txid,
					},
					Amount:    settledBoardingAmount - vtxosToAddAmount,
					Type:      clientTypes.TxSent,
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
			txsToAdd = append(txsToAdd, clientTypes.Transaction{
				TransactionKey: clientTypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      clientTypes.TxSent,
				CreatedAt: time.Now(),
				Hex:       commitmentTx.Tx,
			})
		}
	}

	if len(txsToAdd) > 0 {
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d transaction(s)", count)
		}
	}

	if len(txsToSettle) > 0 {
		count, err := a.store.TransactionStore().
			SettleTransactions(ctx, txsToSettle, commitmentTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	if len(vtxosToSpend) > 0 {
		count, err := a.store.VtxoStore().SettleVtxos(ctx, vtxosToSpend, commitmentTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d vtxo(s)", count)
		}
	}

	return nil
}

func (a *arkClient) handleArkTx(
	ctx context.Context, myPubkeys map[string]struct{}, arkTx *transport.TxNotification,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

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

	vtxosToAdd := make([]clientTypes.Vtxo, 0)
	vtxosToSpend := make(map[clientTypes.Outpoint]string)
	txsToAdd := make([]clientTypes.Transaction, 0)

	for _, vtxo := range arkTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]clientTypes.Outpoint, 0, len(arkTx.SpentVtxos))
	for _, vtxo := range arkTx.SpentVtxos {
		spentVtxos = append(spentVtxos, clientTypes.Outpoint{
			Txid: vtxo.Txid,
			VOut: vtxo.VOut,
		})
	}
	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, spentVtxos)
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
			txsToAdd = append(txsToAdd, clientTypes.Transaction{
				TransactionKey: clientTypes.TransactionKey{
					ArkTxid: arkTx.Txid,
				},
				Amount:      amount,
				Type:        clientTypes.TxReceived,
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
		txsToAdd = append(txsToAdd, clientTypes.Transaction{
			TransactionKey: clientTypes.TransactionKey{
				ArkTxid: arkTx.Txid,
			},
			Amount:      inAmount - outAmount,
			Type:        clientTypes.TxSent,
			CreatedAt:   time.Now(),
			AssetPacket: assetPacket,
			Hex:         arkTx.Tx,
		})
	}

	if len(txsToAdd) > 0 {
		count, err := a.store.TransactionStore().AddTransactions(ctx, txsToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d transaction(s)", count)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	if len(vtxosToSpend) > 0 {
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, arkTx.Txid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d vtxo(s)", count)
		}

		count, err = a.store.TransactionStore().SettleTransactions(ctx, txsToSettle, "")
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d transaction(s)", count)
		}
	}

	return nil
}

func (a *arkClient) handleSweepTx(ctx context.Context, sweepTx *transport.TxNotification) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	if len(sweepTx.SweptVtxos) == 0 {
		return nil
	}

	myVtxos, err := a.store.VtxoStore().GetVtxos(ctx, sweepTx.SweptVtxos)
	if err != nil {
		return err
	}

	vtxosToSweep := make([]clientTypes.Vtxo, 0, len(myVtxos))
	for _, vtxo := range myVtxos {
		if vtxo.Swept {
			continue
		}
		vtxosToSweep = append(vtxosToSweep, vtxo)
	}

	if len(vtxosToSweep) == 0 {
		return nil
	}

	count, err := a.store.VtxoStore().SweepVtxos(ctx, vtxosToSweep)
	if err != nil {
		return err
	}
	if count > 0 {
		log.Debugf("marked %d vtxo(s) as swept", count)
	}

	return nil
}

func (a *arkClient) safeCheck() error {
	if a.Wallet() == nil {
		return ErrNotInitialized
	}
	if a.Wallet().IsLocked() {
		return ErrIsLocked
	}

	a.syncMu.Lock()
	syncDone := a.syncDone
	syncErr := a.syncErr
	a.syncMu.Unlock()
	if !syncDone {
		if syncErr != nil {
			return fmt.Errorf("failed to restore wallet: %s", syncErr)
		}
		return ErrIsSyncing
	}
	return nil
}

func (a *arkClient) getTrackedOnchainUtxos(ctx context.Context) ([]clientTypes.Utxo, error) {
	wallet := a.Wallet()
	if wallet == nil {
		return nil, ErrNotInitialized
	}
	explorer := a.ArkClient.Explorer()
	if explorer == nil {
		return nil, fmt.Errorf("explorer not initialized")
	}

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	onchainAddrs, _, boardingAddrs, redemptionAddrs, err := a.ArkClient.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := []clientTypes.Utxo{}
	for _, addr := range onchainAddrs {
		onchainUtxos, err := a.addressTxHistoryToUtxos(
			addr, nil, arklib.RelativeLocktime{}, explorer,
		)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, onchainUtxos...)
	}

	for _, addr := range boardingAddrs {
		boardingUtxos, err := a.addressTxHistoryToUtxos(
			addr.Address, addr.Tapscripts, cfg.BoardingExitDelay, explorer,
		)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, boardingUtxos...)
	}

	for _, addr := range redemptionAddrs {
		redemptionUtxos, err := a.addressTxHistoryToUtxos(
			addr.Address, addr.Tapscripts, cfg.UnilateralExitDelay, explorer,
		)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, redemptionUtxos...)
	}

	return utxos, nil
}

func (a *arkClient) addressTxHistoryToUtxos(
	address string,
	tapscripts []string,
	delay arklib.RelativeLocktime,
	explorerSvc explorer.Explorer,
) ([]clientTypes.Utxo, error) {
	txs, err := explorerSvc.GetTxs(address)
	if err != nil {
		return nil, err
	}

	utxos := make([]clientTypes.Utxo, 0)
	for _, tx := range txs {
		txHex, err := explorerSvc.GetTxHex(tx.Txid)
		if err != nil {
			return nil, err
		}

		spentStatuses, err := explorerSvc.GetTxOutspends(tx.Txid)
		if err != nil {
			return nil, err
		}

		for i, vout := range tx.Vout {
			if vout.Address != address {
				continue
			}

			explorerUtxo := explorer.Utxo{
				Txid:   tx.Txid,
				Vout:   uint32(i),
				Amount: vout.Amount,
				Script: vout.Script,
				Status: tx.Status,
			}

			utxo := explorerUtxo.ToUtxo(delay, tapscripts)
			utxo.Script = vout.Script
			utxo.Tx = txHex

			if len(spentStatuses) > i {
				utxo.Spent = spentStatuses[i].Spent
				utxo.SpentBy = spentStatuses[i].SpentBy
			}

			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

func (i *arkClient) vtxosToTxs(
	ctx context.Context,
	spendable, spent []clientTypes.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]clientTypes.Transaction, error) {
	indexerSvc := i.ArkClient.Indexer()
	if indexerSvc == nil {
		return nil, fmt.Errorf("indexer not initialized")
	}

	txs := make([]clientTypes.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx or a collaborative exit
	vtxosLeftToCheck := append([]clientTypes.Vtxo{}, spent...)
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

		txs = append(txs, clientTypes.Transaction{
			TransactionKey: clientTypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      clientTypes.TxReceived,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: settledBy,
		})
	}

	// Sendings

	// All spent vtxos are payments unless they are settlements of boarding utxos or refreshes

	// aggregate settled vtxos by "settledBy" (commitment txid)
	vtxosBySettledBy := make(map[string][]clientTypes.Vtxo)
	// aggregate spent vtxos by "arkTxid"
	vtxosBySpentBy := make(map[string][]clientTypes.Vtxo)
	for _, v := range spent {
		if v.SettledBy != "" {
			if _, ok := commitmentTxsToIgnore[v.SettledBy]; !ok {
				if _, ok := vtxosBySettledBy[v.SettledBy]; !ok {
					vtxosBySettledBy[v.SettledBy] = make([]clientTypes.Vtxo, 0)
				}
				vtxosBySettledBy[v.SettledBy] = append(vtxosBySettledBy[v.SettledBy], v)
				continue
			}
		}

		if len(v.ArkTxid) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]clientTypes.Vtxo, 0)
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

			txs = append(txs, clientTypes.Transaction{
				TransactionKey: clientTypes.TransactionKey{
					CommitmentTxid: vtxo.CommitmentTxids[0],
				},
				Amount:    forfeitAmount - resultedAmount,
				Type:      clientTypes.TxSent,
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
				ctx, indexer.WithOutpoints([]clientTypes.Outpoint{{Txid: sb, VOut: 0}}),
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

		txs = append(txs, clientTypes.Transaction{
			TransactionKey: clientTypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    spentAmount - resultedAmount,
			Type:      clientTypes.TxSent,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: vtxo.SettledBy,
		})
	}

	return txs, nil
}

func (a *arkClient) saveSendTransaction(
	ctx context.Context, res client.OffchainTxRes,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	cfg, err := a.GetConfigData(ctx)
	if err != nil {
		return err
	}

	_, offchainAddrs, _, _, err := a.ArkClient.GetAddresses(ctx)
	if err != nil {
		return err
	}
	myPubkeys := make(map[string]struct{}, len(offchainAddrs))
	for _, addr := range offchainAddrs {
		decoded, err := arklib.DecodeAddressV0(addr.Address)
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

	spentVtxos := make(map[clientTypes.Outpoint]string)
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
	newVtxos := make([]clientTypes.Vtxo, 0, len(res.Outputs))
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
		newVtxos = append(newVtxos, clientTypes.Vtxo{
			Outpoint: clientTypes.Outpoint{
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
		count, err := a.store.VtxoStore().AddVtxos(ctx, newVtxos)
		if err != nil {
			return err
		}
		log.Debugf("added %d vtxo(s)", count)
	}

	// Mark vtxos as spent in DB
	count, err := a.store.VtxoStore().SpendVtxos(ctx, spentVtxos, txId)
	if err != nil {
		return fmt.Errorf("failed to update vtxos: %s, skipping marking vtxo as spent", err)
	}
	if count > 0 {
		log.Debugf("spent %d vtxos", len(spentVtxos))
	}

	// Add sent transaction to DB
	if _, err := a.store.TransactionStore().AddTransactions(ctx, []clientTypes.Transaction{
		{
			TransactionKey: clientTypes.TransactionKey{
				ArkTxid: txId,
			},
			Amount:      spentAmount,
			Type:        clientTypes.TxSent,
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

func (a *arkClient) saveBatchTransaction(
	ctx context.Context, res client.BatchTxRes,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

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
			if _, err := a.store.TransactionStore().AddTransactions(ctx, []clientTypes.Transaction{
				{
					TransactionKey: clientTypes.TransactionKey{
						CommitmentTxid: res.CommitmentTxid,
					},
					Amount:      sentAmount,
					Type:        clientTypes.TxSent,
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
		pendingBoardingTxs, err := a.store.TransactionStore().GetTransactions(ctx, boardingTxids)
		if err != nil {
			return err
		}
		if len(pendingBoardingTxs) > 0 {
			pendingBoardingTxids := make([]string, 0, len(pendingBoardingTxs))
			for _, tx := range pendingBoardingTxs {
				pendingBoardingTxids = append(pendingBoardingTxids, tx.BoardingTxid)
			}
			count, err := a.store.TransactionStore().SettleTransactions(
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
		count, err := a.store.VtxoStore().AddVtxos(ctx, res.VtxoOutputs)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d vtxo(s)", count)
		}
	}

	// 2. Settle the vtxos spent in the batch.
	if len(res.VtxoInputs) > 0 {
		vtxosToSettle := make(map[clientTypes.Outpoint]string, len(res.VtxoInputs))
		for _, vtxo := range res.VtxoInputs {
			vtxosToSettle[vtxo.Outpoint] = res.CommitmentTxid
		}
		count, err := a.store.VtxoStore().SettleVtxos(ctx, vtxosToSettle, res.CommitmentTxid)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("settled %d vtxo(s)", count)
		}
	}

	// 3. Spend the boarding utxos spent in the batch.
	if len(res.UtxoInputs) > 0 {
		utxosToSpend := make(map[clientTypes.Outpoint]string, len(res.UtxoInputs))
		for _, utxo := range res.UtxoInputs {
			utxosToSpend[utxo.Outpoint] = res.CommitmentTxid
		}
		count, err := a.store.UtxoStore().SpendUtxos(ctx, utxosToSpend)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("spent %d boarding utxo(s)", count)
		}
	}

	return nil
}

type trackedAddressInfo struct {
	tapscripts []string
	delay      arklib.RelativeLocktime
}

type onchainAddressRegistry struct {
	mu              sync.RWMutex
	addresses       map[string]struct{}
	addressByScript map[string]trackedAddressInfo
}

func newOnchainAddressRegistry() *onchainAddressRegistry {
	return &onchainAddressRegistry{
		addresses:       make(map[string]struct{}),
		addressByScript: make(map[string]trackedAddressInfo),
	}
}

func (a *arkClient) registerTrackedOnchainAddress(
	address string,
	info trackedAddressInfo,
	subscribe bool,
	network arklib.Network,
) error {
	script, err := toOutputScript(address, network)
	if err != nil {
		return err
	}

	scriptHex := hex.EncodeToString(script)

	a.onchainRegistry.mu.Lock()
	_, alreadyTracked := a.onchainRegistry.addresses[address]
	a.onchainRegistry.addresses[address] = struct{}{}
	a.onchainRegistry.addressByScript[scriptHex] = info
	a.onchainRegistry.mu.Unlock()

	if subscribe && !alreadyTracked {
		if err := a.Explorer().SubscribeForAddresses([]string{address}); err != nil {
			return err
		}
	}

	return nil
}

func (a *arkClient) trackedOnchainAddresses() []string {
	a.onchainRegistry.mu.RLock()
	defer a.onchainRegistry.mu.RUnlock()

	addresses := make([]string, 0, len(a.onchainRegistry.addresses))
	for address := range a.onchainRegistry.addresses {
		addresses = append(addresses, address)
	}
	return addresses
}

func (a *arkClient) lookupTrackedAddressByScript(script string) (trackedAddressInfo, bool) {
	a.onchainRegistry.mu.RLock()
	defer a.onchainRegistry.mu.RUnlock()

	info, ok := a.onchainRegistry.addressByScript[script]
	return info, ok
}

// utxoReplacement represents a mapping from an old UTXO outpoint to its
// replacement outpoint after an RBF (Replace-By-Fee) transaction.
type utxoReplacement struct {
	from clientTypes.Outpoint
	to   clientTypes.Outpoint
}

// matchReplacementOutputs maps stored UTXOs from a replaced transaction to the
// corresponding outputs in the replacement transaction by matching on script
// (pkScript). This correctly handles cases where Bitcoin Core's bumpfee
// reorders outputs, which would break a naive index-based mapping.
func matchReplacementOutputs(
	storedUtxos []clientTypes.Utxo,
	replacementTxid string,
	replacementTx *wire.MsgTx,
) []utxoReplacement {
	replacements := make([]utxoReplacement, 0, len(storedUtxos))
	// Track which new outputs have been matched to avoid double-mapping.
	matched := make(map[uint32]bool)

	for _, stored := range storedUtxos {
		for newIdx, txOut := range replacementTx.TxOut {
			if matched[uint32(newIdx)] {
				continue
			}
			if hex.EncodeToString(txOut.PkScript) == stored.Script {
				replacements = append(replacements, utxoReplacement{
					from: stored.Outpoint,
					to: clientTypes.Outpoint{
						Txid: replacementTxid,
						VOut: uint32(newIdx),
					},
				})
				matched[uint32(newIdx)] = true
				break
			}
		}
	}
	return replacements
}
