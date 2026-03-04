package arksdk

import (
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
	client "github.com/arkade-os/arkd/pkg/client-lib"
	transport "github.com/arkade-os/arkd/pkg/client-lib/client"
	explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer"
	mempool_explorer "github.com/arkade-os/arkd/pkg/client-lib/explorer/mempool"
	sdkstore "github.com/arkade-os/arkd/pkg/client-lib/store"
	sdktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/internal/utils"
	"github.com/arkade-os/go-sdk/store"
	"github.com/arkade-os/go-sdk/types"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
)

type ServiceOption func(*newArkClient)

func WithVerboseN() ServiceOption {
	return func(c *newArkClient) {
		c.verbose = true
	}
}

type newArkClient struct {
	client.ArkClient

	verbose  bool
	store    types.Store
	explorer explorer.Explorer

	syncMu *sync.Mutex
	// TODO drop the channel
	syncCh            chan error
	syncDone          bool
	syncErr           error
	syncListeners     *syncListeners
	stopFn            context.CancelFunc
	refreshDbInterval time.Duration
	dbMu              *sync.Mutex

	utxoBroadcaster *utils.Broadcaster[sdktypes.UtxoEvent]
	vtxoBroadcaster *utils.Broadcaster[sdktypes.VtxoEvent]
	txBroadcaster   *utils.Broadcaster[sdktypes.TransactionEvent]
}

func NewNewArkClient(datadir string, verbose bool) (client.ArkClient, error) {
	configStore, err := sdkstore.NewStore(sdkstore.Config{
		ConfigStoreType: sdktypes.FileStore,
		BaseDir:         datadir,
	})
	if err != nil {
		return nil, err
	}

	clientOpts := make([]client.ServiceOption, 0)
	if verbose {
		clientOpts = append(clientOpts, client.WithVerbose())
	}

	db, err := store.NewStore(store.Config{
		AppDataStoreType: types.SQLStore,
		BaseDir:          datadir,
	})

	cli, err := client.NewArkClient(configStore, clientOpts...)
	if err != nil {
		return nil, err
	}

	client := &newArkClient{
		ArkClient: cli,
		verbose:   verbose,
		store:     db,
		syncMu:    &sync.Mutex{},
	}

	syncListeners := newReadyListeners()

	client.syncListeners = syncListeners

	return client, nil
}

func LoadNewArkClient(datadir string, verbose bool) (client.ArkClient, error) {
	configStore, err := sdkstore.NewStore(sdkstore.Config{
		ConfigStoreType: sdktypes.FileStore,
		BaseDir:         datadir,
	})
	if err != nil {
		return nil, err
	}

	db, err := store.NewStore(store.Config{
		AppDataStoreType: types.SQLStore,
		BaseDir:          datadir,
	})

	clientOpts := make([]client.ServiceOption, 0)
	if verbose {
		clientOpts = append(clientOpts, client.WithVerbose())
	}

	data, err := configStore.ConfigStore().GetData(context.Background())
	if err != nil {
		return nil, err
	}

	explorerSvc, err := mempool_explorer.NewExplorer(data.ExplorerURL, data.Network)
	if err != nil {
		return nil, err
	}

	clientOpts = append(clientOpts, client.WithExplorer(explorerSvc))

	cli, err := client.LoadArkClient(configStore, clientOpts...)
	if err != nil {
		return nil, err
	}

	client := &newArkClient{
		ArkClient: cli,
		store:     db,
		syncMu:    &sync.Mutex{},
		explorer:  explorerSvc,
	}

	syncListeners := newReadyListeners()

	client.syncListeners = syncListeners

	return client, nil
}

func (a *newArkClient) Init(ctx context.Context, args client.InitArgs) error {
	return a.ArkClient.Init(ctx, args)
}

func (a *newArkClient) Unlock(ctx context.Context, password string) error {
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
	a.utxoBroadcaster = utils.NewBroadcaster[sdktypes.UtxoEvent]()
	a.vtxoBroadcaster = utils.NewBroadcaster[sdktypes.VtxoEvent]()
	a.txBroadcaster = utils.NewBroadcaster[sdktypes.TransactionEvent]()

	go func() {
		err := <-a.syncCh
		a.setRestored(err)
	}()

	bgCtx, cancel := context.WithCancel(context.Background())
	a.stopFn = cancel

	go func() {
		a.explorer.Start()

		ctx := bgCtx

		err := func() error {
			if err := a.refreshDb(ctx); err != nil {
				return err
			}

			return nil
		}()
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

func (a *newArkClient) setRestored(err error) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()

	a.syncDone = true
	a.syncErr = err

	a.syncListeners.broadcast(err)
	a.syncListeners.clear()
}

func (a *newArkClient) refreshDb(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	// Fetch new and spent vtxos.
	spendableVtxos, spentVtxos, err := a.ArkClient.ListVtxos(ctx)
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// Fetch new and spent utxos.
	allUtxos, err := a.getAllBoardingUtxos(ctx)
	if err != nil {
		return err
	}

	spendableUtxos := make([]sdktypes.Utxo, 0, len(allUtxos))
	spentUtxos := make([]sdktypes.Utxo, 0, len(allUtxos))
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
	unconfirmedTxs := make([]sdktypes.Transaction, 0)
	confirmedTxs := make([]sdktypes.Transaction, 0)
	for _, u := range allUtxos {
		tx := sdktypes.Transaction{
			TransactionKey: sdktypes.TransactionKey{
				BoardingTxid: u.Txid,
			},
			Amount:    u.Amount,
			Type:      sdktypes.TxReceived,
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
	return a.refreshVtxoDb(ctx, spendableVtxos, spentVtxos)
}

func (a *newArkClient) refreshTxDb(ctx context.Context, newTxs []sdktypes.Transaction) error {
	// Fetch old data.
	oldTxs, err := a.store.TransactionStore().GetAllTransactions(ctx)
	if err != nil {
		return err
	}

	// Index the old data for quick lookups.
	oldTxsMap := make(map[string]sdktypes.Transaction, len(oldTxs))
	updateTxsMap := make(map[string]sdktypes.Transaction, 0)
	unconfirmedTxsMap := make(map[string]sdktypes.Transaction, 0)
	for _, tx := range oldTxs {
		if tx.CreatedAt.IsZero() {
			unconfirmedTxsMap[tx.TransactionKey.String()] = tx
		} else if tx.SettledBy == "" {
			updateTxsMap[tx.TransactionKey.String()] = tx
		}
		oldTxsMap[tx.TransactionKey.String()] = tx
	}

	txsToAdd := make([]sdktypes.Transaction, 0, len(newTxs))
	txsToSettle := make([]sdktypes.Transaction, 0, len(newTxs))
	txsToConfirm := make([]sdktypes.Transaction, 0, len(newTxs))
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

func (a *newArkClient) refreshUtxoDb(
	ctx context.Context, spendableUtxos, spentUtxos []sdktypes.Utxo,
) error {
	// Fetch old data.
	oldSpendableUtxos, _, err := a.store.UtxoStore().GetAllUtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableUtxoMap := make(map[sdktypes.Outpoint]sdktypes.Utxo, 0)
	for _, u := range oldSpendableUtxos {
		oldSpendableUtxoMap[u.Outpoint] = u
	}

	utxosToAdd := make([]sdktypes.Utxo, 0, len(spendableUtxos))
	utxosToConfirm := make(map[sdktypes.Outpoint]int64)
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
	utxosToSpend := make(map[sdktypes.Outpoint]string)
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

func (a *newArkClient) refreshVtxoDb(
	ctx context.Context, spendableVtxos, spentVtxos []sdktypes.Vtxo,
) error {
	// Fetch old data.
	oldSpendableVtxos, _, err := a.store.VtxoStore().GetAllVtxos(ctx)
	if err != nil {
		return err
	}

	// Index old data for quick lookups.
	oldSpendableVtxoMap := make(map[sdktypes.Outpoint]sdktypes.Vtxo, 0)
	for _, v := range oldSpendableVtxos {
		oldSpendableVtxoMap[v.Outpoint] = v
	}

	vtxosToAdd := make([]sdktypes.Vtxo, 0, len(spendableVtxos))
	for _, vtxo := range spendableVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; !ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Spent vtxos include swept and redeemed, let's make sure to update any vtxo that was
	// previously spendable.
	vtxosToUpdate := make([]sdktypes.Vtxo, 0, len(spentVtxos))
	for _, vtxo := range spentVtxos {
		if _, ok := oldSpendableVtxoMap[vtxo.Outpoint]; ok {
			vtxosToUpdate = append(vtxosToUpdate, vtxo)
		}
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("added %d new vtxo(s)", count)
		}
	}
	if len(vtxosToUpdate) > 0 {
		count, err := a.store.VtxoStore().UpdateVtxos(ctx, vtxosToUpdate)
		if err != nil {
			return err
		}
		if count > 0 {
			log.Debugf("updated %d vtxo(s)", count)
		}
	}

	return nil
}

func (a *newArkClient) listenForArkTxs(ctx context.Context) {
	wallet := a.ArkClient.Wallet()
	if wallet == nil {
		// Should be unreachable
		log.Error("failed to listen for offchain txs, wallet is nil")
		return
	}
	client := a.ArkClient.Client()
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

			_, offchainAddrs, _, _, err := wallet.GetAddresses(ctx)
			if err != nil {
				log.WithError(err).Error("failed to get offchain addresses")
				continue
			}

			myPubkeys := make(map[string]struct{})
			for _, addr := range offchainAddrs {
				// nolint
				decoded, _ := arklib.DecodeAddressV0(addr.Address)
				myPubkeys[hex.EncodeToString(schnorr.SerializePubKey(decoded.VtxoTapKey))] = struct{}{}
			}

			if event.CommitmentTx != nil {
				if err := a.handleCommitmentTx(ctx, myPubkeys, event.CommitmentTx); err != nil {
					log.WithError(err).Error("failed to process commitment tx")
					continue
				}
			}

			if event.ArkTx != nil {
				if err := a.handleArkTx(ctx, myPubkeys, event.ArkTx); err != nil {
					log.WithError(err).Error("failed to process ark tx")
					continue
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func (a *newArkClient) listenForOnchainTxs(ctx context.Context) {
	wallet := a.ArkClient.Wallet()
	if wallet == nil {
		// Should be unreachable
		log.Error("failed to listen for onchain txs, wallet is nil")
		return
	}
	cfg, err := a.ArkClient.GetConfigData(ctx)
	if err != nil {
		// Should be unreachable
		log.WithError(err).Error("failed to get config data")
		return
	}

	onchainAddrs, offchainAddrs, boardingAddrs, _, err := wallet.GetAddresses(ctx)
	if err != nil {
		log.WithError(err).Error("failed to get boarding addresses")
		return
	}

	addresses := make([]string, 0, len(boardingAddrs)+len(onchainAddrs)+len(offchainAddrs))
	type addressInfo struct {
		tapscripts []string
		delay      arklib.RelativeLocktime
	}
	addressByScript := make(map[string]addressInfo, 0)

	// we listen for boarding addresses to catch "boarding" events
	for _, addr := range boardingAddrs {
		addresses = append(addresses, addr.Address)

		script, err := toOutputScript(addr.Address, cfg.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for boarding address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: addr.Tapscripts,
			delay:      cfg.BoardingExitDelay, // TODO: ideally computed from tapscripts
		}
	}

	// we listen for classic P2TR addresses to catch onchain send/receive events
	for _, addr := range onchainAddrs {
		addresses = append(addresses, addr)

		script, err := toOutputScript(addr, cfg.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for onchain address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: []string{},                // no tapscripts for onchain address
			delay:      arklib.RelativeLocktime{}, // no delay for classic onchain address
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

		script, err := toOutputScript(addr, cfg.Network)
		if err != nil {
			log.WithError(err).Error("failed to get pk script for offchain address")
			continue
		}

		addressByScript[hex.EncodeToString(script)] = addressInfo{
			tapscripts: offchainAddr.Tapscripts,
			delay:      cfg.UnilateralExitDelay, // TODO: ideally computed from tapscripts
		}
	}

	if err := a.explorer.SubscribeForAddresses(addresses); err != nil {
		log.WithError(err).Error("failed to subscribe for onchain addresses")
		return
	}

	ch := a.explorer.GetAddressesEvents()

	log.Debugf("subscribed for %d addresses", len(addresses))
	for {
		select {
		case <-ctx.Done():
			log.Debug("stopping onchain transaction listener")
			if err := a.explorer.UnsubscribeForAddresses(addresses); err != nil {
				log.WithError(err).Error("failed to unsubscribe for onchain addresses")
			}
			return
		case update := <-ch:
			// TODO: we may want to forward this error so the user can try to reconnect.
			if update.Error != nil {
				log.WithError(update.Error).Error("received error from explorer")
				continue
			}
			txsToAdd := make([]sdktypes.Transaction, 0)
			txsToConfirm := make([]string, 0)
			utxosToConfirm := make(map[sdktypes.Outpoint]int64)
			utxosToSpend := make(map[sdktypes.Outpoint]string)
			if len(update.NewUtxos) > 0 {
				for _, u := range update.NewUtxos {
					txsToAdd = append(txsToAdd, sdktypes.Transaction{
						TransactionKey: sdktypes.TransactionKey{
							BoardingTxid: u.Txid,
						},
						Amount:    u.Amount,
						Type:      sdktypes.TxReceived,
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
				if err != nil {
					a.dbMu.Unlock()
					log.WithError(err).Error("failed to update rbf boarding transactions")
					continue
				}
				if count > 0 {
					log.Debugf("replaced %d boarding transaction(s)", count)
				}

				for replacedTxid, replacementTxid := range update.Replacements {
					newTransaction, err := a.explorer.GetTxHex(replacementTxid)
					if err != nil {
						log.WithError(err).Error("failed to get boarding replacement transaction")
						continue
					}
					var tx wire.MsgTx
					if err := tx.Deserialize(hex.NewDecoder(strings.NewReader(newTransaction))); err != nil {
						log.WithError(err).
							Error("failed to deserialize boarding replacement transaction")
						continue
					}

					utxoStore := a.store.UtxoStore()

					for outputIndex := range tx.TxOut {
						replacedUtxo := sdktypes.Outpoint{
							Txid: replacedTxid,
							VOut: uint32(outputIndex),
						}

						if utxos, err := utxoStore.GetUtxos(ctx, []sdktypes.Outpoint{replacedUtxo}); err == nil &&
							len(utxos) > 0 {
							if err := utxoStore.ReplaceUtxo(ctx, replacedUtxo, sdktypes.Outpoint{
								Txid: replacementTxid,
								VOut: uint32(outputIndex),
							}); err != nil {
								log.WithError(err).Error("failed to replace boarding utxo")
								continue
							}
						}
					}
				}
				a.dbMu.Unlock()
			}

			if len(update.NewUtxos) > 0 {
				utxosToAdd := make([]sdktypes.Utxo, 0, len(update.NewUtxos))
				for _, u := range update.NewUtxos {
					address, ok := addressByScript[u.Script]
					if !ok {
						log.WithField("script", u.Script).
							WithField("outpoint", u.Outpoint).
							Error("failed to find address for new utxo")
						continue
					}

					txHex, err := a.explorer.GetTxHex(u.Txid)
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

					utxosToAdd = append(utxosToAdd, sdktypes.Utxo{
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

func (a *newArkClient) listenDbEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			time.Sleep(100 * time.Millisecond)
			if a.utxoBroadcaster != nil {
				a.utxoBroadcaster.Close()
			}
			if a.vtxoBroadcaster != nil {
				a.vtxoBroadcaster.Close()
			}
			if a.txBroadcaster != nil {
				a.txBroadcaster.Close()
			}
			return
		case event, ok := <-a.store.UtxoStore().GetEventChannel():
			if !ok {
				continue
			}
			go func() {
				closedListeners := a.utxoBroadcaster.Publish(event)
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
				closedListeners := a.vtxoBroadcaster.Publish(event)
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
				closedListeners := a.txBroadcaster.Publish(event)
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

func (a *newArkClient) periodicRefreshDb(ctx context.Context) {
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
			if err := a.refreshDb(ctx); err != nil {
				log.WithError(err).Error("failed to refresh db")
			}
		}
	}
}

func (a *newArkClient) handleCommitmentTx(
	ctx context.Context, myPubkeys map[string]struct{}, commitmentTx *transport.TxNotification,
) error {
	a.dbMu.Lock()
	defer a.dbMu.Unlock()

	vtxosToAdd := make([]sdktypes.Vtxo, 0)
	vtxosToSpend := make(map[sdktypes.Outpoint]string, 0)
	txsToAdd := make([]sdktypes.Transaction, 0)
	txsToSettle := make([]string, 0)

	for _, vtxo := range commitmentTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos is ours.
	spentVtxos := make([]sdktypes.Outpoint, 0, len(commitmentTx.SpentVtxos))
	indexedSpentVtxos := make(map[sdktypes.Outpoint]sdktypes.Vtxo)
	for _, vtxo := range commitmentTx.SpentVtxos {
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			spentVtxos = append(spentVtxos, sdktypes.Outpoint{
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
			txsToAdd = append(txsToAdd, sdktypes.Transaction{
				TransactionKey: sdktypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      sdktypes.TxReceived,
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
				txsToAdd = append(txsToAdd, sdktypes.Transaction{
					TransactionKey: sdktypes.TransactionKey{
						CommitmentTxid: commitmentTx.Txid,
					},
					Amount:    settledBoardingAmount - vtxosToAddAmount,
					Type:      sdktypes.TxSent,
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
			txsToAdd = append(txsToAdd, sdktypes.Transaction{
				TransactionKey: sdktypes.TransactionKey{
					CommitmentTxid: commitmentTx.Txid,
				},
				Amount:    amount,
				Type:      sdktypes.TxSent,
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

func (a *newArkClient) handleArkTx(
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

	vtxosToAdd := make([]sdktypes.Vtxo, 0)
	vtxosToSpend := make(map[sdktypes.Outpoint]string)
	txsToAdd := make([]sdktypes.Transaction, 0)

	for _, vtxo := range arkTx.SpendableVtxos {
		// remove opcodes from P2TR script
		tapkey := vtxo.Script[4:]
		if _, ok := myPubkeys[tapkey]; ok {
			vtxosToAdd = append(vtxosToAdd, vtxo)
		}
	}

	// Check if any of the spent vtxos are ours.
	spentVtxos := make([]sdktypes.Outpoint, 0, len(arkTx.SpentVtxos))
	for _, vtxo := range arkTx.SpentVtxos {
		spentVtxos = append(spentVtxos, sdktypes.Outpoint{
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
			txsToAdd = append(txsToAdd, sdktypes.Transaction{
				TransactionKey: sdktypes.TransactionKey{
					ArkTxid: arkTx.Txid,
				},
				Amount:      amount,
				Type:        sdktypes.TxReceived,
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
		txsToAdd = append(txsToAdd, sdktypes.Transaction{
			TransactionKey: sdktypes.TransactionKey{
				ArkTxid: arkTx.Txid,
			},
			Amount:      inAmount - outAmount,
			Type:        sdktypes.TxSent,
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
		log.Debugf("added %d transaction(s)", count)
	}

	if len(vtxosToAdd) > 0 {
		count, err := a.store.VtxoStore().AddVtxos(ctx, vtxosToAdd)
		if err != nil {
			return err
		}
		log.Debugf("added %d vtxo(s)", count)
	}

	if len(vtxosToSpend) > 0 {
		count, err := a.store.VtxoStore().SpendVtxos(ctx, vtxosToSpend, arkTx.Txid)
		if err != nil {
			return err
		}
		log.Debugf("spent %d vtxo(s)", count)

		count, err = a.store.TransactionStore().SettleTransactions(ctx, txsToSettle, "")
		if err != nil {
			return err
		}
		log.Debugf("settled %d transaction(s)", count)
	}

	return nil
}

func (a *newArkClient) getAllBoardingUtxos(ctx context.Context) ([]sdktypes.Utxo, error) {
	wallet := a.ArkClient.Wallet()
	if wallet == nil {
		return nil, fmt.Errorf("wallet not initialized")
	}

	cfg, err := a.ArkClient.GetConfigData(ctx)
	if err != nil {
		return nil, err
	}

	_, _, boardingAddrs, _, err := wallet.GetAddresses(ctx)
	if err != nil {
		return nil, err
	}

	utxos := []sdktypes.Utxo{}
	for _, addr := range boardingAddrs {
		txs, err := a.explorer.GetTxs(addr)
		if err != nil {
			return nil, err
		}
		for _, tx := range txs {
			for i, vout := range tx.Vout {
				if vout.Address == addr {
					createdAt := time.Time{}
					utxoTime := time.Now()
					if tx.Status.Confirmed {
						createdAt = time.Unix(tx.Status.BlockTime, 0)
						utxoTime = time.Unix(tx.Status.BlockTime, 0)
					}

					txHex, err := a.explorer.GetTxHex(tx.Txid)
					if err != nil {
						return nil, err
					}
					spentStatuses, err := a.explorer.GetTxOutspends(tx.Txid)
					if err != nil {
						return nil, err
					}
					spent := false
					spentBy := ""
					if len(spentStatuses) > i {
						if spentStatuses[i].Spent {
							spent = true
							spentBy = spentStatuses[i].SpentBy
						}
					}

					utxos = append(utxos, sdktypes.Utxo{
						Outpoint: sdktypes.Outpoint{
							Txid: tx.Txid,
							VOut: uint32(i),
						},
						Amount: vout.Amount,
						Script: vout.Script,
						Delay:  cfg.BoardingExitDelay,
						SpendableAt: utxoTime.Add(
							time.Duration(cfg.BoardingExitDelay.Seconds()) * time.Second,
						),
						CreatedAt:  createdAt,
						Tapscripts: addr.Tapscripts,
						Spent:      spent,
						SpentBy:    spentBy,
						Tx:         txHex,
					})
				}
			}
		}
	}

	return utxos, nil
}

func (i *newArkClient) vtxosToTxs(
	ctx context.Context, spendable, spent []sdktypes.Vtxo, commitmentTxsToIgnore map[string]struct{},
) ([]sdktypes.Transaction, error) {
	indexer := i.ArkClient.Indexer()
	if indexer == nil {
		return nil, fmt.Errorf("indexer not initialized")
	}

	txs := make([]sdktypes.Transaction, 0)

	// Receivals

	// All vtxos are receivals unless:
	// - they resulted from a settlement (either boarding or refresh)
	// - they are the change of a spend tx or a collaborative exit
	vtxosLeftToCheck := append([]sdktypes.Vtxo{}, spent...)
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

		txs = append(txs, sdktypes.Transaction{
			TransactionKey: sdktypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    vtxo.Amount - settleAmount - spentAmount,
			Type:      sdktypes.TxReceived,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: settledBy,
		})
	}

	// Sendings

	// All spent vtxos are payments unless they are settlements of boarding utxos or refreshes

	// aggregate settled vtxos by "settledBy" (commitment txid)
	vtxosBySettledBy := make(map[string][]sdktypes.Vtxo)
	// aggregate spent vtxos by "arkTxid"
	vtxosBySpentBy := make(map[string][]sdktypes.Vtxo)
	for _, v := range spent {
		if v.SettledBy != "" {
			if _, ok := commitmentTxsToIgnore[v.SettledBy]; !ok {
				if _, ok := vtxosBySettledBy[v.SettledBy]; !ok {
					vtxosBySettledBy[v.SettledBy] = make([]sdktypes.Vtxo, 0)
				}
				vtxosBySettledBy[v.SettledBy] = append(vtxosBySettledBy[v.SettledBy], v)
				continue
			}
		}

		if len(v.ArkTxid) <= 0 {
			continue
		}

		if _, ok := vtxosBySpentBy[v.ArkTxid]; !ok {
			vtxosBySpentBy[v.ArkTxid] = make([]sdktypes.Vtxo, 0)
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

			txs = append(txs, sdktypes.Transaction{
				TransactionKey: sdktypes.TransactionKey{
					CommitmentTxid: vtxo.CommitmentTxids[0],
				},
				Amount:    forfeitAmount - resultedAmount,
				Type:      sdktypes.TxSent,
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
			opts := &indexer.GetVtxosRequestOption{}
			// nolint
			opts.WithOutpoints([]sdktypes.Outpoint{{Txid: sb, VOut: 0}})
			resp, err := indexer.GetVtxos(ctx, *opts)
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

		txs = append(txs, sdktypes.Transaction{
			TransactionKey: sdktypes.TransactionKey{
				CommitmentTxid: commitmentTxid,
				ArkTxid:        arkTxid,
			},
			Amount:    spentAmount - resultedAmount,
			Type:      sdktypes.TxSent,
			CreatedAt: vtxo.CreatedAt,
			SettledBy: vtxo.SettledBy,
		})
	}

	return txs, nil
}
