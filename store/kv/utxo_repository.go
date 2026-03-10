package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	sdktypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	utxoStoreDir = "utxos"
)

type utxoStore struct {
	db      *badgerhold.Store
	lock    *sync.Mutex
	eventCh chan types.UtxoEvent
}

func NewUtxoStore(dir string, logger badger.Logger) (types.UtxoStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, utxoStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open utxo store: %s", err)
	}
	return &utxoStore{
		db:      badgerDb,
		lock:    &sync.Mutex{},
		eventCh: make(chan types.UtxoEvent, 100),
	}, nil
}

func (s *utxoStore) ReplaceUtxo(ctx context.Context, from, to sdktypes.Outpoint) error {
	var utxo sdktypes.Utxo
	if err := s.db.Get(from.String(), &utxo); err != nil {
		return err
	}

	if err := s.db.Delete(from.String(), &utxo); err != nil {
		return err
	}

	utxo.Outpoint = to
	if err := s.db.Insert(to.String(), &utxo); err != nil {
		return err
	}

	go s.sendEvent(types.UtxoEvent{Type: types.UtxosReplaced, Utxos: []sdktypes.Utxo{utxo}})

	return nil
}

func (s *utxoStore) AddUtxos(_ context.Context, utxos []sdktypes.Utxo) (int, error) {
	addedUtxos := make([]sdktypes.Utxo, 0, len(utxos))
	for _, utxo := range utxos {
		if err := s.db.Insert(utxo.String(), &utxo); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		addedUtxos = append(addedUtxos, utxo)
	}

	if len(addedUtxos) > 0 {
		go s.sendEvent(types.UtxoEvent{Type: types.UtxosAdded, Utxos: addedUtxos})
	}

	return len(addedUtxos), nil
}

func (s *utxoStore) ConfirmUtxos(
	ctx context.Context, confirmedUtxoMap map[sdktypes.Outpoint]int64,
) (int, error) {
	outpoints := make([]sdktypes.Outpoint, 0, len(confirmedUtxoMap))
	for outpoint := range confirmedUtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := s.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	confirmedUtxos := make([]sdktypes.Utxo, 0, len(utxos))
	for _, utxo := range utxos {
		if !utxo.CreatedAt.IsZero() {
			continue
		}
		utxo.CreatedAt = time.Unix(confirmedUtxoMap[utxo.Outpoint], 0)
		utxo.SpendableAt = utxo.CreatedAt
		if utxo.Delay.Value > 0 {
			utxo.SpendableAt = utxo.SpendableAt.Add(
				time.Duration(utxo.Delay.Seconds()) * time.Second,
			)
		}

		if err := s.db.Update(utxo.String(), &utxo); err != nil {
			return -1, err
		}
		confirmedUtxos = append(confirmedUtxos, utxo)
	}

	if len(confirmedUtxos) > 0 {
		go s.sendEvent(types.UtxoEvent{Type: types.UtxosConfirmed, Utxos: confirmedUtxos})
	}

	return len(confirmedUtxos), nil
}

func (s *utxoStore) SpendUtxos(
	ctx context.Context, spentUtxoMap map[sdktypes.Outpoint]string,
) (int, error) {
	outpoints := make([]sdktypes.Outpoint, 0, len(spentUtxoMap))
	for outpoint := range spentUtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := s.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentUtxos := make([]sdktypes.Utxo, 0, len(utxos))
	for _, utxo := range utxos {
		if utxo.Spent {
			continue
		}
		utxo.Spent = true
		utxo.SpentBy = spentUtxoMap[utxo.Outpoint]

		if err := s.db.Update(utxo.String(), &utxo); err != nil {
			return -1, err
		}
		spentUtxos = append(spentUtxos, utxo)
	}

	if len(spentUtxos) > 0 {
		go s.sendEvent(types.UtxoEvent{Type: types.UtxosSpent, Utxos: spentUtxos})
	}

	return len(spentUtxos), nil
}

func (s *utxoStore) GetAllUtxos(
	_ context.Context,
) (spendable, spent []sdktypes.Utxo, err error) {
	var allUtxos []sdktypes.Utxo
	if err := s.db.Find(&allUtxos, nil); err != nil {
		return nil, nil, err
	}

	for _, utxo := range allUtxos {
		if utxo.Spent {
			spent = append(spent, utxo)
		} else {
			spendable = append(spendable, utxo)
		}
	}
	return
}

func (s *utxoStore) GetUtxos(
	_ context.Context, keys []sdktypes.Outpoint,
) ([]sdktypes.Utxo, error) {
	var utxos []sdktypes.Utxo
	for _, key := range keys {
		var utxo sdktypes.Utxo
		if err := s.db.Get(key.String(), &utxo); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		utxos = append(utxos, utxo)
	}

	return utxos, nil
}

func (s *utxoStore) GetEventChannel() <-chan types.UtxoEvent {
	return s.eventCh
}

func (s *utxoStore) Clean(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the utxo db: %s", err)
	}
	return nil
}

func (s *utxoStore) Close() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing db: %s", err)
	}
}

func (s *utxoStore) sendEvent(event types.UtxoEvent) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for range 3 {
		select {
		case s.eventCh <- event:
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
	log.Warn("failed to send utxo event")
}
