package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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
	wg      *sync.WaitGroup
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
		wg:      &sync.WaitGroup{},
		eventCh: make(chan types.UtxoEvent, 100),
	}, nil
}

func (s *utxoStore) ReplaceUtxo(ctx context.Context, from, to clientTypes.Outpoint) error {
	var utxo clientTypes.Utxo
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

	s.wg.Go(func() {
		s.sendEvent(types.UtxoEvent{
			Type:  types.UtxosReplaced,
			Utxos: []clientTypes.Utxo{utxo},
		})
	})

	return nil
}

func (s *utxoStore) AddUtxos(_ context.Context, utxos []clientTypes.Utxo) (int, error) {
	addedUtxos := make([]clientTypes.Utxo, 0, len(utxos))
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
		s.wg.Go(func() {
			s.sendEvent(types.UtxoEvent{
				Type:  types.UtxosAdded,
				Utxos: addedUtxos,
			})
		})
	}

	return len(addedUtxos), nil
}

func (s *utxoStore) ConfirmUtxos(
	ctx context.Context, confirmedUtxoMap map[clientTypes.Outpoint]int64,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(confirmedUtxoMap))
	for outpoint := range confirmedUtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := s.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	confirmedUtxos := make([]clientTypes.Utxo, 0, len(utxos))
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
		s.wg.Go(func() {
			s.sendEvent(types.UtxoEvent{
				Type:  types.UtxosConfirmed,
				Utxos: confirmedUtxos,
			})
		})
	}

	return len(confirmedUtxos), nil
}

func (s *utxoStore) SpendUtxos(
	ctx context.Context, spentUtxoMap map[clientTypes.Outpoint]string,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(spentUtxoMap))
	for outpoint := range spentUtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	utxos, err := s.GetUtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentUtxos := make([]clientTypes.Utxo, 0, len(utxos))
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
		s.wg.Go(func() {
			s.sendEvent(types.UtxoEvent{
				Type:  types.UtxosSpent,
				Utxos: spentUtxos,
			})
		})
	}

	return len(spentUtxos), nil
}

func (s *utxoStore) DeleteUtxos(
	_ context.Context, outpoints []clientTypes.Outpoint,
) (int, error) {
	deleted := 0
	for _, op := range outpoints {
		var utxo clientTypes.Utxo
		if err := s.db.Get(op.String(), &utxo); err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}
			return -1, err
		}
		if err := s.db.Delete(op.String(), &utxo); err != nil {
			return -1, err
		}
		deleted++
	}
	return deleted, nil
}


func (s *utxoStore) GetAllUtxos(
	_ context.Context,
) (spendable, spent []clientTypes.Utxo, err error) {
	var allUtxos []clientTypes.Utxo
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

func (s *utxoStore) GetUtxosByTxid(
	_ context.Context, txid string,
) ([]clientTypes.Utxo, error) {
	var utxos []clientTypes.Utxo
	if err := s.db.Find(&utxos, badgerhold.Where("Txid").Eq(txid)); err != nil {
		return nil, err
	}
	return utxos, nil
}

func (s *utxoStore) GetUtxos(
	_ context.Context, keys []clientTypes.Outpoint,
) ([]clientTypes.Utxo, error) {
	var utxos []clientTypes.Utxo
	for _, key := range keys {
		var utxo clientTypes.Utxo
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
	s.wg.Wait()
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
