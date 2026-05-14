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
	vtxoStoreDir = "vtxos"
)

type vtxoStore struct {
	db      *badgerhold.Store
	lock    *sync.Mutex
	wg      *sync.WaitGroup
	eventCh chan types.VtxoEvent
}

func NewVtxoStore(dir string, logger badger.Logger) (types.VtxoStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, vtxoStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open vtxo store: %s", err)
	}
	return &vtxoStore{
		db:      badgerDb,
		lock:    &sync.Mutex{},
		wg:      &sync.WaitGroup{},
		eventCh: make(chan types.VtxoEvent, 100),
	}, nil
}

func (s *vtxoStore) AddVtxos(_ context.Context, vtxos []clientTypes.Vtxo) (int, error) {
	addedVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if err := s.db.Insert(vtxo.Outpoint.String(), &vtxo); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		addedVtxos = append(addedVtxos, vtxo)
	}

	if len(addedVtxos) > 0 {
		s.wg.Go(func() {
			s.sendEvent(types.VtxoEvent{
				Type:  types.VtxosAdded,
				Vtxos: addedVtxos,
			})
		})
	}

	return len(addedVtxos), nil
}

func (s *vtxoStore) SpendVtxos(
	ctx context.Context, spentVtxoMap map[clientTypes.Outpoint]string, arkTxid string,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.ArkTxid = arkTxid

		if err := s.db.Update(vtxo.Outpoint.String(), &vtxo); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		s.wg.Go(func() {
			s.sendEvent(types.VtxoEvent{
				Type:  types.VtxosSpent,
				Vtxos: spentVtxos,
			})
		})
	}

	return len(spentVtxos), nil
}

func (s *vtxoStore) SweepVtxos(ctx context.Context, vtxosToSweep []clientTypes.Vtxo) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(vtxosToSweep))
	for _, vtxo := range vtxosToSweep {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := s.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	sweptVtxos := make([]clientTypes.Vtxo, 0, len(vtxosToSweep))
	for _, v := range vtxos {
		if v.Swept {
			continue
		}

		v.Swept = true
		if err := s.db.Update(v.Outpoint.String(), &v); err != nil {
			return -1, err
		}
		sweptVtxos = append(sweptVtxos, v)
	}

	if len(sweptVtxos) > 0 {
		s.wg.Go(func() {
			s.sendEvent(types.VtxoEvent{
				Type:  types.VtxosSwept,
				Vtxos: sweptVtxos,
			})
		})
	}

	return len(sweptVtxos), nil
}

func (s *vtxoStore) UnrollVtxos(
	ctx context.Context,
	vtxosToUnroll []clientTypes.Vtxo,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(vtxosToUnroll))
	for _, vtxo := range vtxosToUnroll {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := s.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	unrolledVtxos := make([]clientTypes.Vtxo, 0, len(vtxosToUnroll))
	for _, v := range vtxos {
		if v.Unrolled {
			continue
		}

		v.Unrolled = true
		if err := s.db.Update(v.Outpoint.String(), &v); err != nil {
			return -1, err
		}
		unrolledVtxos = append(unrolledVtxos, v)
	}

	if len(unrolledVtxos) > 0 {
		s.wg.Go(func() {
			s.sendEvent(types.VtxoEvent{
				Type:  types.VtxosUnrolled,
				Vtxos: unrolledVtxos,
			})
		})
	}

	return len(unrolledVtxos), nil
}

func (s *vtxoStore) SettleVtxos(
	ctx context.Context, spentVtxoMap map[clientTypes.Outpoint]string, settledBy string,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.SettledBy = settledBy

		if err := s.db.Update(vtxo.Outpoint.String(), &vtxo); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		s.wg.Go(func() {
			s.sendEvent(types.VtxoEvent{
				Type:  types.VtxoSettled,
				Vtxos: spentVtxos,
			})
		})
	}

	return len(spentVtxos), nil
}

// GetVtxos returns VTXOs filtered by VtxoFilter. The Page parameter is
// accepted for interface compatibility but ignored — KV store always returns
// all matching VTXOs (pagination is only implemented in the SQL store).
func (s *vtxoStore) GetVtxos(
	_ context.Context, _ types.Page, filter types.VtxoFilter,
) ([]clientTypes.Vtxo, error) {
	var allVtxos []clientTypes.Vtxo
	if err := s.db.Find(&allVtxos, nil); err != nil {
		return nil, err
	}

	result := make([]clientTypes.Vtxo, 0, len(allVtxos))
	for _, vtxo := range allVtxos {
		switch filter {
		case types.VtxoFilterSpendable:
			if !vtxo.Spent && !vtxo.Unrolled {
				result = append(result, vtxo)
			}
		case types.VtxoFilterSpent:
			if vtxo.Spent || vtxo.Unrolled {
				result = append(result, vtxo)
			}
		case types.VtxoFilterRecoverable:
			if vtxo.IsRecoverable() {
				result = append(result, vtxo)
			}
		default: // VtxoFilterAll
			result = append(result, vtxo)
		}
	}
	return result, nil
}

func (s *vtxoStore) GetVtxosByOutpoint(
	_ context.Context, keys []clientTypes.Outpoint,
) ([]clientTypes.Vtxo, error) {
	var vtxos []clientTypes.Vtxo
	for _, key := range keys {
		var vtxo clientTypes.Vtxo
		err := s.db.Get(key.String(), &vtxo)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		vtxos = append(vtxos, vtxo)
	}

	return vtxos, nil
}

func (s *vtxoStore) GetEventChannel() <-chan types.VtxoEvent {
	return s.eventCh
}

func (s *vtxoStore) Clean(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the vtxo db: %s", err)
	}
	return nil
}

func (s *vtxoStore) Close() {
	s.wg.Wait()
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing db: %s", err)
	}
}

func (s *vtxoStore) sendEvent(event types.VtxoEvent) {
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
	log.Warn("failed to send vtxo event")
}
