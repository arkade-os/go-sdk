package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

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
	eventCh chan types.VtxoEvent
}

type vtxoRecord struct {
	Outpoint        types.Outpoint
	Script          string
	Amount          uint64
	CommitmentTxids []string
	ExpiresAt       time.Time
	CreatedAt       time.Time
	Preconfirmed    bool
	Swept           bool
	Unrolled        bool
	Spent           bool
	SpentBy         string
	SettledBy       string
	ArkTxid         string
	Asset           []byte
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
		eventCh: make(chan types.VtxoEvent, 100),
	}, nil
}

func (s *vtxoStore) AddVtxos(_ context.Context, vtxos []types.Vtxo) (int, error) {
	addedVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		record, err := toVtxoRecord(vtxo)
		if err != nil {
			return -1, err
		}
		if err := s.db.Insert(vtxo.Outpoint.String(), &record); err != nil {
			if errors.Is(err, badgerhold.ErrKeyExists) {
				continue
			}
			return -1, err
		}
		addedVtxos = append(addedVtxos, vtxo)
	}

	if len(addedVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosAdded, Vtxos: addedVtxos})
	}

	return len(addedVtxos), nil
}

func (s *vtxoStore) SpendVtxos(
	ctx context.Context, spentVtxoMap map[types.Outpoint]string, arkTxid string,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.ArkTxid = arkTxid

		record, err := toVtxoRecord(vtxo)
		if err != nil {
			return -1, err
		}
		if err := s.db.Update(vtxo.Outpoint.String(), &record); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosSpent, Vtxos: spentVtxos})
	}

	return len(spentVtxos), nil
}

func (s *vtxoStore) SettleVtxos(
	ctx context.Context, spentVtxoMap map[types.Outpoint]string, settledBy string,
) (int, error) {
	outpoints := make([]types.Outpoint, 0, len(spentVtxoMap))
	for outpoint := range spentVtxoMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := s.GetVtxos(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]types.Vtxo, 0, len(vtxos))
	for _, vtxo := range vtxos {
		if vtxo.Spent {
			continue
		}
		vtxo.Spent = true
		vtxo.SpentBy = spentVtxoMap[vtxo.Outpoint]
		vtxo.SettledBy = settledBy

		record, err := toVtxoRecord(vtxo)
		if err != nil {
			return -1, err
		}
		if err := s.db.Update(vtxo.Outpoint.String(), &record); err != nil {
			return -1, err
		}
		spentVtxos = append(spentVtxos, vtxo)
	}

	if len(spentVtxos) > 0 {
		go s.sendEvent(types.VtxoEvent{Type: types.VtxosSpent, Vtxos: spentVtxos})
	}

	return len(spentVtxos), nil
}

func (s *vtxoStore) UpdateVtxos(ctx context.Context, vtxos []types.Vtxo) (int, error) {
	for _, vtxo := range vtxos {
		record, err := toVtxoRecord(vtxo)
		if err != nil {
			return -1, err
		}
		if err := s.db.Upsert(vtxo.Outpoint.String(), &record); err != nil {
			return -1, err
		}
	}
	go s.sendEvent(types.VtxoEvent{
		Type:  types.VtxosUpdated,
		Vtxos: vtxos,
	})
	return len(vtxos), nil
}

func (s *vtxoStore) GetAllVtxos(
	_ context.Context,
) (spendable, spent []types.Vtxo, err error) {
	var allVtxoRecords []vtxoRecord
	err = s.db.Find(&allVtxoRecords, nil)
	if err != nil {
		return nil, nil, err
	}

	for _, record := range allVtxoRecords {
		vtxo := record.toVtxo()
		if vtxo.Spent || vtxo.Unrolled {
			spent = append(spent, vtxo)
		} else {
			spendable = append(spendable, vtxo)
		}
	}
	return
}

func (s *vtxoStore) GetSpendableVtxos(ctx context.Context) (spendable []types.Vtxo, err error) {
	var allVtxoRecords []vtxoRecord
	err = s.db.Find(&allVtxoRecords, nil)
	if err != nil {
		return nil, err
	}

	for _, record := range allVtxoRecords {
		vtxo := record.toVtxo()
		if !vtxo.Spent && !vtxo.Unrolled {
			spendable = append(spendable, vtxo)
		}
	}
	return spendable, nil
}

func (s *vtxoStore) GetVtxos(
	_ context.Context, keys []types.Outpoint,
) ([]types.Vtxo, error) {
	var vtxos []types.Vtxo
	for _, key := range keys {
		var record vtxoRecord
		err := s.db.Get(key.String(), &record)
		if err != nil {
			if errors.Is(err, badgerhold.ErrNotFound) {
				continue
			}

			return nil, err
		}
		vtxos = append(vtxos, record.toVtxo())
	}

	return vtxos, nil
}

func (s *vtxoStore) GetEventChannel() <-chan types.VtxoEvent {
	return s.eventCh
}

func (s *vtxoStore) Clean(_ context.Context) error {
	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean the vtxo db: %s", err)
	}
	return nil
}

func (s *vtxoStore) Close() {
	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing db: %s", err)
	}
}

func (s *vtxoStore) sendEvent(event types.VtxoEvent) {
	s.lock.Lock()
	defer s.lock.Unlock()

	select {
	case s.eventCh <- event:
		return
	default:
		time.Sleep(100 * time.Millisecond)
	}
}

func toVtxoRecord(vtxo types.Vtxo) (vtxoRecord, error) {
	var assetData []byte
	if vtxo.AssetOutput != nil {
		encoded, err := vtxo.AssetOutput.EncodeTlv()
		if err != nil {
			return vtxoRecord{}, err
		}
		assetData = encoded
	}

	return vtxoRecord{
		Outpoint:        vtxo.Outpoint,
		Script:          vtxo.Script,
		Amount:          vtxo.Amount,
		CommitmentTxids: vtxo.CommitmentTxids,
		ExpiresAt:       vtxo.ExpiresAt,
		CreatedAt:       vtxo.CreatedAt,
		Preconfirmed:    vtxo.Preconfirmed,
		Swept:           vtxo.Swept,
		Unrolled:        vtxo.Unrolled,
		Spent:           vtxo.Spent,
		SpentBy:         vtxo.SpentBy,
		SettledBy:       vtxo.SettledBy,
		ArkTxid:         vtxo.ArkTxid,
		Asset:           assetData,
	}, nil
}

func (r vtxoRecord) toVtxo() types.Vtxo {
	var parsedAsset *types.AssetOutput
	if len(r.Asset) > 0 {
		var decoded types.AssetOutput
		if err := decoded.DecodeTlv(r.Asset); err == nil {
			parsedAsset = &decoded
		}
	}

	return types.Vtxo{
		Outpoint:        r.Outpoint,
		Script:          r.Script,
		Amount:          r.Amount,
		CommitmentTxids: r.CommitmentTxids,
		ExpiresAt:       r.ExpiresAt,
		CreatedAt:       r.CreatedAt,
		Preconfirmed:    r.Preconfirmed,
		Swept:           r.Swept,
		Unrolled:        r.Unrolled,
		Spent:           r.Spent,
		SpentBy:         r.SpentBy,
		SettledBy:       r.SettledBy,
		ArkTxid:         r.ArkTxid,
		AssetOutput:     parsedAsset,
	}
}
