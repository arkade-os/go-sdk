package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/arkade-os/go-sdk/types"
	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"github.com/timshannon/badgerhold/v4"
)

const (
	contractStoreDir = "contracts"
)

type contractStore struct {
	db   *badgerhold.Store
	lock *sync.Mutex
}

func NewContractStore(dir string, logger badger.Logger) (types.ContractStore, error) {
	if dir != "" {
		dir = filepath.Join(dir, contractStoreDir)
	}
	badgerDb, err := createDB(dir, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to open contract store: %s", err)
	}

	return &contractStore{
		db:   badgerDb,
		lock: &sync.Mutex{},
	}, nil
}

func (s *contractStore) AddContract(
	ctx context.Context, contract types.Contract, keyIndex uint32,
) error {
	if err := s.db.Insert(contract.Script, contractDTO{contract, keyIndex}); err != nil {
		if errors.Is(err, badgerhold.ErrKeyExists) {
			return fmt.Errorf("contract %s already exists", contract.Script)
		}
		return err
	}
	return nil
}

func (s *contractStore) ListContracts(ctx context.Context) ([]types.Contract, error) {
	return s.find(ctx, nil)
}

func (s *contractStore) GetContractsByScripts(
	ctx context.Context, scripts []string,
) ([]types.Contract, error) {
	values := make([]interface{}, len(scripts))
	for i, script := range scripts {
		values[i] = script
	}
	query := badgerhold.Where("Script").In(values...)
	return s.find(ctx, query)
}

func (s *contractStore) GetContractsByState(
	ctx context.Context, state types.ContractState,
) ([]types.Contract, error) {
	query := badgerhold.Where("State").Eq(string(state))
	return s.find(ctx, query)
}

func (s *contractStore) GetContractsByType(
	ctx context.Context, contractType types.ContractType,
) ([]types.Contract, error) {
	query := badgerhold.Where("Type").Eq(string(contractType))
	return s.find(ctx, query)
}

func (s *contractStore) GetLatestContract(
	ctx context.Context, contractType types.ContractType,
) (*types.Contract, error) {
	query := badgerhold.Where("Type").Eq(string(contractType)).SortBy("KeyIndex").Reverse()
	contracts, err := s.find(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(contracts) == 0 {
		return nil, nil
	}
	return &contracts[0], nil
}

func (s *contractStore) UpdateContractState(
	ctx context.Context, script string, state types.ContractState,
) error {
	var dto contractDTO
	if err := s.db.Get(script, &dto); err != nil {
		if errors.Is(err, badgerhold.ErrNotFound) {
			return fmt.Errorf("contract %s not found", script)
		}
		return err
	}
	dto.State = state
	return s.db.Update(script, dto)
}

func (s *contractStore) find(
	ctx context.Context, query *badgerhold.Query,
) ([]types.Contract, error) {
	var data []contractDTO
	if err := s.db.Find(&data, query); err != nil {
		return nil, err
	}

	var contracts []types.Contract
	for _, dto := range data {
		contracts = append(contracts, dto.Contract)
	}
	return contracts, nil
}
func (s *contractStore) Clean(_ context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Badger().DropAll(); err != nil {
		return fmt.Errorf("failed to clean contract store: %s", err)
	}
	return nil
}

func (s *contractStore) Close() {
	s.lock.Lock()
	defer s.lock.Unlock()

	if err := s.db.Close(); err != nil {
		log.Debugf("error on closing contract store: %s", err)
	}
}

type contractDTO struct {
	types.Contract
	KeyIndex uint32
}
