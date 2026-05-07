package kvstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/go-sdk/internal/utils"
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

func (s *contractStore) AddContract(ctx context.Context, contract types.Contract) error {
	dto, err := toContractDTO(contract)
	if err != nil {
		return err
	}
	if err := s.db.Insert(contract.Script, *dto); err != nil {
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

func (s *contractStore) GetContractsByKeyIds(
	ctx context.Context, keyIds []string,
) ([]types.Contract, error) {
	values := make([]interface{}, 0, len(keyIds))
	for _, keyId := range keyIds {
		values = append(values, keyId)
	}
	query := badgerhold.Where("OwnerKeyId").In(values...)
	return s.find(ctx, query)
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
	dto.State = string(state)
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
		contracts = append(contracts, dto.parse())
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
	Type        string
	Label       string
	Script      string
	Address     string
	State       string
	CreatedAt   int64
	OwnerKey    string
	OwnerKeyId  string
	SignerKey   string
	ExitDelay   arklib.RelativeLocktime
	ExtraParams map[string]string
	Metadata    map[string]string
}

func (c contractDTO) parse() types.Contract {
	params := map[string]string{
		types.ContractParamOwnerKey:   c.OwnerKey,
		types.ContractParamOwnerKeyId: c.OwnerKeyId,
		types.ContractParamSignerKey:  c.SignerKey,
		types.ContractParamExitDelay:  strconv.Itoa(int(c.ExitDelay.Seconds())),
	}
	for k, v := range c.ExtraParams {
		params[k] = v
	}
	return types.Contract{
		Type:      types.ContractType(c.Type),
		Label:     c.Label,
		Params:    params,
		Script:    c.Script,
		Address:   c.Address,
		State:     types.ContractState(c.State),
		CreatedAt: time.Unix(c.CreatedAt, 0),
		Metadata:  c.Metadata,
	}
}

func toContractDTO(contract types.Contract) (*contractDTO, error) {
	if _, ok := contract.Params[types.ContractParamOwnerKey]; !ok {
		return nil, fmt.Errorf("missing %s param", types.ContractParamOwnerKey)
	}
	if _, ok := contract.Params[types.ContractParamOwnerKeyId]; !ok {
		return nil, fmt.Errorf("missing %s param", types.ContractParamOwnerKeyId)
	}
	if _, ok := contract.Params[types.ContractParamSignerKey]; !ok {
		return nil, fmt.Errorf("missing %s param", types.ContractParamSignerKey)
	}
	if _, ok := contract.Params[types.ContractParamExitDelay]; !ok {
		return nil, fmt.Errorf("missing %s param", types.ContractParamExitDelay)
	}

	exitDelay, err := utils.ParseDelay(contract.Params[types.ContractParamExitDelay])
	if err != nil {
		return nil, fmt.Errorf("invalid %s param: %w", types.ContractParamExitDelay, err)
	}

	extraParams := make(map[string]string)
	for k, v := range contract.Params {
		if k != types.ContractParamOwnerKey && k != types.ContractParamOwnerKeyId &&
			k != types.ContractParamSignerKey && k != types.ContractParamExitDelay {
			extraParams[k] = v
		}
	}
	return &contractDTO{
		Type:        string(contract.Type),
		Label:       contract.Label,
		Script:      contract.Script,
		Address:     contract.Address,
		State:       string(contract.State),
		CreatedAt:   contract.CreatedAt.Unix(),
		OwnerKey:    contract.Params[types.ContractParamOwnerKey],
		OwnerKeyId:  contract.Params[types.ContractParamOwnerKeyId],
		SignerKey:   contract.Params[types.ContractParamSignerKey],
		ExitDelay:   *exitDelay,
		ExtraParams: extraParams,
		Metadata:    contract.Metadata,
	}, nil
}
