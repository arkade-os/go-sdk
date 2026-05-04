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
	ownerKeyIDParam  = "keyID"
	ownerKeyParam    = "ownerKey"
	signerKeyParam   = "signerKey"
	exitDelayParam   = "exitDelay"
	isOnchainParam   = "isOnchain"
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

func (s *contractStore) ListContracts(ctx context.Context, onchain bool) ([]types.Contract, error) {
	query := badgerhold.Where("IsOnchain").Eq(onchain)
	return s.find(ctx, query)
}

func (s *contractStore) GetLatestContract(
	ctx context.Context, contractType types.ContractType, onchain bool,
) (*types.Contract, error) {
	query := badgerhold.Where("Type").Eq(string(contractType)).
		And("IsOnchain").Eq(onchain).SortBy("OwnerKeyIndex").Reverse()
	contracts, err := s.find(ctx, query)
	if err != nil {
		return nil, err
	}
	if len(contracts) == 0 {
		return nil, nil
	}
	return &contracts[0], nil
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

func (s *contractStore) GetOnchainContracts(ctx context.Context) ([]types.Contract, error) {
	query := badgerhold.Where("IsOnchain").Eq(true)
	return s.find(ctx, query)
}
func (s *contractStore) GetContractsByKeyIDs(
	ctx context.Context, keyIDs []string,
) ([]types.Contract, error) {
	values := make([]interface{}, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		index, err := utils.ParseDerivationIndex(keyID)
		if err != nil {
			return nil, fmt.Errorf("invalid key ID %s: %w", keyID, err)
		}
		values = append(values, index)
	}
	query := badgerhold.Where("OwnerKeyIndex").In(values...)
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
	Type          string
	Label         string
	Script        string
	Address       string
	State         string
	CreatedAt     int64
	OwnerKey      string
	OwnerKeyIndex uint32
	SignerKey     string
	ExitDelay     arklib.RelativeLocktime
	IsOnchain     bool
	ExtraParams   map[string]string
	Metadata      map[string]string
}

func (c contractDTO) parse() types.Contract {
	params := map[string]string{
		ownerKeyParam:   c.OwnerKey,
		ownerKeyIDParam: fmt.Sprintf("m/0/%d", c.OwnerKeyIndex),
		signerKeyParam:  c.SignerKey,
		exitDelayParam:  strconv.Itoa(int(c.ExitDelay.Seconds())),
		isOnchainParam:  strconv.FormatBool(c.IsOnchain),
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
	if _, ok := contract.Params[ownerKeyParam]; !ok {
		return nil, fmt.Errorf("missing %s param", ownerKeyParam)
	}
	if _, ok := contract.Params[ownerKeyIDParam]; !ok {
		return nil, fmt.Errorf("missing %s param", ownerKeyIDParam)
	}
	if _, ok := contract.Params[signerKeyParam]; !ok {
		return nil, fmt.Errorf("missing %s param", signerKeyParam)
	}
	if _, ok := contract.Params[exitDelayParam]; !ok {
		return nil, fmt.Errorf("missing %s param", exitDelayParam)
	}

	ownerKeyIndex, err := utils.ParseDerivationIndex(contract.Params[ownerKeyIDParam])
	if err != nil {
		return nil, fmt.Errorf("invalid %s param: %w", ownerKeyIDParam, err)
	}
	exitDelay, err := utils.ParseDelay(contract.Params[exitDelayParam])
	if err != nil {
		return nil, fmt.Errorf("invalid %s param: %w", exitDelayParam, err)
	}
	var isOnchain bool
	if val, ok := contract.Params[isOnchainParam]; ok {
		isOnchain, err = strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("invalid %s param: %w", isOnchainParam, err)
		}
	}

	extraParams := make(map[string]string)
	for k, v := range contract.Params {
		if k != ownerKeyParam && k != ownerKeyIDParam && k != signerKeyParam &&
			k != exitDelayParam && k != isOnchainParam {
			extraParams[k] = v
		}
	}
	return &contractDTO{
		Type:          string(contract.Type),
		Label:         contract.Label,
		Script:        contract.Script,
		Address:       contract.Address,
		State:         string(contract.State),
		CreatedAt:     contract.CreatedAt.Unix(),
		OwnerKey:      contract.Params[ownerKeyParam],
		OwnerKeyIndex: ownerKeyIndex,
		SignerKey:     contract.Params[signerKeyParam],
		ExitDelay:     *exitDelay,
		ExtraParams:   extraParams,
		IsOnchain:     isOnchain,
		Metadata:      contract.Metadata,
	}, nil
}
