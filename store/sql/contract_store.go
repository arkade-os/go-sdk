package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/go-sdk/store/sql/sqlc/queries"
	"github.com/arkade-os/go-sdk/types"
)

type contractStore struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
}

func NewContractStore(db *sql.DB) types.ContractStore {
	return &contractStore{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
	}
}

func (v *contractStore) AddContract(
	ctx context.Context, contract types.Contract, keyIndex uint32,
) error {
	params, err := json.Marshal(contract.Params)
	if err != nil {
		return fmt.Errorf("failed to serialize extra params: %w", err)
	}

	var metadataBytes []byte
	if len(contract.Metadata) > 0 {
		buf, err := json.Marshal(contract.Metadata)
		if err != nil {
			return fmt.Errorf("failed to serialize metadata: %w", err)
		}
		metadataBytes = buf
	}
	metadata := string(metadataBytes)
	if err := v.querier.InsertContract(ctx, queries.InsertContractParams{
		Script:    contract.Script,
		Type:      string(contract.Type),
		Label:     sql.NullString{String: contract.Label, Valid: len(contract.Label) > 0},
		Address:   contract.Address,
		State:     string(contract.State),
		CreatedAt: contract.CreatedAt.Unix(),
		Params:    string(params),
		KeyIndex:  int64(keyIndex),
		Metadata:  sql.NullString{String: metadata, Valid: len(metadata) > 0},
	}); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint failed") {
			return fmt.Errorf("contract %s already exists", contract.Script)
		}
		return err
	}
	return nil
}

func (v *contractStore) ListContracts(ctx context.Context) ([]types.Contract, error) {
	rows, err := v.querier.SelectAllContracts(ctx)
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		contracts = append(contracts, toContract(row))
	}
	return contracts, nil
}

func (v *contractStore) GetContractsByScripts(
	ctx context.Context, scripts []string,
) ([]types.Contract, error) {
	rows, err := v.querier.SelectContractsByScripts(ctx, scripts)
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		contracts = append(contracts, toContract(row))
	}
	return contracts, nil
}

func (v *contractStore) GetContractsByState(
	ctx context.Context, state types.ContractState,
) ([]types.Contract, error) {
	rows, err := v.querier.SelectContractsByState(ctx, string(state))
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		contracts = append(contracts, toContract(row))
	}
	return contracts, nil
}

func (v *contractStore) GetContractsByType(
	ctx context.Context, contractType types.ContractType,
) ([]types.Contract, error) {
	rows, err := v.querier.SelectContractsByType(ctx, string(contractType))
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		contracts = append(contracts, toContract(row))
	}
	return contracts, nil
}

func (v *contractStore) GetLatestContract(
	ctx context.Context, contractType types.ContractType,
) (*types.Contract, error) {
	row, err := v.querier.SelectLatestContractByType(ctx, string(contractType))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	contract := toContract(row)

	return &contract, nil
}
func (v *contractStore) UpdateContractState(
	ctx context.Context, script string, state types.ContractState,
) error {
	n, err := v.querier.UpdateContractState(ctx, queries.UpdateContractStateParams{
		Script: script,
		State:  string(state),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("contract %s not found", script)
	}
	return nil
}

func (v *contractStore) Clean(ctx context.Context) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if err := v.querier.CleanContracts(ctx); err != nil {
		return err
	}
	// nolint:all
	v.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (v *contractStore) Close() {
	v.lock.Lock()
	defer v.lock.Unlock()

	// nolint:all
	v.db.Close()
}

func toContract(row queries.Contract) types.Contract {
	params := make(map[string]string)
	// nolint:errcheck
	json.Unmarshal([]byte(row.Params), &params)
	metadata := make(map[string]string)
	if row.Metadata.Valid {
		// nolint:errcheck
		json.Unmarshal([]byte(row.Metadata.String), &metadata)
	}
	return types.Contract{
		Type:      types.ContractType(row.Type),
		Label:     row.Label.String,
		Params:    params,
		Script:    row.Script,
		Address:   row.Address,
		State:     types.ContractState(row.State),
		CreatedAt: time.Unix(row.CreatedAt, 0),
		Metadata:  metadata,
	}
}
