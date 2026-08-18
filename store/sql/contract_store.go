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

// nonInteractiveReceiverParam is the contract param persisted only for non-interactive
// vhtlcs (it must match the param name used by the vhtlc contract handler). Its presence
// is what distinguishes the two vhtlc flavors: they are stored under the same vhtlc type,
// so that they share the key-index counter of their common keyspace, and the exact type
// is resolved back from the params on read.
const nonInteractiveReceiverParam = "nonInteractiveReceiver"

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
		Type:      string(storageContractType(contract.Type)),
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

func (v *contractStore) GetActiveContractsByType(
	ctx context.Context, contractType types.ContractType,
) ([]types.Contract, error) {
	rows, err := v.querier.SelectActiveContractsByType(
		ctx, string(storageContractType(contractType)),
	)
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		// The two vhtlc flavors share the stored type: keep only the requested one.
		if contract := toContract(row); contract.Type == contractType {
			contracts = append(contracts, contract)
		}
	}
	return contracts, nil
}

// GetLatestContract returns the contract with the highest key index of the given type, no
// matter its state or, for the vhtlc flavors, its exact type: it drives the key-index
// counter, and skipping a contract of the shared vhtlc keyspace would rewind the counter
// and reuse its key.
func (v *contractStore) GetLatestContract(
	ctx context.Context, contractType types.ContractType,
) (*types.Contract, error) {
	row, err := v.querier.SelectLatestContractByType(
		ctx, string(storageContractType(contractType)),
	)
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

func (v *contractStore) EnableContracts(ctx context.Context, scripts []string) error {
	return v.setContractsState(ctx, scripts, types.ContractStateActive)
}

func (v *contractStore) DisableContracts(ctx context.Context, scripts []string) error {
	return v.setContractsState(ctx, scripts, types.ContractStateInactive)
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

// setContractsState sets the state of the given contracts. When more than one script is given the
// updates run in a single transaction, so either all of them are applied or none is.
func (v *contractStore) setContractsState(
	ctx context.Context, scripts []string, state types.ContractState,
) error {
	if len(scripts) == 0 {
		return nil
	}

	update := func(querier *queries.Queries) error {
		for _, script := range scripts {
			n, err := querier.UpdateContractState(ctx, queries.UpdateContractStateParams{
				State:  string(state),
				Script: script,
			})
			if err != nil {
				return fmt.Errorf("failed to update contract %s: %w", script, err)
			}
			if n == 0 {
				return fmt.Errorf("contract %s not found", script)
			}
		}
		return nil
	}

	if len(scripts) == 1 {
		return update(v.querier)
	}
	return execTx(ctx, v.db, update)
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
		Type:      resolveContractType(types.ContractType(row.Type), params),
		Label:     row.Label.String,
		Params:    params,
		Script:    row.Script,
		Address:   row.Address,
		State:     types.ContractState(row.State),
		CreatedAt: time.Unix(row.CreatedAt, 0),
		Metadata:  metadata,
	}
}

// storageContractType returns the contract type persisted in the type column: the two
// vhtlc flavors are stored under the same vhtlc type.
func storageContractType(t types.ContractType) types.ContractType {
	if t == types.ContractTypeNonInteractiveVHTLC {
		return types.ContractTypeVHTLC
	}
	return t
}

// resolveContractType returns the exact type of a stored contract, derived from the
// persisted type and params: a vhtlc carrying the non-interactive params is a
// non-interactive vhtlc.
func resolveContractType(
	t types.ContractType, params map[string]string,
) types.ContractType {
	if t == types.ContractTypeVHTLC && params[nonInteractiveReceiverParam] != "" {
		return types.ContractTypeNonInteractiveVHTLC
	}
	return t
}
