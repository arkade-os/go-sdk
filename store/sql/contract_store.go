package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/arkade-os/go-sdk/internal/utils"
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

func (v *contractStore) AddContract(ctx context.Context, contract types.Contract) error {
	if _, ok := contract.Params[types.ContractParamOwnerKey]; !ok {
		return fmt.Errorf("missing %s param", types.ContractParamOwnerKey)
	}
	if _, ok := contract.Params[types.ContractParamOwnerKeyId]; !ok {
		return fmt.Errorf("missing %s param", types.ContractParamOwnerKeyId)
	}
	if _, ok := contract.Params[types.ContractParamSignerKey]; !ok {
		return fmt.Errorf("missing %s param", types.ContractParamSignerKey)
	}
	if _, ok := contract.Params[types.ContractParamExitDelay]; !ok {
		return fmt.Errorf("missing %s param", types.ContractParamExitDelay)
	}

	exitDelay, err := utils.ParseDelay(contract.Params[types.ContractParamExitDelay])
	if err != nil {
		return fmt.Errorf("invalid %s param: %w", types.ContractParamExitDelay, err)
	}

	extraParams := make(map[string]string)
	for k, v := range contract.Params {
		if k != types.ContractParamOwnerKey && k != types.ContractParamOwnerKeyId &&
			k != types.ContractParamSignerKey && k != types.ContractParamExitDelay {
			extraParams[k] = v
		}
	}
	var extraParamsBytes []byte
	if len(extraParams) > 0 {
		buf, err := json.Marshal(extraParams)
		if err != nil {
			return fmt.Errorf("failed to serialize extra params: %w", err)
		}
		extraParamsBytes = buf
	}
	extraParamsStr := string(extraParamsBytes)

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
		Script:      contract.Script,
		Type:        string(contract.Type),
		Label:       sql.NullString{String: contract.Label, Valid: len(contract.Label) > 0},
		Address:     contract.Address,
		State:       string(contract.State),
		CreatedAt:   contract.CreatedAt.Unix(),
		OwnerKeyID:  contract.Params[types.ContractParamOwnerKeyId],
		OwnerKey:    contract.Params[types.ContractParamOwnerKey],
		SignerKey:   contract.Params[types.ContractParamSignerKey],
		ExitDelay:   exitDelay.Seconds(),
		ExtraParams: sql.NullString{String: extraParamsStr, Valid: len(extraParamsStr) > 0},
		Metadata:    sql.NullString{String: metadata, Valid: len(metadata) > 0},
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

func (v *contractStore) GetContractsByKeyIds(
	ctx context.Context, keyIds []string,
) ([]types.Contract, error) {
	rows, err := v.querier.SelectContractsByKeyIDs(ctx, keyIds)
	if err != nil {
		return nil, err
	}
	contracts := make([]types.Contract, 0, len(rows))
	for _, row := range rows {
		contracts = append(contracts, toContract(row))
	}
	return contracts, nil
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
	if row.ExtraParams.Valid {
		// nolint:errcheck
		json.Unmarshal([]byte(row.ExtraParams.String), &params)
	}
	params[types.ContractParamOwnerKey] = row.OwnerKey
	params[types.ContractParamOwnerKeyId] = row.OwnerKeyID
	params[types.ContractParamSignerKey] = row.SignerKey
	params[types.ContractParamExitDelay] = strconv.Itoa(int(row.ExitDelay))
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
