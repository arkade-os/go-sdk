package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/arkade-os/go-sdk/contract"
)

type contractRepository struct {
	db *sql.DB
}

// NewContractStore returns a ContractStore backed by the given SQLite database.
func NewContractStore(db *sql.DB) contract.ContractStore {
	return &contractRepository{db: db}
}

func (r *contractRepository) UpsertContract(ctx context.Context, c contract.Contract) error {
	params, err := json.Marshal(c.Params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	metadata, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	isOnchain := 0
	if c.IsOnchain {
		isOnchain = 1
	}

	const q = `
INSERT INTO contract (script, type, label, params, address, is_onchain, state, created_at, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (script) DO UPDATE SET
    label      = EXCLUDED.label,
    state      = EXCLUDED.state,
    metadata   = EXCLUDED.metadata`

	_, err = r.db.ExecContext(ctx, q,
		c.Script, c.Type, c.Label, string(params),
		c.Address, isOnchain, string(c.State),
		c.CreatedAt.Unix(),
		string(metadata),
	)
	return err
}

func (r *contractRepository) GetContractByScript(
	ctx context.Context, scriptHex string,
) (*contract.Contract, error) {
	const q = `SELECT script, type, label, params, address, is_onchain, state, created_at, metadata FROM contract WHERE script = ?`
	row := r.db.QueryRowContext(ctx, q, scriptHex)
	c, err := scanContract(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return c, err
}

func (r *contractRepository) ListContracts(
	ctx context.Context, f contract.Filter,
) ([]contract.Contract, error) {
	q := `SELECT script, type, label, params, address, is_onchain, state, created_at, metadata FROM contract WHERE 1=1`
	args := []any{}

	if f.Type != nil {
		q += ` AND type = ?`
		args = append(args, *f.Type)
	}
	if f.State != nil {
		q += ` AND state = ?`
		args = append(args, *f.State)
	}
	if f.Script != nil {
		q += ` AND script = ?`
		args = append(args, *f.Script)
	}

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	var contracts []contract.Contract
	for rows.Next() {
		c, err := scanContractRow(rows)
		if err != nil {
			return nil, err
		}
		contracts = append(contracts, *c)
	}
	return contracts, rows.Err()
}

func (r *contractRepository) UpdateContractState(
	ctx context.Context, scriptHex string, state contract.State,
) error {
	const q = `UPDATE contract SET state = ? WHERE script = ?`
	_, err := r.db.ExecContext(ctx, q, string(state), scriptHex)
	return err
}

func (r *contractRepository) Clean(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM contract`)
	return err
}

// rowScanner is implemented by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanContract(row *sql.Row) (*contract.Contract, error) {
	return scanContractRow(row)
}

func scanContractRow(row rowScanner) (*contract.Contract, error) {
	var (
		scriptHex, typ, label string
		paramsJSON, metaJSON  string
		address, stateStr     string
		isOnchain             int64
		createdAtUnix         int64
	)

	if err := row.Scan(
		&scriptHex, &typ, &label, &paramsJSON,
		&address, &isOnchain, &stateStr,
		&createdAtUnix, &metaJSON,
	); err != nil {
		return nil, err
	}

	var params map[string]string
	if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
		return nil, fmt.Errorf("unmarshal params: %w", err)
	}

	var metadata map[string]any
	if err := json.Unmarshal([]byte(metaJSON), &metadata); err != nil {
		return nil, fmt.Errorf("unmarshal metadata: %w", err)
	}

	return &contract.Contract{
		Script:    scriptHex,
		Type:      typ,
		Label:     label,
		Params:    params,
		Address:   address,
		IsOnchain: isOnchain != 0,
		State:     contract.State(stateStr),
		CreatedAt: time.Unix(createdAtUnix, 0),
		Metadata:  metadata,
	}, nil
}
