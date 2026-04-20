package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	tapscripts, err := json.Marshal(c.Tapscripts)
	if err != nil {
		return fmt.Errorf("marshal tapscripts: %w", err)
	}
	boardingTapscripts, err := json.Marshal(c.BoardingTapscripts)
	if err != nil {
		return fmt.Errorf("marshal boarding tapscripts: %w", err)
	}

	var expiresAt *int64
	if c.ExpiresAt != nil {
		ts := c.ExpiresAt.Unix()
		expiresAt = &ts
	}

	const q = `
INSERT INTO contract (
    script, type, label, params, address, boarding, onchain, state,
    created_at, expires_at, metadata, tapscripts, boarding_tapscripts,
    delay_type, delay_value, boarding_delay_type, boarding_delay_value
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (script) DO UPDATE SET
    label               = EXCLUDED.label,
    state               = EXCLUDED.state,
    expires_at          = EXCLUDED.expires_at,
    metadata            = EXCLUDED.metadata`

	_, err = r.db.ExecContext(ctx, q,
		c.Script, c.Type, c.Label, string(params),
		c.Address, c.Boarding, c.Onchain, string(c.State),
		c.CreatedAt.Unix(), expiresAt,
		string(metadata), string(tapscripts), string(boardingTapscripts),
		int(c.Delay.Type), c.Delay.Value,
		int(c.BoardingDelay.Type), c.BoardingDelay.Value,
	)
	return err
}

func (r *contractRepository) GetContractByScript(
	ctx context.Context, scriptHex string,
) (*contract.Contract, error) {
	const q = `SELECT * FROM contract WHERE script = ?`
	row := r.db.QueryRowContext(ctx, q, scriptHex)
	c, err := scanContract(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return c, err
}

func (r *contractRepository) ListContracts(
	ctx context.Context, f contract.Filter,
) ([]contract.Contract, error) {
	q := `SELECT * FROM contract WHERE 1=1`
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
	defer rows.Close()

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

// rowScanner is implemented by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanContract(row *sql.Row) (*contract.Contract, error) {
	return scanContractRow(row)
}

func scanContractRow(row rowScanner) (*contract.Contract, error) {
	var (
		scriptHex, typ, label    string
		paramsJSON, metaJSON     string
		address, boarding, onchain string
		stateStr                 string
		createdAtUnix            int64
		expiresAtUnix            sql.NullInt64
		tapscriptsJSON           string
		boardingTapscriptsJSON   string
		delayType, delayValue    int64
		boardDelayType, boardDelayValue int64
	)

	if err := row.Scan(
		&scriptHex, &typ, &label, &paramsJSON,
		&address, &boarding, &onchain, &stateStr,
		&createdAtUnix, &expiresAtUnix,
		&metaJSON, &tapscriptsJSON, &boardingTapscriptsJSON,
		&delayType, &delayValue,
		&boardDelayType, &boardDelayValue,
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

	var tapscripts []string
	if err := json.Unmarshal([]byte(tapscriptsJSON), &tapscripts); err != nil {
		return nil, fmt.Errorf("unmarshal tapscripts: %w", err)
	}

	var boardingTapscripts []string
	if err := json.Unmarshal([]byte(boardingTapscriptsJSON), &boardingTapscripts); err != nil {
		return nil, fmt.Errorf("unmarshal boarding tapscripts: %w", err)
	}

	c := &contract.Contract{
		Script:             scriptHex,
		Type:               typ,
		Label:              label,
		Params:             params,
		Address:            address,
		Boarding:           boarding,
		Onchain:            onchain,
		State:              contract.State(stateStr),
		CreatedAt:          time.Unix(createdAtUnix, 0),
		Metadata:           metadata,
		Tapscripts:         tapscripts,
		BoardingTapscripts: boardingTapscripts,
		Delay: arklib.RelativeLocktime{
			Type:  arklib.RelativeLocktimeType(delayType),
			Value: uint32(delayValue),
		},
		BoardingDelay: arklib.RelativeLocktime{
			Type:  arklib.RelativeLocktimeType(boardDelayType),
			Value: uint32(boardDelayValue),
		},
	}

	if expiresAtUnix.Valid {
		t := time.Unix(expiresAtUnix.Int64, 0)
		c.ExpiresAt = &t
	}

	return c, nil
}
