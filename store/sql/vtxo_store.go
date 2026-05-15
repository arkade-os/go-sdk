package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	clienttypes "github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/go-sdk/store/sql/sqlc/queries"
	"github.com/arkade-os/go-sdk/types"
	log "github.com/sirupsen/logrus"
)

type vtxoRepository struct {
	db      *sql.DB
	querier *queries.Queries
	lock    *sync.Mutex
	wg      *sync.WaitGroup
	eventCh chan types.VtxoEvent
}

func NewVtxoStore(db *sql.DB) types.VtxoStore {
	return &vtxoRepository{
		db:      db,
		querier: queries.New(db),
		lock:    &sync.Mutex{},
		wg:      &sync.WaitGroup{},
		eventCh: make(chan types.VtxoEvent, 100),
	}
}

func (v *vtxoRepository) AddVtxos(ctx context.Context, vtxos []clienttypes.Vtxo) (int, error) {
	addedVtxos := make([]clienttypes.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for i := range vtxos {
			vtxo := vtxos[i]
			var createdAt, expiresAt int64
			if !vtxo.ExpiresAt.IsZero() {
				expiresAt = vtxo.ExpiresAt.Unix()
			}
			if !vtxo.CreatedAt.IsZero() {
				createdAt = vtxo.CreatedAt.Unix()
			}
			if err := querierWithTx.InsertVtxo(
				ctx, queries.InsertVtxoParams{
					Txid:            vtxo.Txid,
					Vout:            int64(vtxo.VOut),
					Script:          vtxo.Script,
					Amount:          int64(vtxo.Amount),
					CommitmentTxids: strings.Join(vtxo.CommitmentTxids, ","),
					ExpiresAt:       expiresAt,
					CreatedAt:       createdAt,
					Preconfirmed:    vtxo.Preconfirmed,
					Swept:           vtxo.Swept,
					Unrolled:        vtxo.Unrolled,
					Spent:           vtxo.Spent,
					SpentBy:         sql.NullString{String: vtxo.SpentBy, Valid: true},
					SettledBy:       sql.NullString{String: vtxo.SettledBy, Valid: true},
					ArkTxid:         sql.NullString{String: vtxo.ArkTxid, Valid: true},
				},
			); err != nil {
				if strings.Contains(err.Error(), "UNIQUE constraint failed") {
					return nil
				}
				return err
			}
			// Insert assets into asset and asset_vtxo tables
			for _, asset := range vtxo.Assets {
				if err := querierWithTx.UpsertAsset(ctx, queries.UpsertAssetParams{
					AssetID: asset.AssetId,
				}); err != nil {
					return err
				}
				if err := querierWithTx.InsertAssetVtxo(ctx, queries.InsertAssetVtxoParams{
					VtxoTxid: vtxo.Txid,
					VtxoVout: int64(vtxo.VOut),
					AssetID:  asset.AssetId,
					Amount:   int64(asset.Amount),
				}); err != nil {
					return err
				}
			}
			addedVtxos = append(addedVtxos, vtxo)
		}

		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(addedVtxos) > 0 {
		v.wg.Go(func() {
			v.sendEvent(types.VtxoEvent{
				Type:  types.VtxosAdded,
				Vtxos: addedVtxos,
			})
		})
	}

	return len(addedVtxos), nil
}

func (v *vtxoRepository) SpendVtxos(
	ctx context.Context, spentVtxosMap map[clienttypes.Outpoint]string, arkTxid string,
) (int, error) {
	outpoints := make([]clienttypes.Outpoint, 0, len(spentVtxosMap))
	for outpoint := range spentVtxosMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoints(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]clienttypes.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if vtxo.Spent {
				continue
			}
			vtxo.Spent = true
			vtxo.SpentBy = spentVtxosMap[vtxo.Outpoint]
			vtxo.ArkTxid = arkTxid
			if err := querierWithTx.SpendVtxo(ctx, queries.SpendVtxoParams{
				SpentBy: sql.NullString{String: vtxo.SpentBy, Valid: true},
				ArkTxid: sql.NullString{String: vtxo.ArkTxid, Valid: true},
				Txid:    vtxo.Txid,
				Vout:    int64(vtxo.VOut),
			}); err != nil {
				return err
			}
			spentVtxos = append(spentVtxos, vtxo)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(spentVtxos) > 0 {
		v.wg.Go(func() {
			v.sendEvent(types.VtxoEvent{
				Type:  types.VtxosSpent,
				Vtxos: spentVtxos,
			})
		})
	}

	return len(spentVtxos), nil
}

func (v *vtxoRepository) SweepVtxos(
	ctx context.Context,
	vtxosToSweep []clienttypes.Vtxo,
) (int, error) {
	outpoints := make([]clienttypes.Outpoint, 0, len(vtxosToSweep))
	for _, vtxo := range vtxosToSweep {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoints(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	sweptVtxos := make([]clienttypes.Vtxo, 0)
	txBody := func(querierWithTx *queries.Queries) error {
		for _, v := range vtxos {
			if v.Swept {
				continue
			}

			v.Swept = true
			if err := querierWithTx.SweepVtxo(ctx, queries.SweepVtxoParams{
				Txid: v.Txid,
				Vout: int64(v.VOut),
			}); err != nil {
				return err
			}
			sweptVtxos = append(sweptVtxos, v)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(sweptVtxos) > 0 {
		v.wg.Go(func() {
			v.sendEvent(types.VtxoEvent{
				Type:  types.VtxosSwept,
				Vtxos: sweptVtxos,
			})
		})
	}

	return len(sweptVtxos), nil
}

func (v *vtxoRepository) UnrollVtxos(
	ctx context.Context,
	vtxosToUnroll []clienttypes.Vtxo,
) (int, error) {
	outpoints := make([]clienttypes.Outpoint, 0, len(vtxosToUnroll))
	for _, vtxo := range vtxosToUnroll {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoints(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	unrolledVtxos := make([]clienttypes.Vtxo, 0)
	txBody := func(querierWithTx *queries.Queries) error {
		for _, v := range vtxos {
			if v.Unrolled {
				continue
			}

			v.Unrolled = true
			if err := querierWithTx.UnrollVtxo(ctx, queries.UnrollVtxoParams{
				Txid: v.Txid,
				Vout: int64(v.VOut),
			}); err != nil {
				return err
			}
			unrolledVtxos = append(unrolledVtxos, v)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(unrolledVtxos) > 0 {
		v.wg.Go(func() {
			v.sendEvent(types.VtxoEvent{
				Type:  types.VtxosUnrolled,
				Vtxos: unrolledVtxos,
			})
		})
	}

	return len(unrolledVtxos), nil
}

func (v *vtxoRepository) SettleVtxos(
	ctx context.Context, spentVtxosMap map[clienttypes.Outpoint]string, settledBy string,
) (int, error) {
	outpoints := make([]clienttypes.Outpoint, 0, len(spentVtxosMap))
	for outpoint := range spentVtxosMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoints(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	settledVtxos := make([]clienttypes.Vtxo, 0, len(vtxos))
	txBody := func(querierWithTx *queries.Queries) error {
		for _, vtxo := range vtxos {
			if vtxo.Spent {
				continue
			}
			vtxo.Spent = true
			vtxo.SpentBy = spentVtxosMap[vtxo.Outpoint]
			vtxo.SettledBy = settledBy
			if err := querierWithTx.SettleVtxo(ctx, queries.SettleVtxoParams{
				SpentBy:   sql.NullString{String: vtxo.SpentBy, Valid: true},
				SettledBy: sql.NullString{String: vtxo.SettledBy, Valid: true},
				Txid:      vtxo.Txid,
				Vout:      int64(vtxo.VOut),
			}); err != nil {
				return err
			}
			settledVtxos = append(settledVtxos, vtxo)
		}
		return nil
	}
	if err := execTx(ctx, v.db, txBody); err != nil {
		return -1, err
	}

	if len(settledVtxos) > 0 {
		v.wg.Go(func() {
			v.sendEvent(types.VtxoEvent{
				Type:  types.VtxoSettled,
				Vtxos: settledVtxos,
			})
		})
	}

	return len(settledVtxos), nil
}

func (v *vtxoRepository) GetVtxosByOutpoints(
	ctx context.Context, keys []clienttypes.Outpoint,
) ([]clienttypes.Vtxo, error) {
	vtxos := make([]clienttypes.Vtxo, 0, len(keys))
	for _, key := range keys {
		rows, err := v.querier.SelectVtxo(ctx, queries.SelectVtxoParams{
			Txid: key.Txid,
			Vout: int64(key.VOut),
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		if len(rows) > 0 {
			vtxos = append(vtxos, assetVtxoVwGroupToVtxo(rows))
		}
	}

	return vtxos, nil
}

func (v *vtxoRepository) GetSpendableOrRecoverableVtxos(
	ctx context.Context,
) (spendableOrRecoverable []clienttypes.Vtxo, err error) {
	rows, err := v.querier.SelectSpendableOrRecoverableVtxos(ctx)
	if err != nil {
		return nil, err
	}

	return assetVtxoVwRowsToVtxos(rows), nil
}

func (v *vtxoRepository) GetVtxos(
	ctx context.Context, q types.GetVtxoFilter,
) ([]clienttypes.Vtxo, *types.Cursor, error) {
	// We ask SQL for q.Limit+1 rows. If the database returns more than q.Limit rows,
	// we know there's at least one more page, and the extra row's outpoint becomes the cursor
	// for the next page. If it returns ≤ q.Limit, we've hit the end and Next stays nil.
	params := queries.GetVtxosParams{
		LimitPlusOne: int64(q.Limit) + 1,
	}

	// Translate the typed status filter into the string the SQL query expects.
	// VtxoStatusAll leaves StatusFilter.Valid = false, which the WHERE clause
	// interprets as "no status filter."
	switch q.Status {
	case types.VtxoStatusSpendable:
		params.StatusFilter = sql.NullString{String: "spendable", Valid: true}
	case types.VtxoStatusSpent:
		params.StatusFilter = sql.NullString{String: "spent", Valid: true}
	case types.VtxoStatusAll:
		// No status filter at the SQL layer.
	}

	if q.AssetID != "" {
		params.AssetID = sql.NullString{String: q.AssetID, Valid: true}
	}

	// Cursor position: SQL resumes from rows strictly less than
	// (cursor_created_at, cursor_txid, cursor_vout) in the descending sort
	// order. Nil After = first page; the cursor params stay invalid and the
	// query's cursor predicate is a no-op.
	if q.After != nil {
		params.CursorCreatedAt = sql.NullInt64{Int64: q.After.CreatedAt, Valid: true}
		params.CursorTxid = sql.NullString{String: q.After.Txid, Valid: true}
		params.CursorVout = sql.NullInt64{Int64: int64(q.After.VOut), Valid: true}
	}

	rows, err := v.querier.GetVtxos(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	vtxos := assetVtxoVwRowsToVtxos(rows)

	// If we got back more than the caller asked for, the extra row is the
	// "has more" sentinel: drop it and use its outpoint to build the cursor
	// for the cursor page. Otherwise we hit the end of the dataset and Next
	// stays nil, signaling no further pages.
	var cursor *types.Cursor
	if len(vtxos) > q.Limit {
		vtxos = vtxos[:q.Limit]
		last := vtxos[len(vtxos)-1]
		cursor = &types.Cursor{
			CreatedAt: last.CreatedAt.Unix(),
			Txid:      last.Txid,
			VOut:      last.VOut,
		}
	}

	return vtxos, cursor, nil
}

func (v *vtxoRepository) GetEventChannel() <-chan types.VtxoEvent {
	return v.eventCh
}

func (v *vtxoRepository) Clean(ctx context.Context) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	if err := v.querier.CleanAssetVtxos(ctx); err != nil {
		return err
	}
	if err := v.querier.CleanVtxos(ctx); err != nil {
		return err
	}
	// nolint:all
	v.db.ExecContext(ctx, "VACUUM")
	return nil
}

func (v *vtxoRepository) sendEvent(event types.VtxoEvent) {
	v.lock.Lock()
	defer v.lock.Unlock()

	for range 3 {
		select {
		case v.eventCh <- event:
			return
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
	log.Warn("failed to send vtxo event")
}

// assetVtxoVwRowsToVtxos folds the N×M (vtxo × asset) row stream produced by
// asset_vtxo_vw into one Vtxo per outpoint. Preserves first-seen order of
// outpoints, so SQL ORDER BY clauses are observable in the output.
func assetVtxoVwRowsToVtxos(rows []queries.AssetVtxoVw) []clienttypes.Vtxo {
	byOutpoint := make(map[string][]queries.AssetVtxoVw)
	order := make([]string, 0)
	for _, row := range rows {
		key := fmt.Sprintf("%s:%d", row.Txid, row.Vout)
		if _, ok := byOutpoint[key]; !ok {
			order = append(order, key)
		}
		byOutpoint[key] = append(byOutpoint[key], row)
	}

	vtxos := make([]clienttypes.Vtxo, 0, len(order))
	for _, key := range order {
		vtxos = append(vtxos, assetVtxoVwGroupToVtxo(byOutpoint[key]))
	}
	return vtxos
}

// assetVtxoVwGroupToVtxo converts a group of AssetVtxoVw rows (same vtxo, one row per asset from the view) into one clienttypes.Vtxo.
func assetVtxoVwGroupToVtxo(group []queries.AssetVtxoVw) clienttypes.Vtxo {
	if len(group) == 0 {
		return clienttypes.Vtxo{}
	}
	row := group[0]
	vtxoRow := queries.Vtxo{
		Txid:            row.Txid,
		Vout:            row.Vout,
		Script:          row.Script,
		Amount:          row.Amount,
		CommitmentTxids: row.CommitmentTxids,
		SpentBy:         row.SpentBy,
		Spent:           row.Spent,
		ExpiresAt:       row.ExpiresAt,
		CreatedAt:       row.CreatedAt,
		Preconfirmed:    row.Preconfirmed,
		Swept:           row.Swept,
		SettledBy:       row.SettledBy,
		Unrolled:        row.Unrolled,
		ArkTxid:         row.ArkTxid,
	}

	assets := make([]queries.AssetVtxo, 0)
	for _, r := range group {
		if r.AssetID.Valid {
			assets = append(assets, queries.AssetVtxo{
				VtxoTxid: r.Txid,
				VtxoVout: r.Vout,
				AssetID:  r.AssetID.String,
				Amount:   r.AssetAmount.Int64,
			})
		}
	}
	return rowToVtxo(vtxoRow, assets)
}

func rowToVtxo(row queries.Vtxo, assetVtxos []queries.AssetVtxo) clienttypes.Vtxo {
	var expiresAt, createdAt time.Time
	if row.ExpiresAt != 0 {
		expiresAt = time.Unix(row.ExpiresAt, 0)
	}
	if row.CreatedAt != 0 {
		createdAt = time.Unix(row.CreatedAt, 0)
	}

	var assets []clienttypes.Asset
	if len(assetVtxos) > 0 {
		assets = make([]clienttypes.Asset, 0, len(assetVtxos))
		for _, av := range assetVtxos {
			assets = append(assets, clienttypes.Asset{
				AssetId: av.AssetID,
				Amount:  uint64(av.Amount),
			})
		}
	}
	return clienttypes.Vtxo{
		Outpoint: clienttypes.Outpoint{
			Txid: row.Txid,
			VOut: uint32(row.Vout),
		},
		Script:          row.Script,
		Amount:          uint64(row.Amount),
		CommitmentTxids: strings.Split(row.CommitmentTxids, ","),
		ExpiresAt:       expiresAt,
		CreatedAt:       createdAt,
		Preconfirmed:    row.Preconfirmed,
		Swept:           row.Swept,
		Unrolled:        row.Unrolled,
		Spent:           row.Spent,
		SpentBy:         row.SpentBy.String,
		SettledBy:       row.SettledBy.String,
		ArkTxid:         row.ArkTxid.String,
		Assets:          assets,
	}
}
