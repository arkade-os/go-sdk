package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	clientTypes "github.com/arkade-os/arkd/pkg/client-lib/types"
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

func (v *vtxoRepository) AddVtxos(ctx context.Context, vtxos []clientTypes.Vtxo) (int, error) {
	addedVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
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
	ctx context.Context, spentVtxosMap map[clientTypes.Outpoint]string, arkTxid string,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(spentVtxosMap))
	for outpoint := range spentVtxosMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	spentVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
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
	vtxosToSweep []clientTypes.Vtxo,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(vtxosToSweep))
	for _, vtxo := range vtxosToSweep {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	sweptVtxos := make([]clientTypes.Vtxo, 0)
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
	vtxosToUnroll []clientTypes.Vtxo,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(vtxosToUnroll))
	for _, vtxo := range vtxosToUnroll {
		outpoints = append(outpoints, vtxo.Outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	unrolledVtxos := make([]clientTypes.Vtxo, 0)
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
	ctx context.Context, spentVtxosMap map[clientTypes.Outpoint]string, settledBy string,
) (int, error) {
	outpoints := make([]clientTypes.Outpoint, 0, len(spentVtxosMap))
	for outpoint := range spentVtxosMap {
		outpoints = append(outpoints, outpoint)
	}
	vtxos, err := v.GetVtxosByOutpoint(ctx, outpoints)
	if err != nil {
		return -1, err
	}

	settledVtxos := make([]clientTypes.Vtxo, 0, len(vtxos))
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

// GetVtxos returns VTXOs filtered by the given VtxoFilter.
//
// When page.PageSize == 0, all matching VTXOs are returned (no LIMIT).
// Otherwise the paginated SQL path is used, which dispatches based on filter.
//
// The view rows are grouped by outpoint because asset_vtxo_vw is a LEFT JOIN
// of vtxo and asset_vtxo: a multi-asset VTXO produces N view rows (one per
// asset). The grouping step collapses them back into a single Vtxo with an
// Assets slice.
func (v *vtxoRepository) GetVtxos(
	ctx context.Context, page types.Page, filter types.VtxoFilter,
) ([]clientTypes.Vtxo, error) {
	limit, offset := pageToLimitOffset(page)

	// Recoverable filtering cannot be done in SQL (it depends on wall-clock
	// time via ExpiresAt), so we always fetch ALL VTXOs, filter in Go, and
	// then apply pagination to the filtered result. This is acceptable because
	// recoverable VTXOs are rare.
	if filter == types.VtxoFilterRecoverable {
		rows, err := v.querier.SelectAllVtxos(ctx)
		if err != nil {
			return nil, err
		}
		allVtxos := assetVtxoVwRowsToVtxos(rows)
		filtered := make([]clientTypes.Vtxo, 0, len(allVtxos))
		for _, vtxo := range allVtxos {
			if vtxo.IsRecoverable() {
				filtered = append(filtered, vtxo)
			}
		}
		// Apply Go-side pagination to the filtered slice.
		if limit > 0 {
			if offset >= int64(len(filtered)) {
				return []clientTypes.Vtxo{}, nil
			}
			end := offset + limit
			if end > int64(len(filtered)) {
				end = int64(len(filtered))
			}
			filtered = filtered[offset:end]
		}
		return filtered, nil
	}

	var (
		rows []queries.AssetVtxoVw
		err  error

		allSpendable = limit == 0 && filter == types.VtxoFilterSpendable
		allSpent     = limit == 0 && filter == types.VtxoFilterSpent
		all          = limit == 0
	)

	switch {
	//no pagination
	case allSpendable:
		rows, err = v.querier.SelectSpendableVtxos(ctx)
	case allSpent:
		rows, err = v.querier.SelectSpentVtxos(ctx)
	case all:
		rows, err = v.querier.SelectAllVtxos(ctx)

	// with pagination
	case filter == types.VtxoFilterSpendable:
		rows, err = v.querier.SelectSpendableVtxosPaginated(
			ctx,
			queries.SelectSpendableVtxosPaginatedParams{
				Limit: limit, Offset: offset,
			},
		)
	case filter == types.VtxoFilterSpent:
		rows, err = v.querier.SelectSpentVtxosPaginated(
			ctx,
			queries.SelectSpentVtxosPaginatedParams{
				Limit: limit, Offset: offset,
			},
		)
	default:
		// VtxoFilterAll uses the "all" paginated query.
		rows, err = v.querier.SelectAllVtxosPaginated(ctx, queries.SelectAllVtxosPaginatedParams{
			Limit: limit, Offset: offset,
		})
	}
	if err != nil {
		return nil, err
	}

	return assetVtxoVwRowsToVtxos(rows), nil
}

// GetVtxosByOutpoint fetches specific VTXOs by their outpoint keys.
func (v *vtxoRepository) GetVtxosByOutpoint(
	ctx context.Context, keys []clientTypes.Outpoint,
) ([]clientTypes.Vtxo, error) {
	vtxos := make([]clientTypes.Vtxo, 0, len(keys))
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

// pageToLimitOffset converts a Page to SQL LIMIT/OFFSET values.
//   - PageSize == 0 is a sentinel meaning "return all rows" (limit 0 tells the
//     caller to skip the paginated query and use the unpaginated variant).
//   - PageSize values above MaxPageSize are clamped to prevent unbounded result sets.
//   - PageNum is 1-based for callers; 0 is silently treated as 1 so that
//     Page{PageSize: 10} returns the first page rather than an empty result.
func pageToLimitOffset(p types.Page) (limit, offset int64) {
	if p.PageSize == 0 {
		return 0, 0
	}
	size := p.PageSize
	if size > types.MaxPageSize {
		size = types.MaxPageSize
	}
	num := p.PageNum
	if num == 0 {
		num = 1
	}
	return int64(size), int64(num-1) * int64(size)
}

// assetVtxoVwRowsToVtxos groups flat view rows back into domain VTXOs.
//
// The asset_vtxo_vw view LEFT JOINs vtxo with asset_vtxo, so a single VTXO
// carrying N assets produces N rows in the result set. This function groups
// those rows by outpoint and merges each group into one Vtxo with a populated
// Assets slice.
func assetVtxoVwRowsToVtxos(rows []queries.AssetVtxoVw) []clientTypes.Vtxo {
	byOutpoint := make(map[string][]queries.AssetVtxoVw)
	for _, row := range rows {
		key := fmt.Sprintf("%s:%d", row.Txid, row.Vout)
		byOutpoint[key] = append(byOutpoint[key], row)
	}

	vtxos := make([]clientTypes.Vtxo, 0, len(byOutpoint))
	for _, group := range byOutpoint {
		vtxo := assetVtxoVwGroupToVtxo(group)
		vtxos = append(vtxos, vtxo)
	}

	return vtxos
}

// assetVtxoVwGroupToVtxo converts a group of AssetVtxoVw rows (same vtxo, one row per asset from the view) into one types.Vtxo.
func assetVtxoVwGroupToVtxo(group []queries.AssetVtxoVw) clientTypes.Vtxo {
	if len(group) == 0 {
		return clientTypes.Vtxo{}
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

func rowToVtxo(row queries.Vtxo, assetVtxos []queries.AssetVtxo) clientTypes.Vtxo {
	var expiresAt, createdAt time.Time
	if row.ExpiresAt != 0 {
		expiresAt = time.Unix(row.ExpiresAt, 0)
	}
	if row.CreatedAt != 0 {
		createdAt = time.Unix(row.CreatedAt, 0)
	}

	var assets []clientTypes.Asset
	if len(assetVtxos) > 0 {
		assets = make([]clientTypes.Asset, 0, len(assetVtxos))
		for _, av := range assetVtxos {
			assets = append(assets, clientTypes.Asset{
				AssetId: av.AssetID,
				Amount:  uint64(av.Amount),
			})
		}
	}
	return clientTypes.Vtxo{
		Outpoint: clientTypes.Outpoint{
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
