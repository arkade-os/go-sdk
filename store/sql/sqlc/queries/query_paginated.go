// Package queries — paginated query implementations.
//
// These queries are hand-written because sqlc cannot generate queries containing
// IN (subquery) patterns. The equivalent SQL is documented inline below.
//
// WHY a subquery instead of LIMIT on the view directly:
//
// asset_vtxo_vw is a LEFT JOIN of vtxo and asset_vtxo. A multi-asset VTXO
// produces N rows in the view (one per asset). If we applied LIMIT directly to
// the view, a 2-asset VTXO would consume 2 slots of the page budget, returning
// fewer logical VTXOs than the caller requested. Instead, the inner subquery
// paginates at the VTXO level (on the vtxo table), and the outer query fetches
// all view rows for the selected VTXOs. The Go layer then groups view rows
// back into domain VTXOs via the byOutpoint map (see assetVtxoVwRowsToVtxos).
package queries

import "context"

const selectAllVtxosPaginated = `SELECT txid, vout, script, amount, commitment_txids, spent_by, spent, expires_at,
       created_at, preconfirmed, swept, settled_by, unrolled, ark_txid, asset_id, asset_amount
FROM asset_vtxo_vw
WHERE (txid, vout) IN (
  SELECT txid, vout FROM vtxo
  ORDER BY created_at DESC, txid ASC, vout ASC
  LIMIT ? OFFSET ?
)`

type SelectAllVtxosPaginatedParams struct {
	Limit  int64
	Offset int64
}

func (q *Queries) SelectAllVtxosPaginated(
	ctx context.Context,
	arg SelectAllVtxosPaginatedParams,
) ([]AssetVtxoVw, error) {
	rows, err := q.db.QueryContext(ctx, selectAllVtxosPaginated, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var items []AssetVtxoVw
	for rows.Next() {
		var i AssetVtxoVw
		if err := rows.Scan(
			&i.Txid,
			&i.Vout,
			&i.Script,
			&i.Amount,
			&i.CommitmentTxids,
			&i.SpentBy,
			&i.Spent,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.Preconfirmed,
			&i.Swept,
			&i.SettledBy,
			&i.Unrolled,
			&i.ArkTxid,
			&i.AssetID,
			&i.AssetAmount,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSpendableVtxosPaginated = `SELECT txid, vout, script, amount, commitment_txids, spent_by, spent,
       expires_at, created_at, preconfirmed, swept, settled_by, unrolled, ark_txid, asset_id, asset_amount
FROM asset_vtxo_vw
WHERE (txid, vout) IN (
  SELECT txid, vout FROM vtxo
  WHERE spent = false AND unrolled = false
  ORDER BY created_at DESC, txid ASC, vout ASC
  LIMIT ? OFFSET ?
)`

type SelectSpendableVtxosPaginatedParams struct {
	Limit  int64
	Offset int64
}

func (q *Queries) SelectSpendableVtxosPaginated(
	ctx context.Context,
	arg SelectSpendableVtxosPaginatedParams,
) ([]AssetVtxoVw, error) {
	rows, err := q.db.QueryContext(ctx, selectSpendableVtxosPaginated, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var items []AssetVtxoVw
	for rows.Next() {
		var i AssetVtxoVw
		if err := rows.Scan(
			&i.Txid,
			&i.Vout,
			&i.Script,
			&i.Amount,
			&i.CommitmentTxids,
			&i.SpentBy,
			&i.Spent,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.Preconfirmed,
			&i.Swept,
			&i.SettledBy,
			&i.Unrolled,
			&i.ArkTxid,
			&i.AssetID,
			&i.AssetAmount,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSpentVtxos = `SELECT txid, vout, script, amount, commitment_txids, spent_by, spent,
       expires_at, created_at, preconfirmed, swept, settled_by, unrolled, ark_txid, asset_id, asset_amount
FROM asset_vtxo_vw
WHERE spent = true OR unrolled = true`

func (q *Queries) SelectSpentVtxos(
	ctx context.Context,
) ([]AssetVtxoVw, error) {
	rows, err := q.db.QueryContext(ctx, selectSpentVtxos)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var items []AssetVtxoVw
	for rows.Next() {
		var i AssetVtxoVw
		if err := rows.Scan(
			&i.Txid,
			&i.Vout,
			&i.Script,
			&i.Amount,
			&i.CommitmentTxids,
			&i.SpentBy,
			&i.Spent,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.Preconfirmed,
			&i.Swept,
			&i.SettledBy,
			&i.Unrolled,
			&i.ArkTxid,
			&i.AssetID,
			&i.AssetAmount,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const selectSpentVtxosPaginated = `SELECT txid, vout, script, amount, commitment_txids, spent_by, spent,
       expires_at, created_at, preconfirmed, swept, settled_by, unrolled, ark_txid, asset_id, asset_amount
FROM asset_vtxo_vw
WHERE (txid, vout) IN (
  SELECT txid, vout FROM vtxo
  WHERE spent = true OR unrolled = true
  ORDER BY created_at DESC, txid ASC, vout ASC
  LIMIT ? OFFSET ?
)`

type SelectSpentVtxosPaginatedParams struct {
	Limit  int64
	Offset int64
}

func (q *Queries) SelectSpentVtxosPaginated(
	ctx context.Context,
	arg SelectSpentVtxosPaginatedParams,
) ([]AssetVtxoVw, error) {
	rows, err := q.db.QueryContext(ctx, selectSpentVtxosPaginated, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var items []AssetVtxoVw
	for rows.Next() {
		var i AssetVtxoVw
		if err := rows.Scan(
			&i.Txid,
			&i.Vout,
			&i.Script,
			&i.Amount,
			&i.CommitmentTxids,
			&i.SpentBy,
			&i.Spent,
			&i.ExpiresAt,
			&i.CreatedAt,
			&i.Preconfirmed,
			&i.Swept,
			&i.SettledBy,
			&i.Unrolled,
			&i.ArkTxid,
			&i.AssetID,
			&i.AssetAmount,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
