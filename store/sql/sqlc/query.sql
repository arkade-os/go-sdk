-- name: InsertVtxo :exec
INSERT INTO vtxo (
    txid, vout, script, amount, commitment_txids, spent_by, spent, preconfirmed, expires_at, created_at, swept, unrolled, settled_by, ark_txid
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateVtxo :exec
UPDATE vtxo
SET
    spent = true,
    spent_by = :spent_by,
    settled_by = COALESCE(sqlc.narg(settled_by), settled_by),
    ark_txid = COALESCE(sqlc.narg(ark_txid), ark_txid)
WHERE txid = :txid AND vout = :vout;

-- name: SelectAllVtxos :many
SELECT * FROM asset_vtxo_vw;

-- name: SelectVtxo :many
SELECT *
FROM asset_vtxo_vw
WHERE txid = :txid AND vout = :vout;

-- name: SelectSpendableVtxos :many
SELECT * FROM asset_vtxo_vw
WHERE spent = false AND unrolled = false;

-- name: CleanVtxos :exec
DELETE FROM vtxo;

-- name: UpsertAsset :exec
INSERT INTO asset (asset_id, metadata, immutable) VALUES (:asset_id, sqlc.narg(metadata), sqlc.narg(immutable))
ON CONFLICT (asset_id) DO UPDATE SET
    metadata = COALESCE(EXCLUDED.metadata, metadata),
    immutable = COALESCE(EXCLUDED.immutable, immutable);

-- name: InsertAssetControl :exec
INSERT INTO asset_control (asset_id, control_asset_id) VALUES (:asset_id, :control_asset_id)
ON CONFLICT (asset_id, control_asset_id) DO NOTHING;

-- name: InsertAssetVtxo :exec
INSERT INTO asset_vtxo (vtxo_txid, vtxo_vout, asset_id, amount) VALUES (?, ?, ?, ?);

-- name: CleanAssetVtxos :exec
DELETE FROM asset_vtxo;

-- name: InsertTx :exec
INSERT INTO tx (
    txid, txid_type, amount, type, created_at, hex, settled_by, settled, asset_packet, asset_packet_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateTx :exec
UPDATE tx
SET
    created_at     = COALESCE(sqlc.narg(created_at), created_at),
    settled        = CASE WHEN :settled_by IS NOT NULL THEN TRUE ELSE settled END,
    settled_by    = COALESCE(sqlc.narg(settled_by), settled_by)
WHERE txid = :txid; 

-- name: ReplaceTx :exec
UPDATE tx
SET    txid       = :new_txid,
       txid_type  = :txid_type,
       amount     = :amount,
       type       = :type,
       settled_by    = :settled_by,
       settled        = CASE WHEN :settled_by IS NOT NULL THEN TRUE ELSE FALSE END,
       created_at = :created_at,
       hex        = :hex
WHERE  txid = :old_txid;

-- name: SelectAllTxs :many
SELECT * FROM tx;

-- name: SelectTxs :many
SELECT * FROM tx
WHERE txid IN (sqlc.slice('txids'));

-- name: CleanTxs :exec
DELETE FROM tx;

-- name: InsertUtxo :exec
INSERT INTO utxo (
    txid, vout, script, amount, spent_by, spent, tapscripts, spendable_at, created_at, delay_value, delay_type, tx
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateUtxo :exec
UPDATE utxo
SET
    spent = CASE WHEN :spent IS TRUE THEN TRUE ELSE spent END,
    spent_by = COALESCE(sqlc.narg(spent_by), spent_by),
    created_at = COALESCE(sqlc.narg(created_at), created_at),
    spendable_at = COALESCE(sqlc.narg(spendable_at), spendable_at)
WHERE txid = :txid AND vout = :vout;

-- name: SelectAllUtxos :many
SELECT * from utxo;

-- name: SelectUtxo :one
SELECT *
FROM utxo
WHERE txid = :txid AND vout = :vout;

-- name: DeleteUtxo :exec
DELETE FROM utxo
WHERE txid = :txid AND vout = :vout;

-- name: CleanUtxos :exec
DELETE FROM utxo;