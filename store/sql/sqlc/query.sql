-- name: InsertVtxo :exec
INSERT INTO vtxo (
    txid, vout, script, amount, commitment_txids, spent_by, spent, preconfirmed, expires_at, created_at, swept, unrolled, settled_by, ark_txid
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SpendVtxo :exec
UPDATE vtxo
SET
    spent = true,
    spent_by = :spent_by,
    ark_txid = COALESCE(sqlc.narg(ark_txid), ark_txid)
WHERE txid = :txid AND vout = :vout;

-- name: SettleVtxo :exec
UPDATE vtxo
SET
    spent = true,
    spent_by = :spent_by,
    settled_by = COALESCE(sqlc.narg(settled_by), settled_by)
WHERE txid = :txid AND vout = :vout;

-- name: SweepVtxo :exec
UPDATE vtxo
SET swept = true
WHERE txid = :txid AND vout = :vout;

-- name: UnrollVtxo :exec
UPDATE vtxo
SET unrolled = true
WHERE txid = :txid AND vout = :vout;

-- name: SelectVtxo :many
SELECT *
FROM asset_vtxo_vw
WHERE txid = :txid AND vout = :vout;

-- name: SelectSpendableOrRecoverableVtxos :many
SELECT * FROM asset_vtxo_vw
WHERE spent = false AND unrolled = false;

-- name: GetVtxos :many
-- Cursor-based keyset pagination over VTXOs. Two stages.
-- Stage 1, page_keys CTE, scans the base vtxo table (one row per VTXO so
-- LIMIT counts VTXOs not asset rows), applies status and asset filters,
-- applies the cursor predicate, sorts by (created_at DESC, txid DESC, vout
-- DESC) using the matching composite index for an O(log n + limit) scan,
-- and LIMITs at the SQL layer. Stage 2 INNER JOINs the paged keys against
-- asset_vtxo_vw to hydrate assets in one round-trip; applying LIMIT to the
-- view directly would cut multi-asset VTXOs mid-way.
-- The caller passes (user_limit + 1) as limit_plus_one. The extra row is
-- a has-more sentinel; if SQL returns more than user_limit rows the caller
-- trims the last one and uses its outpoint as the next cursor.
-- status_filter accepts NULL (no filter), spendable (spent=false AND
-- unrolled=false), or spent (spent=true OR unrolled=true). asset_id uses
-- EXISTS rather than JOIN so the row count stays at VTXO count. The cursor
-- predicate uses SQL row-value comparison which is the canonical
-- composite-key keyset idiom. CAST wrappers around sqlc.narg are required
-- so sqlc emits typed nullable Go args instead of interface{}.
-- WARNING: do not put inline -- comments inside the query body below;
-- sqlc's query splitter breaks downstream queries when the GetVtxos body
-- contains inline comments. Keep all docs here in the header.
WITH page_keys AS (
    SELECT txid, vout, created_at FROM vtxo
    WHERE
        (CAST(sqlc.narg(status_filter) AS TEXT) IS NULL
            OR (CAST(sqlc.narg(status_filter) AS TEXT) = 'spendable' AND spent = false AND unrolled = false)
            OR (CAST(sqlc.narg(status_filter) AS TEXT) = 'spent'     AND (spent = true OR unrolled = true)))
        AND (CAST(sqlc.narg(asset_id) AS TEXT) IS NULL OR EXISTS (
            SELECT 1 FROM asset_vtxo av
            WHERE av.vtxo_txid = vtxo.txid AND av.vtxo_vout = vtxo.vout
                  AND av.asset_id = CAST(sqlc.narg(asset_id) AS TEXT)
        ))
        AND (CAST(sqlc.narg(cursor_created_at) AS INTEGER) IS NULL
            OR (vtxo.created_at, vtxo.txid, vtxo.vout) < (
                CAST(sqlc.narg(cursor_created_at) AS INTEGER),
                CAST(sqlc.narg(cursor_txid) AS TEXT),
                CAST(sqlc.narg(cursor_vout) AS INTEGER)
            ))
    ORDER BY created_at DESC, txid DESC, vout DESC
    LIMIT sqlc.arg(limit_plus_one)
)
SELECT v.*
FROM asset_vtxo_vw v
INNER JOIN page_keys pk ON v.txid = pk.txid AND v.vout = pk.vout
ORDER BY pk.created_at DESC, pk.txid DESC, pk.vout DESC;

-- name: CleanVtxos :exec
DELETE FROM vtxo;

-- name: UpsertAsset :exec
INSERT INTO asset (asset_id, control_asset_id, metadata) VALUES (:asset_id, sqlc.narg(control_asset_id), sqlc.narg(metadata))
ON CONFLICT (asset_id) DO UPDATE SET
    control_asset_id = COALESCE(EXCLUDED.control_asset_id, control_asset_id),
    metadata = COALESCE(EXCLUDED.metadata, metadata);

-- name: InsertAssetVtxo :exec
INSERT INTO asset_vtxo (vtxo_txid, vtxo_vout, asset_id, amount) VALUES (?, ?, ?, ?);

-- name: SelectAsset :one
SELECT * FROM asset WHERE asset_id = :asset_id;

-- name: CleanAssetVtxos :exec
DELETE FROM asset_vtxo;

-- name: CleanAssets :exec
DELETE FROM asset;

-- name: InsertTx :exec
INSERT INTO tx (
    txid, txid_type, amount, type, created_at, hex, settled_by, settled, asset_packet
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

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

-- name: SelectUtxosByTxid :many
SELECT *
FROM utxo
WHERE txid = :txid;

-- name: DeleteUtxo :exec
DELETE FROM utxo
WHERE txid = :txid AND vout = :vout;

-- name: CleanUtxos :exec
DELETE FROM utxo;

-- name: InsertContract :exec
INSERT INTO contract (
    script, type, label, address, state, created_at, params, key_index, metadata
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SelectAllContracts :many
SELECT * FROM contract;

-- name: SelectContractsByScripts :many
SELECT * FROM contract
WHERE script IN (sqlc.slice('scripts'));

-- name: SelectContractsByType :many
SELECT * FROM contract
WHERE type = :type;

-- name: SelectContractsByState :many
SELECT * FROM contract
WHERE state = :state;

-- name: SelectLatestContractByType :one
SELECT * FROM contract
WHERE type = :contract_type ORDER BY key_index DESC LIMIT 1;

-- name: UpdateContractState :execrows
UPDATE contract
SET
    state = :state
WHERE script = :script;

-- name: CleanContracts :exec
DELETE FROM contract;