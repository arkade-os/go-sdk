-- name: InsertSwap :exec
INSERT INTO swap (
    id, from_currency, to_currency, amount, status, created_at, updated_at,
    vhtlc_script, funding_txid, redeem_txid, preimage,
    ln_preimage_hash, ln_invoice,
    chain_funding_txid, chain_redeem_txid, chain_address, chain_private_key,
    chain_swap_tree
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SelectSwap :one
SELECT * FROM swap
WHERE id = :id;

-- name: UpdateSwap :execrows
UPDATE swap
SET
    status = :status,
    updated_at = :updated_at,
    funding_txid = :funding_txid,
    redeem_txid = :redeem_txid,
    preimage = :preimage,
    chain_funding_txid = :chain_funding_txid,
    chain_redeem_txid = :chain_redeem_txid
WHERE id = :id;
