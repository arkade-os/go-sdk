-- name: InsertSwap :execrows
INSERT OR IGNORE INTO swap (
    id, amount, timestamp, to_currency, from_currency, status,
    invoice, funding_tx_id, redeem_tx_id, vhtlc_contract_script
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SelectSwap :one
SELECT * FROM swap
WHERE id = :id;

-- name: UpdateSwap :execrows
UPDATE swap
SET
    status = :status,
    funding_tx_id = COALESCE(sqlc.narg('funding_tx_id'), funding_tx_id),
    redeem_tx_id = COALESCE(sqlc.narg('redeem_tx_id'), redeem_tx_id)
WHERE id = :id;

-- name: InsertChainSwap :exec
INSERT INTO chain_swap (
    id, from_currency, to_currency, amount, status, user_lockup_tx_id,
    server_lockup_tx_id, claim_tx_id, refund_tx_id,
    user_btc_lockup_address, btc_htlc_private_key,
    error_message, boltz_create_response_json,
    created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SelectChainSwap :one
SELECT * FROM chain_swap
WHERE id = :id;

-- name: UpdateChainSwap :execrows
UPDATE chain_swap
SET
    status = :status,
    user_lockup_tx_id = :user_lockup_tx_id,
    server_lockup_tx_id = :server_lockup_tx_id,
    claim_tx_id = :claim_tx_id,
    refund_tx_id = :refund_tx_id,
    btc_htlc_private_key = COALESCE(sqlc.narg('btc_htlc_private_key'), btc_htlc_private_key),
    error_message = :error_message,
    boltz_create_response_json = :boltz_create_response_json,
    updated_at = :updated_at
WHERE id = :id;
