-- name: InsertSwap :execrows
INSERT OR IGNORE INTO swap (
    id, amount, timestamp, to_currency, from_currency, status, swap_type,
    invoice, funding_tx_id, redeem_tx_id, vhtlc_contract_script
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateSwap :execrows
UPDATE swap
SET
    status = :status,
    redeem_tx_id = :redeem_tx_id
WHERE id = :id;

-- name: InsertChainSwap :exec
INSERT INTO chain_swap (
    id, from_currency, to_currency, amount, status, user_lockup_tx_id,
    server_lockup_tx_id, claim_tx_id, claim_preimage, refund_tx_id,
    user_btc_lockup_address, error_message, boltz_create_response_json,
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
    error_message = :error_message,
    boltz_create_response_json = :boltz_create_response_json,
    updated_at = :updated_at
WHERE id = :id;

-- name: UpsertHTLCKey :exec
INSERT INTO htlc_key (address, private_key, created_at)
VALUES (?, ?, ?)
ON CONFLICT(address) DO UPDATE SET
    private_key = excluded.private_key,
    created_at = excluded.created_at;

-- name: SelectHTLCKey :one
SELECT * FROM htlc_key
WHERE address = :address;
