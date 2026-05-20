CREATE INDEX IF NOT EXISTS idx_vtxo_created_at_txid_vout
    ON vtxo (created_at DESC, txid DESC, vout DESC);
