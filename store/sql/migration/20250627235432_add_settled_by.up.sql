ALTER TABLE vtxo ADD COLUMN settled_by TEXT;
ALTER TABLE vtxo DROP COLUMN redeemed;
ALTER TABLE vtxo ADD COLUMN unrolled BOOLEAN NOT NULL;
ALTER TABLE vtxo ADD COLUMN ark_txid TEXT;
ALTER TABLE tx ADD COLUMN settled_by TEXT;