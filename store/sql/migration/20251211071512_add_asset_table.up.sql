CREATE TABLE IF NOT EXISTS asset (
  asset_id TEXT PRIMARY KEY,
  metadata TEXT NULL
);

CREATE TABLE IF NOT EXISTS asset_control (
  asset_id TEXT NOT NULL,
  control_asset_id TEXT NOT NULL,
  PRIMARY KEY (asset_id, control_asset_id),
  FOREIGN KEY (asset_id) REFERENCES asset(asset_id),
  FOREIGN KEY (control_asset_id) REFERENCES asset(asset_id)
);

CREATE TABLE IF NOT EXISTS asset_vtxo (
  vtxo_txid TEXT NOT NULL,
  vtxo_vout INTEGER NOT NULL,
  asset_id TEXT NOT NULL,
  amount INTEGER NOT NULL,
  PRIMARY KEY (vtxo_txid, vtxo_vout, asset_id),
  FOREIGN KEY (vtxo_txid, vtxo_vout) REFERENCES vtxo(txid, vout),
  FOREIGN KEY (asset_id) REFERENCES asset(asset_id)
);

CREATE VIEW IF NOT EXISTS asset_vtxo_vw AS
SELECT vtxo.*, asset_vtxo.asset_id, asset_vtxo.amount as asset_amount
FROM vtxo LEFT JOIN asset_vtxo ON vtxo.txid = asset_vtxo.vtxo_txid AND vtxo.vout = asset_vtxo.vtxo_vout;

ALTER TABLE tx ADD COLUMN asset_packet TEXT;