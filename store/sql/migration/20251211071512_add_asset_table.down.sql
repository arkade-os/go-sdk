DROP VIEW IF EXISTS asset_vtxo_vw;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS asset_control;
DROP TABLE IF EXISTS asset_vtxo;

ALTER TABLE tx DROP COLUMN asset_packet;
ALTER TABLE tx DROP COLUMN asset_packet_version;