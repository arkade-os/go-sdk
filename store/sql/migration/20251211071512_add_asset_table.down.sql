DROP VIEW IF EXISTS asset_vtxo_vw;
DROP TABLE IF EXISTS asset_vtxo;
DROP TABLE IF EXISTS asset;

ALTER TABLE tx DROP COLUMN asset_packet;
ALTER TABLE tx DROP COLUMN asset_packet_version;