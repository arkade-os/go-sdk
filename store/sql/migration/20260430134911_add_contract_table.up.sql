CREATE TABLE IF NOT EXISTS contract (
  script TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  label TEXT,
  address TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  owner_key_id TEXT NOT NULL,
  owner_key TEXT NOT NULL,
  signer_key TEXT NOT NULL,
  exit_delay INTEGER NOT NULL,
  is_onchain BOOLEAN NOT NULL,
  extra_params TEXT,
  metadata TEXT
);