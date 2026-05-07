CREATE TABLE IF NOT EXISTS contract (
  script TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  label TEXT,
  address TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  params TEXT NOT NULL,
  key_index INTEGER NOT NULL,
  metadata TEXT
);