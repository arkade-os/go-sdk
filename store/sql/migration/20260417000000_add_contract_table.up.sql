CREATE TABLE IF NOT EXISTS contract (
    script      TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    params      TEXT NOT NULL DEFAULT '{}',
    address     TEXT NOT NULL DEFAULT '',
    is_onchain  INTEGER NOT NULL DEFAULT 0,
    state       TEXT NOT NULL DEFAULT 'active',
    created_at  INTEGER NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
);
