CREATE TABLE IF NOT EXISTS contract (
    script               TEXT PRIMARY KEY,
    type                 TEXT NOT NULL,
    label                TEXT NOT NULL DEFAULT '',
    params               TEXT NOT NULL DEFAULT '{}',
    address              TEXT NOT NULL DEFAULT '',
    boarding             TEXT NOT NULL DEFAULT '',
    onchain              TEXT NOT NULL DEFAULT '',
    state                TEXT NOT NULL DEFAULT 'active',
    created_at           INTEGER NOT NULL,
    expires_at           INTEGER,
    metadata             TEXT NOT NULL DEFAULT '{}',
    tapscripts           TEXT NOT NULL DEFAULT '[]',
    boarding_tapscripts  TEXT NOT NULL DEFAULT '[]',
    delay_type           INTEGER NOT NULL DEFAULT 0,
    delay_value          INTEGER NOT NULL DEFAULT 0,
    boarding_delay_type  INTEGER NOT NULL DEFAULT 0,
    boarding_delay_value INTEGER NOT NULL DEFAULT 0
);
