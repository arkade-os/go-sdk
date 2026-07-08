CREATE TABLE IF NOT EXISTS swap (
  id TEXT PRIMARY KEY,
  amount INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  to_currency TEXT NOT NULL,
  from_currency TEXT NOT NULL,
  status INTEGER NOT NULL CHECK(status IN(0,1,2)),
  swap_type INTEGER NOT NULL,
  invoice TEXT NOT NULL,
  funding_tx_id TEXT NOT NULL,
  redeem_tx_id TEXT NOT NULL,
  vhtlc_contract_script TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_swap (
  id TEXT PRIMARY KEY,
  from_currency TEXT NOT NULL,
  to_currency TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status INTEGER NOT NULL CHECK(status IN(0,1,2,3,4,5,6,7,8)),
  user_lockup_tx_id TEXT,
  server_lockup_tx_id TEXT,
  claim_tx_id TEXT,
  claim_preimage TEXT NOT NULL,
  refund_tx_id TEXT,
  user_btc_lockup_address TEXT,
  error_message TEXT,
  boltz_create_response_json TEXT,
  created_at INTEGER DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS htlc_key (
  address TEXT PRIMARY KEY,
  private_key TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
