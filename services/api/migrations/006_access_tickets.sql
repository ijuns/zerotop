CREATE TABLE access_tickets (
  ticket_hash TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runtime_runs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('desktop', 'openvpn')),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX access_tickets_expiry_idx
  ON access_tickets(expires_at) WHERE consumed_at IS NULL;
