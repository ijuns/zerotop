CREATE TABLE IF NOT EXISTS openvpn_profiles (
  run_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  namespace TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  assigned_ip TEXT NOT NULL,
  allowed_cidr TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  encrypted_client_bundle JSONB NOT NULL,
  encrypted_server_bundle JSONB NOT NULL,
  bootstrap_token_hash CHAR(64) NOT NULL,
  bootstrap_consumed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  CHECK (expires_at > created_at),
  CHECK (length(bootstrap_token_hash) = 64)
);

CREATE INDEX IF NOT EXISTS openvpn_profiles_expiry_idx
  ON openvpn_profiles (expires_at)
  WHERE revoked_at IS NULL;
