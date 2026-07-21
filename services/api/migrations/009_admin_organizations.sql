CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS join_code_hash TEXT;

UPDATE organizations
   SET join_code_hash = encode(digest(lower(btrim(join_code)), 'sha256'), 'hex')
 WHERE join_code_hash IS NULL;

ALTER TABLE organizations
  ALTER COLUMN join_code_hash SET NOT NULL;

DROP INDEX IF EXISTS organizations_join_code_lower_unique;

ALTER TABLE organizations
  DROP COLUMN IF EXISTS join_code;

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS join_code_rotated_at TIMESTAMPTZ;

UPDATE organizations
   SET join_code_rotated_at = created_at
 WHERE join_code_rotated_at IS NULL;

ALTER TABLE organizations
  ALTER COLUMN join_code_rotated_at SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS organizations_join_code_hash_unique
  ON organizations(join_code_hash);

ALTER TABLE labs
  ADD COLUMN IF NOT EXISTS admin_quarantined_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS admin_quarantined_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS admin_quarantine_reason TEXT;

CREATE INDEX IF NOT EXISTS users_admin_list_idx
  ON users(platform_role, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS labs_admin_list_idx
  ON labs(validation_status, team_type, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS runtime_runs_admin_list_idx
  ON runtime_runs(status, access_method, created_at DESC, id DESC);
