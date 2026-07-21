-- Platform-admin account suspension. A non-null disabled_at revokes the
-- account: resolveActor rejects the request before any route handler runs.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS disabled_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS disabled_reason TEXT;

CREATE INDEX IF NOT EXISTS users_disabled_idx
  ON users(disabled_at) WHERE disabled_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS organization_memberships_role_idx
  ON organization_memberships(organization_id, role, created_at, user_id);
