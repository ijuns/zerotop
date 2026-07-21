CREATE TABLE IF NOT EXISTS builder_schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS environment_builds (
  id UUID PRIMARY KEY,
  lab_id TEXT NOT NULL,
  lab_version INTEGER NOT NULL CHECK (lab_version > 0),
  requested_by TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL CHECK (request_digest ~ '^sha256:[a-f0-9]{64}$'),
  spec_digest TEXT NOT NULL CHECK (spec_digest ~ '^sha256:[a-f0-9]{64}$'),
  spec_json JSONB NOT NULL,
  resolved_packages_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  namespace TEXT NOT NULL UNIQUE,
  job_name TEXT NOT NULL,
  image_ref TEXT CHECK (image_ref IS NULL OR image_ref !~ '@'),
  image_digest TEXT CHECK (image_digest IS NULL OR image_digest ~ '^sha256:[a-f0-9]{64}$'),
  provenance_json JSONB,
  consumable_json JSONB,
  failure_code TEXT,
  failure_detail TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  deadline_at TIMESTAMPTZ NOT NULL,
  cleaned_at TIMESTAMPTZ,
  UNIQUE (requested_by, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_environment_builds_active
  ON environment_builds (created_at)
  WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS idx_environment_builds_lab ON environment_builds (lab_id, lab_version);

CREATE INDEX IF NOT EXISTS idx_environment_builds_cleanup
  ON environment_builds (finished_at)
  WHERE status IN ('succeeded', 'failed', 'cancelled') AND cleaned_at IS NULL;

CREATE TABLE IF NOT EXISTS builder_audit_events (
  id BIGSERIAL PRIMARY KEY,
  build_id UUID NOT NULL REFERENCES environment_builds(id) ON DELETE RESTRICT,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_status TEXT,
  next_status TEXT NOT NULL,
  details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_builder_audit_build ON builder_audit_events (build_id, created_at);

CREATE OR REPLACE FUNCTION prevent_builder_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'builder_audit_events is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS builder_audit_append_only ON builder_audit_events;
CREATE TRIGGER builder_audit_append_only
  BEFORE UPDATE OR DELETE ON builder_audit_events
  FOR EACH ROW EXECUTE FUNCTION prevent_builder_audit_mutation();
