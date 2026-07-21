CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  handle TEXT NOT NULL,
  display_name TEXT NOT NULL,
  password_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT users_email_ci_unique UNIQUE (email),
  CONSTRAINT users_handle_ci_unique UNIQUE (handle)
);

CREATE UNIQUE INDEX users_email_lower_unique ON users (lower(email));
CREATE UNIQUE INDEX users_handle_lower_unique ON users (lower(handle));

CREATE TABLE organizations (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  join_code TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX organizations_slug_lower_unique ON organizations (lower(slug));
CREATE UNIQUE INDEX organizations_join_code_lower_unique ON organizations (lower(join_code));

CREATE TABLE organization_memberships (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (organization_id, user_id)
);

CREATE TABLE labs (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  organization_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  team_type TEXT NOT NULL CHECK (team_type IN ('blue', 'red')),
  question_types_json JSONB NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('ubuntu', 'kali')),
  access_modes_json JSONB NOT NULL,
  validation_status TEXT NOT NULL DEFAULT 'draft'
    CHECK (validation_status IN ('draft', 'validated', 'quarantined')),
  config_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE validation_evidence (
  id TEXT PRIMARY KEY,
  lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
  check_name TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('pass', 'fail')),
  details_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (lab_id, check_name)
);

CREATE TABLE runtime_runs (
  id TEXT PRIMARY KEY,
  lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('ready', 'stopped', 'expired')),
  environment TEXT NOT NULL CHECK (environment IN ('ubuntu', 'kali')),
  access_method TEXT NOT NULL CHECK (access_method IN ('browser_desktop', 'openvpn', 'both')),
  browser_url TEXT,
  openvpn_profile_json JSONB,
  expires_at TIMESTAMPTZ NOT NULL,
  metadata_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE challenge_results (
  id TEXT PRIMARY KEY,
  lab_id TEXT NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  score INTEGER NOT NULL CHECK (score >= 0),
  max_score INTEGER NOT NULL CHECK (max_score > 0 AND score <= max_score),
  answers_json JSONB NOT NULL,
  evidence_json JSONB NOT NULL,
  completed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE idempotency_records (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  operation TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  response_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, operation, idempotency_key)
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  metadata_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX organization_memberships_organization_idx
  ON organization_memberships(organization_id);
CREATE INDEX labs_owner_idx ON labs(owner_user_id);
CREATE INDEX labs_organization_idx ON labs(organization_id);
CREATE INDEX validation_evidence_lab_idx ON validation_evidence(lab_id);
CREATE INDEX runtime_runs_lab_user_idx ON runtime_runs(lab_id, user_id);
CREATE INDEX challenge_results_lab_user_idx ON challenge_results(lab_id, user_id);
CREATE INDEX audit_logs_resource_idx
  ON audit_logs(resource_type, resource_id, created_at);
