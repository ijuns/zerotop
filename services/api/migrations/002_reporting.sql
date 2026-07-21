ALTER TABLE users
  ADD COLUMN platform_role TEXT NOT NULL DEFAULT 'user'
    CHECK (platform_role IN ('user', 'platform_admin')),
  ADD COLUMN global_ranking_opt_in BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE organization_memberships
  DROP CONSTRAINT organization_memberships_role_check,
  ADD CONSTRAINT organization_memberships_role_check
    CHECK (role IN ('owner', 'org_admin', 'member'));

ALTER TABLE challenge_results
  ADD COLUMN run_id TEXT REFERENCES runtime_runs(id) ON DELETE SET NULL,
  ADD COLUMN skills_json JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX challenge_results_run_idx ON challenge_results(run_id);
