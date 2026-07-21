ALTER TABLE labs
  ADD COLUMN grading_config_json JSONB NOT NULL DEFAULT '{"questions":[]}'::jsonb;

CREATE TABLE trusted_grade_evidence (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runtime_runs(id) ON DELETE CASCADE,
  question_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('elk', 'ai_rubric')),
  passed BOOLEAN NOT NULL,
  score_ratio DOUBLE PRECISION NOT NULL CHECK (score_ratio >= 0 AND score_ratio <= 1),
  policy_version TEXT NOT NULL,
  evidence_reference TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE (run_id, question_id)
);

CREATE UNIQUE INDEX challenge_results_run_unique
  ON challenge_results(run_id) WHERE run_id IS NOT NULL;

CREATE TABLE score_events (
  id TEXT PRIMARY KEY,
  result_id TEXT NOT NULL REFERENCES challenge_results(id) ON DELETE RESTRICT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  organization_id TEXT REFERENCES organizations(id) ON DELETE RESTRICT,
  event_type TEXT NOT NULL CHECK (event_type = 'challenge.graded'),
  points_delta INTEGER NOT NULL CHECK (points_delta >= 0),
  max_points INTEGER NOT NULL CHECK (max_points > 0),
  payload_json JSONB NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX score_events_user_time_idx ON score_events(user_id, occurred_at);
CREATE INDEX score_events_organization_time_idx
  ON score_events(organization_id, occurred_at);

CREATE FUNCTION reject_score_event_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'score_events are append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER score_events_no_update
  BEFORE UPDATE ON score_events
  FOR EACH ROW EXECUTE FUNCTION reject_score_event_mutation();

CREATE TRIGGER score_events_no_delete
  BEFORE DELETE ON score_events
  FOR EACH ROW EXECUTE FUNCTION reject_score_event_mutation();
