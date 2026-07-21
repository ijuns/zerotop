ALTER TABLE runtime_runs
  DROP CONSTRAINT IF EXISTS runtime_runs_status_check;

ALTER TABLE runtime_runs
  ADD CONSTRAINT runtime_runs_status_check
    CHECK (status IN ('provisioning', 'ready', 'failed', 'stopped', 'expired'));
