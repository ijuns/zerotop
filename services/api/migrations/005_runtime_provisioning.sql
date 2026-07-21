ALTER TABLE runtime_runs
  DROP CONSTRAINT runtime_runs_status_check,
  ADD CONSTRAINT runtime_runs_status_check
    CHECK (status IN ('provisioning', 'ready', 'stopped', 'expired'));
