ALTER TABLE runtime_runs
  DROP CONSTRAINT IF EXISTS runtime_runs_access_method_check;

ALTER TABLE runtime_runs
  ADD CONSTRAINT runtime_runs_access_method_check
    CHECK (access_method IN ('browser_desktop', 'openvpn', 'both'));
