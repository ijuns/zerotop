-- "Who" was already recorded; "from where" was not. A null actor_ip means the
-- event had no request context (the expiry sweep and other system actions).
ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS actor_ip TEXT;
