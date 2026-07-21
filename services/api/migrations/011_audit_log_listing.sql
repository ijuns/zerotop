-- The existing audit_logs index is keyed by (resource_type, resource_id) for
-- per-resource lookups. The admin console instead pages the whole log newest
-- first and filters by action or actor, which needs its own covering order.
CREATE INDEX IF NOT EXISTS audit_logs_listing_idx
  ON audit_logs(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS audit_logs_action_idx
  ON audit_logs(action, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS audit_logs_actor_idx
  ON audit_logs(actor_user_id, created_at DESC, id DESC);
