-- Seasons bound a ranking period. They are data rather than constants so an
-- administrator can open and close one without a deploy.
CREATE TABLE IF NOT EXISTS ranking_seasons (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  starts_at TIMESTAMPTZ NOT NULL,
  ends_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  CONSTRAINT ranking_seasons_range CHECK (ends_at > starts_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS ranking_seasons_slug_lower_unique
  ON ranking_seasons (lower(slug));

CREATE INDEX IF NOT EXISTS ranking_seasons_window_idx
  ON ranking_seasons (starts_at, ends_at);

-- Individual ranking is already consent-based (users.global_ranking_opt_in).
-- Cross-organization ranking exposes headcount and readiness to every viewer,
-- so it needs the same explicit agreement rather than being on by default.
ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS ranking_opt_in BOOLEAN NOT NULL DEFAULT false;
