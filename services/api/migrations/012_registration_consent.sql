-- Affiliation is collected at signup and is intentionally not unique: many
-- people share one. The public identifier stays `handle`, which is derived
-- from the email rather than typed by the user.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS affiliation TEXT;

-- PIPA requires being able to demonstrate that consent was given, so the
-- agreement time and the document version in force are stored per user.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS terms_agreed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS terms_version TEXT,
  ADD COLUMN IF NOT EXISTS privacy_agreed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS privacy_version TEXT;
