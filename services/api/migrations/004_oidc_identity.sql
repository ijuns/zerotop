ALTER TABLE users
  ADD COLUMN external_subject TEXT;

CREATE UNIQUE INDEX users_external_subject_unique
  ON users(external_subject) WHERE external_subject IS NOT NULL;
