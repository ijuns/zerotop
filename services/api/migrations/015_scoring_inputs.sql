-- Inputs the season scoring policy needs but that were not being stored.
-- Difficulty sets the base points; hints reduce the score. Time is derived
-- from the run window, so it needs no column.
ALTER TABLE labs
  ADD COLUMN IF NOT EXISTS difficulty TEXT NOT NULL DEFAULT 'intermediate';

ALTER TABLE labs
  ADD CONSTRAINT labs_difficulty_check
  CHECK (difficulty IN ('beginner', 'intermediate', 'advanced', 'expert'));

-- Hints are counted, not fabricated: rows written before this default to 0,
-- which the policy treats as no penalty rather than an assumed one.
ALTER TABLE challenge_results
  ADD COLUMN IF NOT EXISTS hints_used INTEGER NOT NULL DEFAULT 0
  CHECK (hints_used >= 0);
