-- Policy decisions need the schedulable unit for persisted remedy-failure state.
ALTER TABLE decision ADD COLUMN unit TEXT;
CREATE INDEX IF NOT EXISTS ix_decision_unit ON decision(unit, created);
