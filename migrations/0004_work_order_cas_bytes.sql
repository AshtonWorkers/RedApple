-- Policy shedding needs a cheap CAS budget check on ready work orders.
ALTER TABLE work_order ADD COLUMN cas_bytes INT NOT NULL DEFAULT 0;
UPDATE work_order SET cas_bytes = CASE
  WHEN json_valid(payload_json) THEN CASE
    WHEN json_type(payload_json, '$.cas_bytes') = 'integer'
         AND CAST(json_extract(payload_json, '$.cas_bytes') AS INTEGER) >= 0
    THEN CAST(json_extract(payload_json, '$.cas_bytes') AS INTEGER)
    ELSE 0 END
  ELSE 0 END
WHERE payload_json IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_wo_ready_cas ON work_order(state, cas_bytes);
