PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS run(id TEXT PRIMARY KEY, started INT NOT NULL, ended INT,
  mode TEXT CHECK(mode IN ('macos','ios')), budget_json TEXT NOT NULL,
  state TEXT CHECK(state IN ('armed','running','drained','aborted')) NOT NULL,
  CHECK((state IN ('drained','aborted')) = (ended IS NOT NULL)));

CREATE TABLE IF NOT EXISTS artifact(id TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
  bytes INT NOT NULL, created INT NOT NULL,
  ttl_class TEXT CHECK(ttl_class IN ('ephemeral','run','pinned')) NOT NULL);
CREATE INDEX IF NOT EXISTS ix_art_ttl ON artifact(ttl_class, created);

CREATE TABLE IF NOT EXISTS claim(id TEXT PRIMARY KEY, run_id TEXT REFERENCES run(id),
  type TEXT NOT NULL, value_json TEXT NOT NULL, confidence REAL NOT NULL,
  state TEXT NOT NULL DEFAULT 'limbo'
    CHECK(state IN ('limbo','bound','reviewed','promoted','demoted','parked')),
  dedup_key TEXT NOT NULL, created INT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS ux_claim_dedup ON claim(dedup_key);
CREATE INDEX IF NOT EXISTS ix_claim_state ON claim(state, created);

CREATE TABLE IF NOT EXISTS claim_artifact(claim_id TEXT REFERENCES claim(id),
  artifact_id TEXT REFERENCES artifact(id), role TEXT NOT NULL,
  PRIMARY KEY(claim_id, artifact_id, role));

CREATE TABLE IF NOT EXISTS verdict(id INTEGER PRIMARY KEY, claim_id TEXT REFERENCES claim(id),
  reviewer TEXT NOT NULL, agree INT NOT NULL, reason TEXT, created INT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_verdict_claim ON verdict(claim_id);

CREATE TABLE IF NOT EXISTS "join"(id TEXT PRIMARY KEY, a_claim TEXT REFERENCES claim(id),
  b_claim TEXT REFERENCES claim(id), invariants_json TEXT NOT NULL,
  reliability REAL, lower_bound REAL, state TEXT NOT NULL, created INT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_join_state ON "join"(state);

CREATE TABLE IF NOT EXISTS work_order(id TEXT PRIMARY KEY, run_id TEXT REFERENCES run(id),
  action TEXT NOT NULL CHECK(action IN ('retarget','reweight','spawn_subfactory',
    'widen_dialect','force_groom','try_gadget_set','escalate_model','demote','park')),
  unit TEXT NOT NULL, payload_json TEXT, ev_cost REAL NOT NULL CHECK(ev_cost >= 0),
  state TEXT NOT NULL CHECK(state IN ('ready','parked','done')), created INT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_wo_state ON work_order(state, created);

CREATE TABLE IF NOT EXISTS decision(id INTEGER PRIMARY KEY, run_id TEXT, wo_id TEXT,
  trigger_metric TEXT NOT NULL, observed REAL NOT NULL, expected TEXT NOT NULL,
  spent_usd_micro INT NOT NULL CHECK(spent_usd_micro >= 0), created INT NOT NULL);

CREATE TABLE IF NOT EXISTS idem(entity TEXT NOT NULL, entity_id TEXT NOT NULL, to_state TEXT NOT NULL,
  created INT NOT NULL, PRIMARY KEY(entity, entity_id, to_state));

CREATE TABLE IF NOT EXISTS entry_point(id TEXT PRIMARY KEY, name TEXT NOT NULL,
  reach_from_json TEXT NOT NULL, privilege_delta INT NOT NULL CHECK(privilege_delta >= 0),
  parser_complexity REAL NOT NULL CHECK(parser_complexity >= 0),
  weight REAL NOT NULL CHECK(weight >= 0), ring_node TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_ep_weight ON entry_point(weight DESC, id);

CREATE TABLE IF NOT EXISTS ring_node(id TEXT PRIMARY KEY, ipsw_sha TEXT NOT NULL, build TEXT NOT NULL,
  xcode TEXT NOT NULL, sdk TEXT NOT NULL, webkit_commit TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active','current','bad','retired')),
  epoch INT NOT NULL CHECK(epoch >= 0));

CREATE TABLE IF NOT EXISTS device_profile(udid TEXT PRIMARY KEY, build TEXT,
  tier TEXT CHECK(tier IN ('A','B','C')),
  state TEXT NOT NULL CHECK(state IN ('attached','needs_hand','ready','failed',
    'completed','drained','thermal_pause','budget_exhausted')),
  thermal TEXT CHECK(thermal IN ('nominal','serious','critical')),
  crashes INT DEFAULT 0 CHECK(crashes >= 0), exclusion_window TEXT,
  ring_node TEXT REFERENCES ring_node(id));

CREATE TABLE IF NOT EXISTS golden_row(id INTEGER PRIMARY KEY, task_type TEXT NOT NULL,
  packet_json TEXT NOT NULL, reference_json TEXT NOT NULL, released INT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_golden_type ON golden_row(task_type, released);

CREATE TABLE IF NOT EXISTS packet_log(id TEXT PRIMARY KEY, run_id TEXT, task_type TEXT,
  sha TEXT NOT NULL,
  tokens_in INT CHECK(tokens_in IS NULL OR tokens_in >= 0),
  tokens_out INT CHECK(tokens_out IS NULL OR tokens_out >= 0),
  latency_ms INT CHECK(latency_ms IS NULL OR latency_ms >= 0),
  schema_ok INT CHECK(schema_ok IS NULL OR schema_ok IN (0,1)),
  bound_ok INT CHECK(bound_ok IS NULL OR bound_ok IN (0,1)),
  relevance REAL CHECK(relevance IS NULL OR relevance >= 0),
  created INT NOT NULL) STRICT;

CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, entity TEXT NOT NULL, entity_id TEXT NOT NULL,
  from_state TEXT, to_state TEXT, created INT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_audit_entity ON audit(entity, entity_id, created);
