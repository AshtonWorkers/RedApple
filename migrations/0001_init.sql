PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;

CREATE TABLE run(id TEXT PRIMARY KEY, started INT NOT NULL, ended INT,
  mode TEXT CHECK(mode IN ('macos','ios')), budget_json TEXT NOT NULL,
  state TEXT CHECK(state IN ('armed','running','drained','aborted')) NOT NULL);

CREATE TABLE artifact(id TEXT PRIMARY KEY, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
  bytes INT NOT NULL, created INT NOT NULL,
  ttl_class TEXT CHECK(ttl_class IN ('ephemeral','run','pinned')) NOT NULL);
CREATE INDEX ix_art_ttl ON artifact(ttl_class, created);

CREATE TABLE claim(id TEXT PRIMARY KEY, run_id TEXT REFERENCES run(id),
  type TEXT NOT NULL, value_json TEXT NOT NULL, confidence REAL NOT NULL,
  state TEXT NOT NULL DEFAULT 'limbo'
    CHECK(state IN ('limbo','bound','reviewed','promoted','demoted','parked')),
  dedup_key TEXT NOT NULL, created INT NOT NULL);
CREATE UNIQUE INDEX ux_claim_dedup ON claim(dedup_key);
CREATE INDEX ix_claim_state ON claim(state, created);

CREATE TABLE claim_artifact(claim_id TEXT REFERENCES claim(id),
  artifact_id TEXT REFERENCES artifact(id), role TEXT NOT NULL,
  PRIMARY KEY(claim_id, artifact_id, role));

CREATE TABLE verdict(id INTEGER PRIMARY KEY, claim_id TEXT REFERENCES claim(id),
  reviewer TEXT NOT NULL, agree INT NOT NULL, reason TEXT, created INT NOT NULL);
CREATE INDEX ix_verdict_claim ON verdict(claim_id);

CREATE TABLE "join"(id TEXT PRIMARY KEY, a_claim TEXT REFERENCES claim(id),
  b_claim TEXT REFERENCES claim(id), invariants_json TEXT NOT NULL,
  reliability REAL, lower_bound REAL, state TEXT NOT NULL, created INT NOT NULL);
CREATE INDEX ix_join_state ON "join"(state);

CREATE TABLE work_order(id TEXT PRIMARY KEY, run_id TEXT REFERENCES run(id),
  action TEXT NOT NULL CHECK(action IN ('retarget','reweight','spawn_subfactory',
    'widen_dialect','force_groom','try_gadget_set','escalate_model','demote','park')),
  unit TEXT NOT NULL, payload_json TEXT, ev_cost REAL NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ready','parked','done')), created INT NOT NULL);
CREATE INDEX ix_wo_state ON work_order(state, created);

CREATE TABLE decision(id INTEGER PRIMARY KEY, run_id TEXT, wo_id TEXT,
  trigger_metric TEXT NOT NULL, observed REAL NOT NULL, expected TEXT NOT NULL,
  spent_usd_micro INT NOT NULL CHECK(spent_usd_micro >= 0), created INT NOT NULL);

CREATE TABLE idem(entity TEXT NOT NULL, entity_id TEXT NOT NULL, to_state TEXT NOT NULL,
  created INT NOT NULL, PRIMARY KEY(entity, entity_id, to_state));

CREATE TABLE entry_point(id TEXT PRIMARY KEY, name TEXT NOT NULL,
  reach_from_json TEXT NOT NULL, privilege_delta INT NOT NULL,
  parser_complexity REAL NOT NULL, weight REAL NOT NULL, ring_node TEXT NOT NULL);
CREATE INDEX ix_ep_weight ON entry_point(weight DESC, id);

CREATE TABLE ring_node(id TEXT PRIMARY KEY, ipsw_sha TEXT NOT NULL, build TEXT NOT NULL,
  xcode TEXT NOT NULL, sdk TEXT NOT NULL, webkit_commit TEXT NOT NULL,
  state TEXT NOT NULL, epoch INT NOT NULL);

CREATE TABLE device_profile(udid TEXT PRIMARY KEY, build TEXT,
  tier TEXT CHECK(tier IN ('A','B','C')), state TEXT NOT NULL, thermal TEXT,
  crashes INT DEFAULT 0, exclusion_window TEXT, ring_node TEXT REFERENCES ring_node(id));

CREATE TABLE golden_row(id INTEGER PRIMARY KEY, task_type TEXT NOT NULL,
  packet_json TEXT NOT NULL, reference_json TEXT NOT NULL, released INT NOT NULL);
CREATE INDEX ix_golden_type ON golden_row(task_type, released);

CREATE TABLE packet_log(id TEXT PRIMARY KEY, run_id TEXT, task_type TEXT,
  sha TEXT NOT NULL, tokens_in INT, tokens_out INT, latency_ms INT,
  schema_ok INT, bound_ok INT, relevance REAL, created INT NOT NULL);

CREATE TABLE audit(id INTEGER PRIMARY KEY, entity TEXT NOT NULL, entity_id TEXT NOT NULL,
  from_state TEXT, to_state TEXT, created INT NOT NULL);
CREATE INDEX ix_audit_entity ON audit(entity, entity_id, created);
