-- RED APPLE migration 0002: compounding memory tables (RA-MEM)
CREATE TABLE IF NOT EXISTS memory_prior(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  surface TEXT NOT NULL,
  key TEXT NOT NULL,
  value_json TEXT NOT NULL,
  score REAL NOT NULL CHECK(score BETWEEN 0 AND 1),
  support INT NOT NULL CHECK(support >= 0),
  confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
  state TEXT NOT NULL CHECK(state IN ('active','retired')),
  revision INT NOT NULL CHECK(revision >= 1),
  source_claim TEXT REFERENCES claim(id),
  source_artifact TEXT REFERENCES artifact(id),
  created INT NOT NULL,
  updated INT NOT NULL,
  UNIQUE(kind, surface, key)
);
CREATE INDEX IF NOT EXISTS ix_memory_prior_rank
  ON memory_prior(state, surface, kind, score DESC, support DESC, updated DESC, id);
CREATE INDEX IF NOT EXISTS ix_memory_prior_source ON memory_prior(source_claim);

CREATE TABLE IF NOT EXISTS memory_preference(
  id TEXT PRIMARY KEY,
  task_type TEXT NOT NULL,
  surface TEXT NOT NULL,
  prompt_sha TEXT NOT NULL,
  chosen_json TEXT NOT NULL,
  rejected_json TEXT NOT NULL,
  reward REAL NOT NULL CHECK(reward BETWEEN 0 AND 1),
  rationale TEXT,
  source_claim TEXT REFERENCES claim(id),
  source_artifact TEXT REFERENCES artifact(id),
  created INT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_memory_pref_rank
  ON memory_preference(task_type, surface, reward DESC, created DESC, id);
CREATE INDEX IF NOT EXISTS ix_memory_pref_source ON memory_preference(source_claim);

CREATE TABLE IF NOT EXISTS memory_adapter(
  id TEXT PRIMARY KEY,
  task_type TEXT NOT NULL,
  surface TEXT NOT NULL,
  version INT NOT NULL CHECK(version >= 1),
  parent_id TEXT REFERENCES memory_adapter(id),
  state TEXT NOT NULL CHECK(state IN ('candidate','evaluated','shipped','rejected','retired')),
  config_json TEXT NOT NULL,
  train_pair_count INT NOT NULL CHECK(train_pair_count >= 0),
  eval_score REAL,
  baseline_score REAL,
  golden_rows INT,
  golden_passed INT CHECK(golden_passed IN (0,1) OR golden_passed IS NULL),
  ship_blocked_reason TEXT,
  source_artifact TEXT REFERENCES artifact(id),
  created INT NOT NULL,
  updated INT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_memory_adapter_version
  ON memory_adapter(task_type, surface, version);
CREATE INDEX IF NOT EXISTS ix_memory_adapter_scope
  ON memory_adapter(task_type, surface, state, version DESC);

CREATE TABLE IF NOT EXISTS memory_adapter_pair(
  adapter_id TEXT NOT NULL REFERENCES memory_adapter(id),
  pair_id TEXT NOT NULL REFERENCES memory_preference(id),
  PRIMARY KEY(adapter_id, pair_id)
);
CREATE INDEX IF NOT EXISTS ix_memory_adapter_pair_pair ON memory_adapter_pair(pair_id);

CREATE TABLE IF NOT EXISTS memory_sla(
  surface TEXT PRIMARY KEY,
  target_cost_micro INT NOT NULL CHECK(target_cost_micro >= 0),
  best_cost_micro INT CHECK(best_cost_micro IS NULL OR best_cost_micro >= 0),
  last_cost_micro INT CHECK(last_cost_micro IS NULL OR last_cost_micro >= 0),
  met INT NOT NULL CHECK(met IN (0,1)),
  met_at INT,
  observations INT NOT NULL CHECK(observations >= 0),
  regressions INT NOT NULL CHECK(regressions >= 0),
  flagged INT NOT NULL CHECK(flagged IN (0,1)),
  violation_json TEXT,
  created INT NOT NULL,
  updated INT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_sla_event(
  id TEXT PRIMARY KEY,
  surface TEXT NOT NULL,
  cost_micro INT NOT NULL CHECK(cost_micro >= 0),
  target_cost_micro INT NOT NULL CHECK(target_cost_micro >= 0),
  best_after_micro INT,
  last_after_micro INT,
  met_after INT NOT NULL CHECK(met_after IN (0,1)),
  flagged_after INT NOT NULL CHECK(flagged_after IN (0,1)),
  regression INT NOT NULL CHECK(regression IN (0,1)),
  created INT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_memory_sla_event_surface ON memory_sla_event(surface, created);

CREATE TABLE IF NOT EXISTS memory_retrieval(
  id TEXT PRIMARY KEY,
  run_id TEXT,
  surface TEXT NOT NULL,
  task_type TEXT,
  packet_sha TEXT,
  adapter_id TEXT REFERENCES memory_adapter(id),
  prior_ids_json TEXT NOT NULL,
  pair_ids_json TEXT NOT NULL,
  relevance REAL CHECK(relevance IS NULL OR relevance BETWEEN 0 AND 1),
  created INT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_memory_retrieval_scope
  ON memory_retrieval(surface, task_type, created);
CREATE INDEX IF NOT EXISTS ix_memory_retrieval_packet ON memory_retrieval(packet_sha);
