CREATE TABLE ring_version(epoch INT PRIMARY KEY,
  nodes_json TEXT NOT NULL, node_count INT NOT NULL, created INT NOT NULL,
  origin TEXT NOT NULL CHECK(origin IN ('advance','attach','promote','rollback')),
  restored_from_epoch INT);
CREATE INDEX ix_ring_version_created ON ring_version(created, epoch);

CREATE TABLE ring_ingest(id TEXT PRIMARY KEY, kind TEXT NOT NULL,
  uri TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INT NOT NULL,
  artifact_id TEXT REFERENCES artifact(id), epoch INT NOT NULL, created INT NOT NULL);
DROP INDEX IF EXISTS ux_ring_ingest_sha;
CREATE UNIQUE INDEX ux_ring_ingest_sha_epoch ON ring_ingest(kind, sha256, epoch);
CREATE INDEX ix_ring_ingest_epoch ON ring_ingest(epoch, created, id);

CREATE TABLE ring_corpus(id TEXT PRIMARY KEY, corpus_key TEXT NOT NULL,
  ring_node_id TEXT NOT NULL REFERENCES ring_node(id), epoch INT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('active','revoked')),
  artifact_id TEXT REFERENCES artifact(id), created INT NOT NULL, updated INT NOT NULL);
CREATE UNIQUE INDEX ux_ring_corpus ON ring_corpus(corpus_key, ring_node_id, epoch);
CREATE INDEX ix_ring_corpus_state ON ring_corpus(state, epoch, ring_node_id);

CREATE TABLE ring_replay(id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
  epoch INT NOT NULL, ring_node_id TEXT NOT NULL REFERENCES ring_node(id),
  corpus_key TEXT NOT NULL, finding_id TEXT NOT NULL, status TEXT NOT NULL,
  detail_json TEXT NOT NULL, created INT NOT NULL);
CREATE UNIQUE INDEX ux_ring_replay ON ring_replay(run_id, ring_node_id, corpus_key, finding_id);
CREATE INDEX ix_ring_replay_epoch ON ring_replay(epoch, created, id);

CREATE TABLE ring_health(ring_node_id TEXT PRIMARY KEY REFERENCES ring_node(id),
  failures INT NOT NULL DEFAULT 0, bad_marked INT NOT NULL DEFAULT 0, updated INT NOT NULL);
