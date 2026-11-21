# RA-SRF -> claim-ledger `entry_point` rewire

PR #5 keeps RA-SRF self-contained behind `EntryPointStore` (`ra/srf/store.py`).
PR #8 owns the real claim ledger and already has the `entry_point` table:

```sql
CREATE TABLE entry_point(id TEXT PRIMARY KEY, name TEXT NOT NULL,
  reach_from_json TEXT NOT NULL, privilege_delta INT NOT NULL,
  parser_complexity REAL NOT NULL, weight REAL NOT NULL, ring_node TEXT NOT NULL);
CREATE INDEX ix_ep_weight ON entry_point(weight DESC, id);
```

## Payload mapping

RA-SRF rows use `id`; PR #8's `_op_insert_entry_point` expects `entry_point_id`
and writes it to the `id` column. `ra.srf.store.ledger_entry_point_payload(row)`
is the single mapping point:

| RA-SRF row key | ledger `insert_entry_point` payload | `entry_point` column |
| --- | --- | --- |
| `id` | `entry_point_id` | `id` |
| `name` | `name` | `name` |
| `reach_from_json` | `reach_from_json` | `reach_from_json` |
| `privilege_delta` | `privilege_delta` | `privilege_delta` |
| `parser_complexity` | `parser_complexity` | `parser_complexity` |
| `weight` | `weight` | `weight` |
| `ring_node` | `ring_node` | `ring_node` |

`format_spec` is intentionally not a column: it is covered by the deterministic
`id` hash and by `parser_complexity`. Do not add a column without a schema
migration on the PR #8 trunk.

## Replace semantics gap

RA-SRF `replace_ring_node(ring_node, rows)` is delete-then-insert for one ring.
PR #8 currently exposes `_op_insert_entry_point` but no entry-point delete or
ring-scoped replace operation. A clean integration should add one ledger actor
operation, for example:

```text
replace_entry_points_for_ring_node
  payload: {"ring_node": "...", "entry_points": [ledger_entry_point_payload(row), ...]}
```

implemented as `DELETE FROM entry_point WHERE ring_node = ?` followed by the
payload inserts in the same actor transaction. This is required because PR #8's
`insert_entry_point` is a plain `INSERT`: RA-SRF row ids are deterministic, so a
second identical compile would otherwise hit a primary-key conflict, and removed
services would leave stale rows behind.

Until that operation exists, do **not** emulate replace with global deletes or
`INSERT OR REPLACE` from outside the single-writer actor; that bypasses the
ledger's write serialization.

## Readback contract

Consumers should read with the same deterministic order RA-SRF uses:

```sql
SELECT id, name, reach_from_json, privilege_delta, parser_complexity, weight, ring_node
FROM entry_point
WHERE ring_node = ?
ORDER BY weight DESC, id ASC;
```

`reach_from_json` is compact sorted JSON produced by `ra.srf.models.reach_from_json`.
`privilege_delta` is clamped to `0..5`; `parser_complexity` is in `[0, 1]`, while
`weight` is not bounded to `[0, 1]` because `privilege_delta` can be up to 5.

## macOS-only real-cache verification still owed

Linux CI uses synthetic Mach-O/dyld-cache fixtures only. On macOS, verify the real
cache path end to end:

```bash
PYTHONPATH=. python3 -m ra.srf \
  --cache '/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e' \
  --db /tmp/ra_srf_arm64e.sqlite --top 20
```

Expected proof points: non-zero `images_scanned`, `strings_scanned`,
`service_candidates`, and `entry_points`; deterministic `sha256` across two runs;
rows contain both `image:` and `sandbox-profile:` reach records where profiles are
present; SQLite replace for a ring node does not leak into another ring.
