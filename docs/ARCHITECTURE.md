# RedApple architecture

RedApple is a hardware-free core for Apple Security Bounty research. M0 is the spine: local ledger, lanes, PRESS compiler/harness, policy engine, CLI, and load harness.

## Components

- `ra/ledger`: single-writer SQLite actor. Stores claims, artifacts, joins, work orders, decisions, runs, ring nodes, entry points, device profiles, golden rows, packet logs, and audit/idempotency rows. WAL mode, busy timeout, batched commits, ULID claim IDs, dedup keys, TTL artifact classes, retention and invariant checks.
- `ra/lanes`: lane interface (`base.py`), fake lane (`fleet/fake.py`), and version ring manager (`fleet/ring.py`). Lanes produce crashes/artifacts; the ring manager advances macOS/iOS build nodes and records boot failures.
- `ra/press`: packet compiler (`packets.py`), routing budgets (`routing.py`), offline replay queue and DeepSeek client (`client.py`), scripted/local harness (`harness.py`), golden corpus gate (`golden.py`).
- `ra/policy`: closed action vocabulary, EV ranking/shedding, executor caps, atomic dispatch gating in the ledger.
- `ra/obs`: retention sweeps and health checks.
- `ra/cli`: `ra run|attach|retain|replay|golden|doctor`. Errors are JSON on stderr with exit 2 for user/config errors.

## Data flow

1. A lane feeds a crash payload.
2. Triage/packet compilation builds a PRESS packet within the route byte budget.
3. `PressHarness` either calls DeepSeek or, with `local_only`, appends the packet to the replay queue.
4. Claims are written through `Ledger.create_claim` as one batched operation: artifact rows, claim row, and claim-artifact links commit together or fail per operation savepoint.
5. Policy ranks candidates and dispatches ready work orders through `Ledger.dispatch_work_order`, which checks run-scoped spend and marks the order done in the same transaction as the decision row.
6. `ra retain`/retention sweep deletes only unprotected TTL-expired artifacts while preserving pinned artifacts, promoted claim evidence, live joins, and the configured min-set.

## Invariants

- I1: every non-limbo claim has at least one artifact link.
- Claims move only through the documented state machine; repeated transitions are idempotent.
- Artifact IDs are content-addressed (`art_<sha256>`), `sha256` must match, and TTL class can only move upward in rank (`ephemeral < run < pinned`).
- Retention never deletes pinned artifacts, promoted claim evidence, artifacts linked to live joins, or so many artifacts that the min-set is violated.
- Policy dispatch is atomic: budget check, work-order state transition, and decision insert happen in one ledger transaction.
- PRESS replay/doctor/golden paths return clean `FORMAT_FAIL`/`CONFIG_INVALID` errors instead of tracebacks.
