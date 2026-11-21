# Foundry ledger rewire (RA-FND ↔ RA-LED)

PR #7 keeps a small `FoundryStore` protocol plus `JsonFoundryStore` so the
Foundry can land before the M0 ledger. PR #8 already has the normative ledger:
one writer actor, content-addressed `artifact` rows, claims, work orders, and
audit/idempotency rows. When the integration branch combines #8 and #7, the
Foundry must stop persisting to `foundry_state.json` and rewire through that
ledger.

## Conflict resolution

PR #8 contains only `ra/foundry/__init__.py` as a layout placeholder. PR #7
contains the real package. The merge resolution is to keep PR #7's
`ra/foundry/*` implementation and discard PR #8's one-line skeleton. No PR #8
code imports `ra.foundry` today, so this is an add/add conflict on
`__init__.py`, not a semantic conflict.

## Mapping

| Foundry concept | Ledger target | Notes |
|---|---|---|
| CAS object bytes | `artifact` row via `Ledger.put_artifact` / claim artifact link | Ledger artifact id is `art_<sha256>`; Foundry CAS id is the bare sha256. Store the bare digest in `value_json` or derive `art_` + digest when linking. |
| Measurement artifact | `artifact(kind="foundry_measurement")` | JSON payload already contains measurements, decision, harness id, and format. |
| Accepted harness bundle | `artifact(kind="foundry_harness_bundle")` | Tar bundle from `pack_harness_files`; last-good pointer stays in Foundry state. |
| `AttemptRecord` | one `claim` per attempt or one state claim with append-only artifacts | Preferred: one `harness` claim per harness id whose `value_json` is the serialized `FoundryState`; each attempt adds an artifact link with role `attempt`. This preserves I1/I3 because every state update is artifact-bound and idempotent by attempt id. |
| Reprompt packet | `packet_log` row and/or work-order payload | `task_type="harness_synth"` already matches Appendix D. Store packet sha in `packet_log`, and enqueue `widen_dialect`/`spawn_subfactory` only through policy, not directly from Foundry. |
| Parked harness | claim state `parked` | Foundry `parked` maps to ledger `parked`; `candidate`/`accepted`/`reprompt` are not ledger claim states and must live inside `value_json`, not the claim state column. |

## Required PR #8 changes before rewiring

1. Extend `CLAIM_TYPES` in `ra/ledger/db.py` with `"harness"` (or add a
   dedicated foundry table in a later migration). The current enum rejects
   harness claims.
2. Keep `JsonFoundryStore` only as a test/dev fallback. Add
   `LedgerFoundryStore` implementing `FoundryStore` on top of `Ledger` once
   the claim type exists. `load` reads the harness claim's `value_json`;
   `save` writes a new state artifact and updates the claim through the
   single-writer actor.
3. Do not import `ra.ledger` from `ra.foundry` until the integration branch
   contains both packages; PR #7 must remain independently testable.

Until then, `FoundryStore` remains the seam: the Foundry already depends only
on `load`/`save`/`list_ids`, so swapping `JsonFoundryStore` for
`LedgerFoundryStore` is a constructor change, not a Foundry rewrite.
