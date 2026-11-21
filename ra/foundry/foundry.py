"""Harness Foundry orchestration (RA-FND).

I/O is async; the acceptance decision itself is pure logic in acceptance.py.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from .acceptance import evaluate_acceptance
from .cas import ContentAddressedStore
from .dialect import load_dialect_file
from .errors import HarnessRejected
from .models import (
    AcceptanceDecision,
    AcceptanceMeasurements,
    AttemptRecord,
    Dialect,
    FoundryOutcome,
    FoundryState,
    HarnessSpec,
    RollbackResult,
    now_ms,
)
from .store import FoundryStore

ROLLBACK_BUDGET_MS = 10_000
PARK_AFTER_ATTEMPTS = 3


class Foundry:
    """Mechanical harness acceptance, defect accounting, and CAS rollback."""

    def __init__(self, store: FoundryStore, cas: ContentAddressedStore) -> None:
        self.store = store
        self.cas = cas

    async def load_dialect(self, spec: HarnessSpec) -> Dialect:
        """Load and validate the dialect shipped beside a harness."""
        return await asyncio.to_thread(load_dialect_file, spec.dialect_path())

    def _reprompt(
        self,
        spec: HarnessSpec,
        measurements: AcceptanceMeasurements,
        decision: AcceptanceDecision,
        failing_artifact_id: str,
    ) -> dict:
        return {
            "task_type": "harness_synth",
            "harness_id": spec.id,
            "format": spec.format,
            "failing_artifact_id": failing_artifact_id,
            "failing_measurement": measurements.to_dict(),
            "decision": decision.to_dict(),
            "instruction": (
                "Regenerate the harness so RA-FND-001 passes mechanically: "
                "compiles, edges/sec >= 60% of the surface median, and "
                "parser malloc is reachable in the coverage map."
            ),
        }

    async def submit(
        self, spec: HarnessSpec, measurements: AcceptanceMeasurements
    ) -> FoundryOutcome:
        """Validate the dialect, gate acceptance, and persist the attempt."""
        await self.load_dialect(spec)
        decision = evaluate_acceptance(measurements)

        state = await self.store.load(spec.id)
        if state is None:
            state = FoundryState(harness_id=spec.id, format=spec.format)
        if state.state == "parked":
            raise HarnessRejected(f"harness {spec.id} is parked")

        measurement_payload = {
            "harness_id": spec.id,
            "format": spec.format,
            "created_ms": now_ms(),
            "measurements": measurements.to_dict(),
            "decision": decision.to_dict(),
        }
        measurement_artifact_id = await self.cas.put(
            json.dumps(
                measurement_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        artifact_ids = [measurement_artifact_id]

        attempt = AttemptRecord(
            id=f"{spec.id}:a{len(state.attempts) + 1:03d}",
            harness_id=spec.id,
            accepted=decision.accepted,
            created_ms=now_ms(),
            measurements=measurements.to_dict(),
            artifact_ids=list(artifact_ids),
            reasons=list(decision.reasons),
        )

        if decision.accepted:
            files = await asyncio.to_thread(spec.bundle_files)
            bundle_id = await self.cas.put_harness(files)
            artifact_ids.append(bundle_id)
            attempt.artifact_ids.append(bundle_id)
            state.last_good_artifact_id = bundle_id
            state.state = "accepted"
            state.attempts.append(attempt)
            state.updated_ms = now_ms()
            await self.store.save(state)
            return FoundryOutcome(
                status="accepted",
                harness_id=spec.id,
                decision=decision,
                reprompt=None,
                artifact_ids=artifact_ids,
                state=state,
            )

        state.foundry_defect += 1
        state.attempts.append(attempt)
        state.updated_ms = now_ms()
        parked = len(state.attempts) >= PARK_AFTER_ATTEMPTS
        if parked:
            state.state = "parked"
        await self.store.save(state)

        if parked:
            return FoundryOutcome(
                status="parked",
                harness_id=spec.id,
                decision=decision,
                reprompt=None,
                artifact_ids=artifact_ids,
                state=state,
            )

        reprompt = self._reprompt(
            spec, measurements, decision, measurement_artifact_id
        )
        return FoundryOutcome(
            status="reprompt",
            harness_id=spec.id,
            decision=decision,
            reprompt=reprompt,
            artifact_ids=artifact_ids,
            state=state,
        )

    async def rollback(self, harness_id: str, target_dir: Path) -> RollbackResult:
        """Restore the last-good harness artifact and enforce the <10 s budget."""
        state = await self.store.load(harness_id)
        if state is None or state.last_good_artifact_id is None:
            raise HarnessRejected(f"harness {harness_id} has no last-good artifact")

        started = now_ms()
        await self.cas.extract_harness(state.last_good_artifact_id, Path(target_dir))
        elapsed_ms = now_ms() - started
        if elapsed_ms >= ROLLBACK_BUDGET_MS:
            raise HarnessRejected(
                f"rollback took {elapsed_ms}ms, budget is {ROLLBACK_BUDGET_MS}ms"
            )
        return RollbackResult(
            harness_id=harness_id,
            artifact_id=state.last_good_artifact_id,
            elapsed_ms=elapsed_ms,
        )
