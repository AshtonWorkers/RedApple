"""Harness Foundry orchestration for RA-FND."""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .acceptance import evaluate_acceptance
from .cas import ContentAddressedStore
from .dialect import load_dialect_file
from .errors import FoundryError
from .models import (
    AcceptanceDecision,
    AcceptanceMeasurements,
    AttemptRecord,
    Dialect,
    FoundryState,
    HarnessSpec,
    now_ms,
)
from .runner import load_manifest, measure_harness
from .store import FoundryStore
from .synthesis import HarnessSynthesizer, SynthesisRequest, TemplateHarnessSynthesizer

PARK_AFTER_ATTEMPTS = 3
ROLLBACK_BUDGET_MS = 10_000


class HarnessMeasurer(Protocol):
    """Callable surface used by the Foundry to measure one candidate."""

    def __call__(
        self,
        spec: HarnessSpec,
        manifest: dict[str, Any],
        workdir: Path,
        corpus_dir: Path,
        surface_median_edges_per_sec: float | None = None,
        *,
        clangxx: str | None = None,
        dry_run_seconds: float | None = None,
        run_baseline: bool = True,
    ) -> AcceptanceMeasurements:
        """Measure one harness candidate."""


class FoundryOutcome:
    """Result returned by a Foundry submission."""

    def __init__(
        self,
        *,
        accepted: bool,
        state: FoundryState,
        attempt: AttemptRecord,
        measurement_artifact_id: str,
        bundle_artifact_id: str | None,
        reprompt: dict[str, Any] | None,
        parked: bool = False,
    ) -> None:
        self.accepted = accepted
        self.state = state
        self.attempt = attempt
        self.measurement_artifact_id = measurement_artifact_id
        self.bundle_artifact_id = bundle_artifact_id
        self.reprompt = reprompt
        self.parked = parked

    def to_dict(self) -> dict[str, Any]:
        """Serialize the outcome for logs and tests."""
        return {
            "accepted": self.accepted,
            "parked": self.parked,
            "state": self.state.state,
            "attempt": self.attempt.to_dict(),
            "measurement_artifact_id": self.measurement_artifact_id,
            "bundle_artifact_id": self.bundle_artifact_id,
            "reprompt": self.reprompt,
        }


class Foundry:
    """Synthesizes, measures, gates, and rolls back harness candidates."""

    def __init__(
        self,
        store: FoundryStore,
        cas: ContentAddressedStore,
        *,
        synthesizer: HarnessSynthesizer | None = None,
        measurer: HarnessMeasurer | None = None,
        workroot: Path | None = None,
    ) -> None:
        self.store = store
        self.cas = cas
        self.synthesizer = synthesizer or TemplateHarnessSynthesizer()
        self.measurer = measurer or measure_harness
        self.workroot = workroot
        self._submit_locks: dict[str, asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def _submit_lock(self, harness_id: str) -> asyncio.Lock:
        async with self._locks_guard:
            lock = self._submit_locks.get(harness_id)
            if lock is None:
                lock = asyncio.Lock()
                self._submit_locks[harness_id] = lock
            return lock

    async def submit_candidate(
        self,
        spec: HarnessSpec,
        feedback: dict[str, Any] | None = None,
        *,
        surface_median_edges_per_sec: float | None = None,
        dry_run_seconds: float | None = None,
        clangxx: str | None = None,
        run_baseline: bool = True,
    ) -> FoundryOutcome:
        """Synthesize a harness from ``spec``'s dialect, measure it, and gate it."""
        async with await self._submit_lock(spec.id):
            state = await self.store.load(spec.id)
            if state is not None and state.state == "parked":
                raise FoundryError(f"harness {spec.id!r} is parked after retries")
            dialect, dialect_bytes = await self._load_dialect_and_bytes(spec)
            base_manifest = self._base_manifest(spec)
            attempt = (state.attempt_count if state is not None else 0) + 1
            request = self._synthesis_request(
                spec,
                dialect,
                dialect_bytes,
                attempt=attempt,
                feedback=feedback if feedback is not None else self._feedback_from_state(state),
                surface_median_edges_per_sec=surface_median_edges_per_sec,
                dry_run_seconds=dry_run_seconds,
                clangxx=clangxx,
                base_manifest=base_manifest,
            )
            synthesized = self.synthesizer.synthesize(request)
            workdir = self._attempt_workdir(spec.id, attempt)
            self._materialize(workdir, synthesized.files)
            candidate_spec = HarnessSpec(
                id=spec.id,
                format=spec.format,
                directory=workdir,
                source=synthesized.source_name,
                dialect=synthesized.dialect_name,
                manifest=synthesized.manifest_name,
            )
            corpus_dir = workdir / "corpus"
            measurements = await asyncio.to_thread(
                self.measurer,
                candidate_spec,
                synthesized.manifest,
                workdir / "build",
                corpus_dir,
                float(synthesized.manifest.get("surface_median_edges_per_sec", 0.0)),
                clangxx=clangxx,
                dry_run_seconds=dry_run_seconds,
                run_baseline=run_baseline,
            )
            return await self._submit_measured_locked(
                spec,
                measurements,
                bundle_files=synthesized.files,
                state=state,
            )

    async def submit_measurements(
        self, spec: HarnessSpec, measurements: AcceptanceMeasurements
    ) -> FoundryOutcome:
        """Validate the dialect, gate supplied measurements, and persist the attempt."""
        async with await self._submit_lock(spec.id):
            state = await self.store.load(spec.id)
            await self._load_dialect(spec)
            return await self._submit_measured_locked(
                spec,
                measurements,
                bundle_files=await asyncio.to_thread(spec.bundle_files),
                state=state,
            )

    async def submit(
        self, spec: HarnessSpec, measurements: AcceptanceMeasurements
    ) -> FoundryOutcome:
        """Backwards-compatible alias for :meth:`submit_measurements`."""
        return await self.submit_measurements(spec, measurements)

    async def _submit_measured_locked(
        self,
        spec: HarnessSpec,
        measurements: AcceptanceMeasurements,
        *,
        bundle_files: dict[str, bytes],
        state: FoundryState | None,
    ) -> FoundryOutcome:
        if state is None:
            state = FoundryState(harness_id=spec.id, format=spec.format, updated_at=now_ms())
        if state.state == "parked":
            raise FoundryError(f"harness {spec.id!r} is parked after retries")
        decision = evaluate_acceptance(measurements)
        measurement_payload = {
            "harness_id": spec.id,
            "format": spec.format,
            "created_at": now_ms(),
            "measurements": measurements.to_dict(),
            "decision": decision.to_dict(),
        }
        measurement_artifact_id = await self.cas.put_json(
            measurement_payload, kind="foundry_measurement"
        )
        attempt_id = f"{spec.id}:a{state.attempt_count + 1:03d}"
        bundle_artifact_id: str | None = None
        reprompt: dict[str, Any] | None = None
        parked = False

        if decision.accepted:
            bundle_artifact_id = await self.cas.put_harness(bundle_files)
            state.state = "accepted"
            state.last_good_artifact_id = bundle_artifact_id
        else:
            state.foundry_defect_count += 1
            if state.attempt_count + 1 >= PARK_AFTER_ATTEMPTS:
                state.state = "parked"
                parked = True
            else:
                state.state = "reprompt"
                reprompt = self._reprompt(spec, state, measurements, decision)
                state.reprompt_count += 1

        attempt = AttemptRecord(
            attempt_id=attempt_id,
            harness_id=spec.id,
            measurements=measurements,
            decision=decision,
            measurement_artifact_id=measurement_artifact_id,
            created_at=now_ms(),
            bundle_artifact_id=bundle_artifact_id,
        )
        state.attempts = [*(state.attempts or []), attempt]
        state.updated_at = now_ms()
        await self.store.save(state)
        return FoundryOutcome(
            accepted=decision.accepted,
            state=state,
            attempt=attempt,
            measurement_artifact_id=measurement_artifact_id,
            bundle_artifact_id=bundle_artifact_id,
            reprompt=reprompt,
            parked=parked,
        )

    async def rollback(self, harness_id: str, target: Path | None = None) -> FoundryState:
        """Restore the last-good CAS artifact for ``harness_id``."""
        state = await self.store.load(harness_id)
        if state is None:
            raise FoundryError(f"unknown harness {harness_id!r}")
        if state.last_good_artifact_id is None:
            raise FoundryError(f"harness {harness_id!r} has no last-good artifact")
        started = now_ms()
        if target is None:
            await self.cas.get(state.last_good_artifact_id)
        else:
            await self.cas.extract_harness(state.last_good_artifact_id, Path(target))
        elapsed = now_ms() - started
        if elapsed >= ROLLBACK_BUDGET_MS:
            raise FoundryError(f"rollback exceeded {ROLLBACK_BUDGET_MS}ms budget: {elapsed}ms")
        state.state = "candidate"
        state.updated_at = now_ms()
        await self.store.save(state)
        return state

    async def list_states(self) -> list[FoundryState]:
        """List all persisted Foundry states."""
        states = []
        for harness_id in await self.store.list_ids():
            state = await self.store.load(harness_id)
            if state is not None:
                states.append(state)
        return states

    async def _load_dialect(self, spec: HarnessSpec) -> Dialect:
        return await asyncio.to_thread(load_dialect_file, spec.dialect_path)

    async def _load_dialect_and_bytes(self, spec: HarnessSpec) -> tuple[Dialect, bytes]:
        dialect = await self._load_dialect(spec)
        dialect_bytes = await asyncio.to_thread(spec.dialect_path.read_bytes)
        return dialect, dialect_bytes

    def _base_manifest(self, spec: HarnessSpec) -> dict[str, Any]:
        manifest_path = spec.manifest_path
        if manifest_path is None or not manifest_path.exists():
            return {}
        return load_manifest(manifest_path)

    def _synthesis_request(
        self,
        spec: HarnessSpec,
        dialect: Dialect,
        dialect_bytes: bytes,
        *,
        attempt: int,
        feedback: dict[str, Any] | None,
        surface_median_edges_per_sec: float | None,
        dry_run_seconds: float | None,
        clangxx: str | None,
        base_manifest: dict[str, Any],
    ) -> SynthesisRequest:
        median = surface_median_edges_per_sec
        if median is None:
            median = self._manifest_float(base_manifest, "surface_median_edges_per_sec", 0.0)
        seconds = dry_run_seconds
        if seconds is None:
            seconds = self._manifest_float(base_manifest, "dry_run_seconds", 600.0)
        compile_args = base_manifest.get("compile_args", [])
        if not isinstance(compile_args, list) or not all(
            isinstance(item, str) for item in compile_args
        ):
            raise FoundryError("manifest field 'compile_args' must be a list of strings")
        return SynthesisRequest(
            harness_id=spec.id,
            format=spec.format,
            dialect=dialect,
            dialect_bytes=dialect_bytes,
            attempt=attempt,
            feedback=feedback,
            surface=spec.format,
            surface_median_edges_per_sec=median,
            parser_malloc_symbol=str(base_manifest.get("parser_malloc_symbol", "parser_malloc")),
            dry_run_seconds=seconds,
            clangxx=clangxx or str(base_manifest.get("clangxx", "clang++")),
            compile_args=tuple(compile_args),
        )

    def _feedback_from_state(self, state: FoundryState | None) -> dict[str, Any] | None:
        if state is None or not state.attempts:
            return None
        last = state.attempts[-1]
        return {
            "attempt": state.attempt_count,
            "reasons": list(last.decision.reasons),
            "measurements": last.measurements.to_dict(),
        }

    def _attempt_workdir(self, harness_id: str, attempt: int) -> Path:
        if self.workroot is not None:
            workdir = self.workroot / harness_id / f"attempt-{attempt:03d}"
        else:
            workdir = Path(tempfile.mkdtemp(prefix=f"ra-foundry-{harness_id}-"))
        workdir.mkdir(parents=True, exist_ok=True)
        return workdir

    def _materialize(self, workdir: Path, files: dict[str, bytes]) -> None:
        for name, payload in files.items():
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not name:
                raise FoundryError(f"unsafe synthesized path: {name!r}")
            destination = workdir.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)

    @staticmethod
    def _manifest_float(manifest: dict[str, Any], key: str, default: float) -> float:
        value = manifest.get(key, default)
        if isinstance(value, bool):
            raise FoundryError(f"manifest field {key!r} must be a number")
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise FoundryError(f"manifest field {key!r} must be a number") from exc

    def _reprompt(
        self,
        spec: HarnessSpec,
        state: FoundryState,
        measurements: AcceptanceMeasurements,
        decision: AcceptanceDecision,
    ) -> dict[str, Any]:
        return {
            "task_type": "harness_synth",
            "harness_id": spec.id,
            "format": spec.format,
            "attempt": state.attempt_count + 1,
            "failing_measurement": measurements.to_dict(),
            "decision": decision.to_dict(),
        }
