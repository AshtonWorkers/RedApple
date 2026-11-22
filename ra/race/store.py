"""Ledger + CAS persistence for race claims and state (RA-RACE-007).

All race state lives in the M0 claim ledger: findings are ``race`` claims
with CAS-bound schedule/repro/crash artifacts, and per-target budget snapshots
are ``race_state`` claims (latest wins), mirroring LedgerFoundryStore. There
is no side JSON/SQLite store.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from ..errors import DuplicateDedup, FormatFail, InvariantBreach
from ..ledger import (
    ArtifactInput,
    ClaimArtifactInput,
    ClaimInput,
    ClaimState,
    Ledger,
    UlidFactory,
)
from ..ledger.ids import sha256_hex
from .models import (
    CLAIM_FORMAT,
    REPRO_FORMAT,
    STATE_FORMAT,
    CrashSummary,
    RaceClaimRecord,
    RaceCrash,
    RaceSchedule,
    RaceState,
    canonical_json,
)

CLAIM_TYPE_RACE = "race"
CLAIM_TYPE_STATE = "race_state"

_STATE_SCAN_LIMIT = 10000


class RaceCas(Protocol):
    """Content-addressed byte store (structurally satisfied by foundry CAS)."""

    async def put(self, data: bytes) -> str:
        """Store bytes, returning their lowercase sha256 hex digest."""
        ...

    async def get(self, sha256: str) -> bytes:
        """Fetch bytes by digest, verifying integrity."""
        ...


def race_claim_dedup_key(record: RaceClaimRecord) -> str:
    """Deterministic dedup key for one crash claim (idempotent re-probes)."""
    material = f"race|{record.dedup_material()}".encode()
    return "race_" + sha256_hex(material)[:40]


def repro_manifest_bytes(record: RaceClaimRecord) -> bytes:
    """Deterministic replay manifest bound to the claim (RA-RACE-004).

    The manifest is a pure function of the claim record (no timestamps), so
    its sha256 is stable and can be verified against the ledger artifact row.
    """
    manifest = {
        "backend": record.backend,
        "build": record.build,
        "corpus_digest": record.corpus_digest,
        "deterministic": record.deterministic,
        "format": REPRO_FORMAT,
        "iteration": record.iteration,
        "replay": {
            "attempts_budget": record.repro_budget,
            "crash_signature": record.crash.signature(),
            "entrypoint": "ra.race.RaceHarness.replay_claim",
        },
        "ring_node": record.ring_node,
        "schedule_digest": record.schedule_digest,
        "seed": record.seed_hex,
        "target": record.target,
        "target_digest": record.target_digest,
    }
    return canonical_json(manifest)


def assert_race_claim_bound(roles: Sequence[str], *, claim_id: str = "") -> None:
    """Invariant: a race claim must carry CAS-bound schedule/repro/crash artifacts."""
    present = set(roles)
    missing = [role for role in ("schedule", "repro", "crash_meta") if role not in present]
    if missing:
        suffix = f" {claim_id}" if claim_id else ""
        raise InvariantBreach(
            f"I-RACE: unbound race claim{suffix}: missing artifact roles {missing}"
        )


class LedgerRaceStore:
    """Persist race findings and state snapshots through the M0 ledger."""

    def __init__(self, ledger: Ledger, cas: RaceCas, *, ids: UlidFactory | None = None) -> None:
        self._ledger = ledger
        self._cas = cas
        self._ids = ids or UlidFactory()

    # -- state snapshots -------------------------------------------------

    def _state_rows(self) -> list[dict[str, Any]]:
        return self._ledger.claims_by_type(CLAIM_TYPE_STATE, limit=_STATE_SCAN_LIMIT)

    @staticmethod
    def _state_from_row(row: dict[str, Any]) -> tuple[tuple[int, str], RaceState] | None:
        try:
            raw = json.loads(str(row["value_json"]))
        except json.JSONDecodeError:
            return None
        if not isinstance(raw, dict):
            return None
        try:
            state = RaceState.from_dict(raw)
        except FormatFail:
            return None
        return (int(row["created"]), str(row["id"])), state

    async def load_state(self, target: str) -> RaceState | None:
        """Load the latest state snapshot for one target, or None."""
        latest: tuple[tuple[int, str], RaceState] | None = None
        for row in self._state_rows():
            parsed = self._state_from_row(row)
            if parsed is None:
                continue
            key, state = parsed
            if state.target != target:
                continue
            if latest is None or key > latest[0]:
                latest = (key, state)
        return None if latest is None else latest[1]

    async def save_state(self, state: RaceState) -> str:
        """Persist one state snapshot as a bound ``race_state`` claim."""
        data = canonical_json(state.to_dict())
        claim_id = self._ids.new("rs")
        claim = ClaimInput(
            claim_id=claim_id,
            type=CLAIM_TYPE_STATE,
            value_json=data.decode("utf-8"),
            confidence=1.0,
            dedup_key=f"race_state:{claim_id}",
            created=state.updated_ms,
            artifacts=(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind=CLAIM_TYPE_STATE, data=data, ttl_class="run"),
                    role="state",
                ),
            ),
        )
        await self._ledger.create_claim(claim)
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
        return claim_id

    # -- crash claims ----------------------------------------------------

    async def save_crash_claim(
        self,
        record: RaceClaimRecord,
        *,
        schedule: RaceSchedule,
        crash: RaceCrash,
        run_id: str | None = None,
    ) -> str:
        """Persist one crash as a bound ``race`` claim with CAS-bound artifacts.

        Re-probing an identical schedule/crash is idempotent: the deterministic
        dedup key resolves to the existing claim.
        """
        if record.crash.payload_sha256 != sha256_hex(crash.payload):
            raise FormatFail("claim crash digest does not match crash payload")
        if record.crash.payload_bytes != len(crash.payload):
            raise FormatFail("claim crash byte count does not match crash payload")
        schedule_bytes = schedule.to_bytes()
        schedule_sha = await self._cas.put(schedule_bytes)
        if schedule_sha != schedule.digest or schedule_sha != record.schedule_digest:
            raise InvariantBreach("I-RACE: schedule bytes do not match claim digest")
        repro_bytes = repro_manifest_bytes(record)
        await self._cas.put(repro_bytes)

        artifacts: list[ClaimArtifactInput] = [
            ClaimArtifactInput(
                artifact=ArtifactInput(kind="race_schedule", data=schedule_bytes, ttl_class="pinned"),
                role="schedule",
            ),
            ClaimArtifactInput(
                artifact=ArtifactInput(kind="race_repro", data=repro_bytes, ttl_class="pinned"),
                role="repro",
            ),
            ClaimArtifactInput(
                artifact=ArtifactInput(
                    kind="race_crash_meta",
                    data=canonical_json(record.crash.to_dict()),
                    ttl_class="pinned",
                ),
                role="crash_meta",
            ),
        ]
        if crash.payload:
            artifacts.append(
                ClaimArtifactInput(
                    artifact=ArtifactInput(kind="race_crash", data=crash.payload, ttl_class="run"),
                    role="crash",
                )
            )

        dedup_key = race_claim_dedup_key(record)
        claim = ClaimInput(
            claim_id=self._ids.new("race"),
            type=CLAIM_TYPE_RACE,
            value_json=record.to_json(),
            confidence=1.0 if record.reproduced else 0.5,
            dedup_key=dedup_key,
            created=record.created_ms,
            run_id=run_id,
            artifacts=tuple(artifacts),
        )
        try:
            claim_id = await self._ledger.create_claim(claim)
        except DuplicateDedup:
            existing = self._ledger.claim_by_dedup(dedup_key)
            if existing is None:
                raise
            return str(existing["id"])
        await self._ledger.transition_claim(claim_id, ClaimState.BOUND)
        return claim_id

    # -- reads -----------------------------------------------------------

    def race_claims(self, *, target: str | None = None, limit: int = 10000) -> list[dict[str, Any]]:
        """List race claims, optionally filtered by target name."""
        rows = self._ledger.claims_by_type(CLAIM_TYPE_RACE, limit=limit)
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                record = RaceClaimRecord.from_json(str(row["value_json"]))
            except FormatFail:
                continue
            if target is not None and record.target != target:
                continue
            out.append({**row, "record": record})
        return out

    async def verify_claim(self, claim_id: str) -> RaceClaimRecord:
        """Verify a race claim's CAS binding and return its record.

        Raises InvariantBreach for unbound claims, FormatFail for missing or
        malformed claims, and lets CAS integrity errors propagate.
        """
        row = self._ledger.get_claim(claim_id)
        if row is None:
            raise FormatFail(f"unknown claim {claim_id}")
        if str(row["type"]) != CLAIM_TYPE_RACE:
            raise FormatFail(f"claim {claim_id} is not a race claim")
        try:
            record = RaceClaimRecord.from_json(str(row["value_json"]))
        except FormatFail as exc:
            raise InvariantBreach(f"I-RACE: race claim {claim_id} has malformed value_json") from exc

        links = self._ledger.claim_artifacts(claim_id)
        assert_race_claim_bound([str(link["role"]) for link in links], claim_id=claim_id)

        schedule_link = self._artifact_link(links, "schedule", claim_id)
        if str(schedule_link["kind"]) != "race_schedule":
            raise InvariantBreach(f"I-RACE: claim {claim_id} schedule artifact kind mismatch")
        if str(schedule_link["sha256"]) != record.schedule_digest:
            raise InvariantBreach(f"I-RACE: claim {claim_id} schedule sha mismatch")
        if str(schedule_link["artifact_id"]) != f"art_{record.schedule_digest}":
            raise InvariantBreach(f"I-RACE: claim {claim_id} schedule artifact id mismatch")

        schedule_bytes = await self._cas.get(record.schedule_digest)
        if sha256_hex(schedule_bytes) != record.schedule_digest:
            raise InvariantBreach(f"I-RACE: claim {claim_id} CAS schedule failed integrity")
        schedule = RaceSchedule.from_bytes(schedule_bytes)
        if schedule.digest != record.schedule_digest:
            raise InvariantBreach(f"I-RACE: claim {claim_id} schedule digest mismatch")
        if schedule.seed != record.seed or schedule.seed_hex != record.seed_hex:
            raise InvariantBreach(f"I-RACE: claim {claim_id} seed mismatch")
        if schedule.iteration != record.iteration:
            raise InvariantBreach(f"I-RACE: claim {claim_id} iteration mismatch")
        target = schedule.target
        if (
            target.name != record.target
            or target.target_digest != record.target_digest
            or target.ring_node != record.ring_node
            or target.build != record.build
            or target.corpus_digest != record.corpus_digest
        ):
            raise InvariantBreach(f"I-RACE: claim {claim_id} target binding mismatch")

        repro_link = self._artifact_link(links, "repro", claim_id)
        if str(repro_link["kind"]) != "race_repro":
            raise InvariantBreach(f"I-RACE: claim {claim_id} repro artifact kind mismatch")
        expected_repro_sha = sha256_hex(repro_manifest_bytes(record))
        if str(repro_link["sha256"]) != expected_repro_sha:
            raise InvariantBreach(f"I-RACE: claim {claim_id} repro manifest sha mismatch")
        repro_bytes = await self._cas.get(expected_repro_sha)
        if sha256_hex(repro_bytes) != expected_repro_sha:
            raise InvariantBreach(f"I-RACE: claim {claim_id} CAS repro failed integrity")

        crash_meta_link = self._artifact_link(links, "crash_meta", claim_id)
        if str(crash_meta_link["kind"]) != "race_crash_meta":
            raise InvariantBreach(f"I-RACE: claim {claim_id} crash_meta artifact kind mismatch")
        expected_meta_bytes = canonical_json(record.crash.to_dict())
        expected_meta_sha = sha256_hex(expected_meta_bytes)
        if str(crash_meta_link["sha256"]) != expected_meta_sha:
            raise InvariantBreach(f"I-RACE: claim {claim_id} crash_meta sha mismatch")
        if int(crash_meta_link["bytes"]) != len(expected_meta_bytes):
            raise InvariantBreach(f"I-RACE: claim {claim_id} crash_meta byte count mismatch")

        crash_link = self._find_artifact_link(links, "crash")
        if record.crash.payload_bytes > 0:
            if crash_link is None:
                raise InvariantBreach(f"I-RACE: claim {claim_id} missing crash artifact")
            if str(crash_link["kind"]) != "race_crash":
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash artifact kind mismatch")
            if str(crash_link["sha256"]) != record.crash.payload_sha256:
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash payload sha mismatch")
            if int(crash_link["bytes"]) != record.crash.payload_bytes:
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash payload byte count mismatch")
        elif crash_link is not None:
            if str(crash_link["kind"]) != "race_crash":
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash artifact kind mismatch")
            if str(crash_link["sha256"]) != record.crash.payload_sha256:
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash payload sha mismatch")
            if int(crash_link["bytes"]) != record.crash.payload_bytes:
                raise InvariantBreach(f"I-RACE: claim {claim_id} crash payload byte count mismatch")
        return record

    @staticmethod
    def _find_artifact_link(
        links: Sequence[Mapping[str, Any]], role: str
    ) -> Mapping[str, Any] | None:
        for link in links:
            if str(link["role"]) == role:
                return link
        return None

    @classmethod
    def _artifact_link(
        cls, links: Sequence[Mapping[str, Any]], role: str, claim_id: str
    ) -> Mapping[str, Any]:
        link = cls._find_artifact_link(links, role)
        if link is None:
            raise InvariantBreach(f"I-RACE: claim {claim_id} missing {role} artifact")
        return link

    @staticmethod
    def crash_meta_dict(crash: CrashSummary) -> dict[str, Any]:
        return crash.to_dict()


__all__ = [
    "CLAIM_FORMAT",
    "CLAIM_TYPE_RACE",
    "CLAIM_TYPE_STATE",
    "REPRO_FORMAT",
    "STATE_FORMAT",
    "LedgerRaceStore",
    "RaceCas",
    "assert_race_claim_bound",
    "race_claim_dedup_key",
    "repro_manifest_bytes",
]
