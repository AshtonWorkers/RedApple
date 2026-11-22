"""Race harness data models (RA-RACE).

All models serialize to canonical JSON (sorted keys, compact separators) so
that schedules, claims, and state snapshots are byte-deterministic and can be
content-addressed in the M0 ledger/CAS.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..errors import FormatFail
from ..ledger.ids import sha256_hex
from .prng import normalize_seed, parse_seed_hex, seed_hex

SCHEDULE_FORMAT = "ra.race.schedule.v1"
CLAIM_FORMAT = "ra.race.claim.v1"
STATE_FORMAT = "ra.race.state.v1"
REPRO_FORMAT = "ra.race.repro.v1"

MAX_TARGET_STEPS = 4096
MAX_TARGET_WORKERS = 64
MAX_TARGET_OPS = 32
MAX_DELAY_US = 60_000_000
MAX_SEED_SCORES = 256

_SHA256_HEX_LEN = 64


def canonical_json(data: Any) -> bytes:
    """Return canonical JSON bytes: sorted keys, compact separators, ASCII."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _require_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FormatFail(f"race model {name} must be a non-empty str")
    return value


def _opt_str(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise FormatFail(f"race model {name} must be a non-empty str or None")
    return value


def _require_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FormatFail(f"race model {name} must be int")
    if value < minimum:
        raise FormatFail(f"race model {name} must be >= {minimum}")
    return value


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise FormatFail(f"race model {name} must be bool")
    return value


def _require_sha256_hex(value: Any, name: str) -> str:
    text = _require_str(value, name)
    if len(text) != _SHA256_HEX_LEN or any(ch not in "0123456789abcdef" for ch in text):
        raise FormatFail(f"race model {name} must be lowercase sha256 hex")
    return text


def _require_dict(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatFail(f"race model {name} must be an object")
    return value


def _mapping_to_dict(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): item for key, item in value.items()}


@dataclass(frozen=True)
class RaceBudget:
    """Explicit stochastic-race budgets (RA-RACE-005, RA-RACE-006).

    ``flake_budget`` caps non-reproducing crashes per target before the target
    is parked. ``repro_budget`` caps KCSan-free deterministic replay attempts
    per crash claim. ``max_probes`` caps stochastic probes per target.
    """

    flake_budget: int = 3
    repro_budget: int = 5
    max_probes: int = 1024
    max_consecutive_errors: int = 8

    def __post_init__(self) -> None:
        _require_int(self.flake_budget, "flake_budget")
        _require_int(self.repro_budget, "repro_budget", minimum=1)
        _require_int(self.max_probes, "max_probes", minimum=1)
        _require_int(self.max_consecutive_errors, "max_consecutive_errors", minimum=1)

    def to_dict(self) -> dict[str, int]:
        return {
            "flake_budget": self.flake_budget,
            "repro_budget": self.repro_budget,
            "max_probes": self.max_probes,
            "max_consecutive_errors": self.max_consecutive_errors,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceBudget:
        raw = _require_dict(dict(data), "budget")
        return cls(
            flake_budget=_require_int(raw.get("flake_budget"), "flake_budget"),
            repro_budget=_require_int(raw.get("repro_budget"), "repro_budget", minimum=1),
            max_probes=_require_int(raw.get("max_probes"), "max_probes", minimum=1),
            max_consecutive_errors=_require_int(
                raw.get("max_consecutive_errors"), "max_consecutive_errors", minimum=1
            ),
        )


@dataclass(frozen=True)
class RaceTarget:
    """Identity of one stochastic race target pinned to the version ring.

    ``corpus_digest`` is the sha256 of the corpus manifest the race stimulus is
    drawn from; it is bound into every schedule and claim so replay is pinned
    to the exact corpus (RA-RACE-008).
    """

    name: str
    ring_node: str
    build: str
    corpus_digest: str
    ops: tuple[str, ...]
    workers: int = 2
    steps: int = 16
    max_delay_us: int = 1_000
    harness_name: str = "race_probe"
    ipsw_sha: str | None = None
    xcode: str | None = None
    sdk: str | None = None
    webkit_commit: str | None = None

    def __post_init__(self) -> None:
        _require_str(self.name, "name")
        _require_str(self.ring_node, "ring_node")
        _require_str(self.build, "build")
        _require_sha256_hex(self.corpus_digest, "corpus_digest")
        _require_str(self.harness_name, "harness_name")
        if not isinstance(self.ops, tuple) or not self.ops:
            raise FormatFail("race model ops must be a non-empty tuple")
        if len(self.ops) > MAX_TARGET_OPS:
            raise FormatFail(f"race model ops exceeds {MAX_TARGET_OPS} entries")
        seen: set[str] = set()
        for op in self.ops:
            _require_str(op, "ops[]")
            if op in seen:
                raise FormatFail(f"race model ops contains duplicate {op!r}")
            seen.add(op)
        _require_int(self.workers, "workers", minimum=1)
        if self.workers > MAX_TARGET_WORKERS:
            raise FormatFail(f"race model workers exceeds {MAX_TARGET_WORKERS}")
        _require_int(self.steps, "steps", minimum=1)
        if self.steps > MAX_TARGET_STEPS:
            raise FormatFail(f"race model steps exceeds {MAX_TARGET_STEPS}")
        _require_int(self.max_delay_us, "max_delay_us")
        if self.max_delay_us > MAX_DELAY_US:
            raise FormatFail(f"race model max_delay_us exceeds {MAX_DELAY_US}")
        _opt_str(self.ipsw_sha, "ipsw_sha")
        _opt_str(self.xcode, "xcode")
        _opt_str(self.sdk, "sdk")
        _opt_str(self.webkit_commit, "webkit_commit")

    def identity_dict(self) -> dict[str, Any]:
        """Canonical identity payload bound into every schedule."""
        return {
            "build": self.build,
            "corpus_digest": self.corpus_digest,
            "harness_name": self.harness_name,
            "ipsw_sha": self.ipsw_sha,
            "max_delay_us": self.max_delay_us,
            "name": self.name,
            "ops": list(self.ops),
            "ring_node": self.ring_node,
            "sdk": self.sdk,
            "steps": self.steps,
            "webkit_commit": self.webkit_commit,
            "workers": self.workers,
            "xcode": self.xcode,
        }

    @property
    def target_digest(self) -> str:
        """Content digest of the target identity."""
        return sha256_hex(canonical_json(self.identity_dict()))

    def to_dict(self) -> dict[str, Any]:
        return self.identity_dict()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceTarget:
        raw = _require_dict(dict(data), "target")
        ops_raw = raw.get("ops")
        if not isinstance(ops_raw, list) or not all(isinstance(op, str) for op in ops_raw):
            raise FormatFail("race model target ops must be a list of str")
        return cls(
            name=_require_str(raw.get("name"), "target.name"),
            ring_node=_require_str(raw.get("ring_node"), "target.ring_node"),
            build=_require_str(raw.get("build"), "target.build"),
            corpus_digest=_require_str(raw.get("corpus_digest"), "target.corpus_digest"),
            ops=tuple(str(op) for op in ops_raw),
            workers=_require_int(raw.get("workers"), "target.workers", minimum=1),
            steps=_require_int(raw.get("steps"), "target.steps", minimum=1),
            max_delay_us=_require_int(raw.get("max_delay_us"), "target.max_delay_us"),
            harness_name=_require_str(raw.get("harness_name"), "target.harness_name"),
            ipsw_sha=_opt_str(raw.get("ipsw_sha"), "target.ipsw_sha"),
            xcode=_opt_str(raw.get("xcode"), "target.xcode"),
            sdk=_opt_str(raw.get("sdk"), "target.sdk"),
            webkit_commit=_opt_str(raw.get("webkit_commit"), "target.webkit_commit"),
        )


@dataclass(frozen=True)
class RaceStep:
    """One scheduled interleaving step: worker, operation, pre-step delay."""

    worker: int
    op: str
    delay_us: int

    def __post_init__(self) -> None:
        _require_int(self.worker, "worker")
        _require_str(self.op, "op")
        _require_int(self.delay_us, "delay_us")

    def to_dict(self) -> dict[str, Any]:
        return {"delay_us": self.delay_us, "op": self.op, "worker": self.worker}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceStep:
        raw = _require_dict(dict(data), "step")
        return cls(
            worker=_require_int(raw.get("worker"), "step.worker"),
            op=_require_str(raw.get("op"), "step.op"),
            delay_us=_require_int(raw.get("delay_us"), "step.delay_us"),
        )


@dataclass(frozen=True)
class RaceSchedule:
    """Deterministic interleaving schedule derived from (target, seed, iteration).

    ``digest`` is the sha256 of the canonical schedule bytes; it is the CAS
    binding key for replay (RA-RACE-004, RA-RACE-007).
    """

    seed: int
    iteration: int
    target: RaceTarget
    steps: tuple[RaceStep, ...]
    format: str = SCHEDULE_FORMAT

    def __post_init__(self) -> None:
        object.__setattr__(self, "seed", normalize_seed(self.seed))
        if self.format != SCHEDULE_FORMAT:
            raise FormatFail(f"race schedule format must be {SCHEDULE_FORMAT!r}")
        _require_int(self.iteration, "iteration")
        if not isinstance(self.steps, tuple) or not self.steps:
            raise FormatFail("race schedule steps must be a non-empty tuple")
        if len(self.steps) > MAX_TARGET_STEPS:
            raise FormatFail(f"race schedule exceeds {MAX_TARGET_STEPS} steps")
        for step in self.steps:
            if not isinstance(step, RaceStep):
                raise FormatFail("race schedule steps must be RaceStep")
            if step.worker >= self.target.workers:
                raise FormatFail("race schedule step worker out of range")
            if step.op not in self.target.ops:
                raise FormatFail(f"race schedule step op {step.op!r} not in target ops")
            if step.delay_us > self.target.max_delay_us:
                raise FormatFail("race schedule step delay exceeds target max_delay_us")

    @property
    def seed_hex(self) -> str:
        return seed_hex(self.seed)

    @property
    def digest(self) -> str:
        """sha256 of the canonical schedule bytes."""
        return sha256_hex(self.to_bytes())

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "iteration": self.iteration,
            "seed": self.seed_hex,
            "steps": [[step.worker, step.op, step.delay_us] for step in self.steps],
            "target": self.target.identity_dict(),
        }

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    @classmethod
    def from_bytes(cls, data: bytes) -> RaceSchedule:
        try:
            raw = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FormatFail("race schedule bytes are not valid JSON") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceSchedule:
        raw = _require_dict(dict(data), "schedule")
        if raw.get("format") != SCHEDULE_FORMAT:
            raise FormatFail(f"race schedule format must be {SCHEDULE_FORMAT!r}")
        seed_text = _require_str(raw.get("seed"), "schedule.seed")
        seed = parse_seed_hex(seed_text)
        steps_raw = raw.get("steps")
        if not isinstance(steps_raw, list):
            raise FormatFail("race schedule steps must be a list")
        steps: list[RaceStep] = []
        for item in steps_raw:
            if not isinstance(item, list) or len(item) != 3:
                raise FormatFail("race schedule step must be [worker, op, delay_us]")
            worker, op, delay = item
            steps.append(
                RaceStep(
                    worker=_require_int(worker, "step.worker"),
                    op=_require_str(op, "step.op"),
                    delay_us=_require_int(delay, "step.delay_us"),
                )
            )
        return cls(
            seed=seed,
            iteration=_require_int(raw.get("iteration"), "schedule.iteration"),
            target=RaceTarget.from_dict(_require_dict(raw.get("target"), "schedule.target")),
            steps=tuple(steps),
        )


@dataclass(frozen=True)
class CrashSummary:
    """JSON-safe crash identity stored in claim value_json.

    The raw payload lives in a CAS artifact; this summary carries its digest.
    """

    id: str
    kind: str
    context: str
    handle_id: str | None
    path: str | None
    digest: str | None
    metadata: Mapping[str, Any]
    payload_sha256: str
    payload_bytes: int

    def signature(self) -> str:
        """Crash substance signature used for reproduction matching.

        Excludes lane-local identifiers (id, handle_id, path) so a replay on a
        fresh handle can match the original observation.
        """
        material = {
            "context": self.context,
            "digest": self.digest,
            "kind": self.kind,
            "payload_sha256": self.payload_sha256,
        }
        return sha256_hex(canonical_json(material))

    def to_dict(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "digest": self.digest,
            "handle_id": self.handle_id,
            "id": self.id,
            "kind": self.kind,
            "metadata": _mapping_to_dict(self.metadata),
            "path": self.path,
            "payload_bytes": self.payload_bytes,
            "payload_sha256": self.payload_sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CrashSummary:
        raw = _require_dict(dict(data), "crash")
        metadata = raw.get("metadata", {})
        if not isinstance(metadata, dict):
            raise FormatFail("race crash metadata must be an object")
        return cls(
            id=_require_str(raw.get("id"), "crash.id"),
            kind=_require_str(raw.get("kind"), "crash.kind"),
            context=_require_str(raw.get("context"), "crash.context"),
            handle_id=_opt_str(raw.get("handle_id"), "crash.handle_id"),
            path=_opt_str(raw.get("path"), "crash.path"),
            digest=_opt_str(raw.get("digest"), "crash.digest"),
            metadata=dict(metadata),
            payload_sha256=_require_sha256_hex(raw.get("payload_sha256"), "crash.payload_sha256"),
            payload_bytes=_require_int(raw.get("payload_bytes"), "crash.payload_bytes"),
        )


@dataclass(frozen=True)
class RaceCrash:
    """A crash observed while executing a race schedule.

    Reproducible CrashRefs carry the schedule seed and digest in metadata so
    any finding can be replayed from the ledger claim alone (RA-RACE-003).
    """

    id: str
    kind: str
    context: str = "app"
    handle_id: str | None = None
    path: str | None = None
    digest: str | None = None
    payload: bytes = b""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_str(self.id, "crash.id")
        _require_str(self.kind, "crash.kind")
        _require_str(self.context, "crash.context")
        if not isinstance(self.payload, bytes):
            raise FormatFail("race crash payload must be bytes")
        try:
            canonical_json(_mapping_to_dict(self.metadata))
        except (TypeError, ValueError) as exc:
            raise FormatFail("race crash metadata must be JSON-serializable") from exc

    @property
    def payload_sha256(self) -> str:
        return sha256_hex(self.payload)

    @property
    def payload_bytes(self) -> int:
        return len(self.payload)

    def signature(self) -> str:
        return CrashSummary(
            id=self.id,
            kind=self.kind,
            context=self.context,
            handle_id=self.handle_id,
            path=self.path,
            digest=self.digest,
            metadata=self.metadata,
            payload_sha256=self.payload_sha256,
            payload_bytes=self.payload_bytes,
        ).signature()

    def summary(self) -> CrashSummary:
        return CrashSummary(
            id=self.id,
            kind=self.kind,
            context=self.context,
            handle_id=self.handle_id,
            path=self.path,
            digest=self.digest,
            metadata=dict(self.metadata),
            payload_sha256=self.payload_sha256,
            payload_bytes=self.payload_bytes,
        )


@dataclass(frozen=True)
class RaceRunResult:
    """Outcome of executing one schedule on a backend."""

    schedule_digest: str
    crashes: tuple[RaceCrash, ...]
    steps_executed: int
    duration_ms: int
    errors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_sha256_hex(self.schedule_digest, "run_result.schedule_digest")
        if not isinstance(self.crashes, tuple) or any(
            not isinstance(crash, RaceCrash) for crash in self.crashes
        ):
            raise FormatFail("race run result crashes must be a tuple of RaceCrash")
        _require_int(self.steps_executed, "run_result.steps_executed")
        _require_int(self.duration_ms, "run_result.duration_ms")
        if not isinstance(self.errors, tuple) or any(
            not isinstance(error, str) or not error for error in self.errors
        ):
            raise FormatFail("race run result errors must be a tuple of non-empty str")

    @classmethod
    def for_schedule(
        cls,
        schedule: RaceSchedule,
        *,
        crashes: tuple[RaceCrash, ...] = (),
        steps_executed: int | None = None,
        duration_ms: int = 0,
        errors: tuple[str, ...] = (),
    ) -> RaceRunResult:
        """Build a result bound to ``schedule``'s digest."""
        return cls(
            schedule_digest=schedule.digest,
            crashes=crashes,
            steps_executed=len(schedule.steps) if steps_executed is None else steps_executed,
            duration_ms=duration_ms,
            errors=errors,
        )


@dataclass(frozen=True)
class SeedScore:
    """Observed crash rate for one seed: seeds are scored as a distribution."""

    seed: int
    seed_hex: str
    probes: int
    crashes: int

    def __post_init__(self) -> None:
        canonical = normalize_seed(self.seed)
        object.__setattr__(self, "seed", canonical)
        if self.seed_hex != seed_hex(canonical):
            raise FormatFail("seed score seed_hex does not match seed")
        _require_int(self.probes, "seed_score.probes")
        _require_int(self.crashes, "seed_score.crashes")

    @property
    def rate(self) -> float:
        return self.crashes / self.probes if self.probes else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "crashes": self.crashes,
            "probes": self.probes,
            "rate": self.rate,
            "seed": self.seed_hex,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SeedScore:
        raw = _require_dict(dict(data), "seed_score")
        return cls(
            seed=parse_seed_hex(_require_str(raw.get("seed"), "seed_score.seed")),
            seed_hex=_require_str(raw.get("seed"), "seed_score.seed"),
            probes=_require_int(raw.get("probes"), "seed_score.probes", minimum=1),
            crashes=_require_int(raw.get("crashes"), "seed_score.crashes"),
        )


@dataclass(frozen=True)
class RaceState:
    """Per-target budget/score snapshot persisted as a ledger claim.

    Latest snapshot per target wins, mirroring LedgerFoundryStore. All state
    lives in the M0 claim ledger; there is no side store (RA-RACE-005).
    """

    target: str
    master_seed: int | None
    distribution: Mapping[str, Any]
    session: int
    attempts: int
    probes: int
    crashes: int
    flakes: int
    repro_attempts: int
    errors: int
    parked: bool
    parked_reason: str | None
    seed_scores: tuple[SeedScore, ...]
    updated_ms: int
    format: str = STATE_FORMAT

    def __post_init__(self) -> None:
        _require_str(self.target, "state.target")
        if self.master_seed is not None:
            object.__setattr__(self, "master_seed", normalize_seed(self.master_seed))
        if not isinstance(self.distribution, dict):
            raise FormatFail("race state distribution must be an object")
        try:
            canonical_json(_mapping_to_dict(self.distribution))
        except (TypeError, ValueError) as exc:
            raise FormatFail("race state distribution must be JSON-serializable") from exc
        for name in (
            "session",
            "attempts",
            "probes",
            "crashes",
            "flakes",
            "repro_attempts",
            "errors",
            "updated_ms",
        ):
            _require_int(getattr(self, name), f"state.{name}")
        if self.crashes < self.flakes:
            raise FormatFail("race state flakes cannot exceed crashes")
        if self.format != STATE_FORMAT:
            raise FormatFail(f"race state format must be {STATE_FORMAT!r}")
        if not isinstance(self.parked, bool):
            raise FormatFail("state.parked must be bool")
        if not isinstance(self.seed_scores, tuple) or any(
            not isinstance(score, SeedScore) for score in self.seed_scores
        ):
            raise FormatFail("race state seed_scores must be a tuple of SeedScore")
        if len(self.seed_scores) > MAX_SEED_SCORES:
            raise FormatFail(f"race state seed_scores exceeds {MAX_SEED_SCORES} entries")
        if self.parked and not self.parked_reason:
            raise FormatFail("parked race state requires parked_reason")
        if not self.parked and self.parked_reason is not None:
            raise FormatFail("unparked race state must not carry parked_reason")

    @property
    def master_seed_hex(self) -> str | None:
        return None if self.master_seed is None else seed_hex(self.master_seed)

    @property
    def crash_rate(self) -> float:
        """Observed crash rate over the seed distribution (RA-RACE-002)."""
        return self.crashes / self.probes if self.probes else 0.0

    @classmethod
    def initial(
        cls,
        *,
        target: str,
        master_seed: int,
        distribution: Mapping[str, Any],
        updated_ms: int,
    ) -> RaceState:
        return cls(
            target=target,
            master_seed=normalize_seed(master_seed),
            distribution=dict(distribution),
            session=0,
            attempts=0,
            probes=0,
            crashes=0,
            flakes=0,
            repro_attempts=0,
            errors=0,
            parked=False,
            parked_reason=None,
            seed_scores=(),
            updated_ms=updated_ms,
        )

    def _replace(self, **changes: Any) -> RaceState:
        values: dict[str, Any] = {
            "target": self.target,
            "master_seed": self.master_seed,
            "distribution": self.distribution,
            "session": self.session,
            "attempts": self.attempts,
            "probes": self.probes,
            "crashes": self.crashes,
            "flakes": self.flakes,
            "repro_attempts": self.repro_attempts,
            "errors": self.errors,
            "parked": self.parked,
            "parked_reason": self.parked_reason,
            "seed_scores": self.seed_scores,
            "updated_ms": self.updated_ms,
            "format": self.format,
        }
        values.update(changes)
        return RaceState(**values)

    def next_attempt(self) -> RaceState:
        """Count one schedule attempt (completed or errored)."""
        return self._replace(attempts=self.attempts + 1)

    def record_error(self) -> RaceState:
        return self._replace(errors=self.errors + 1)

    def record_probe(self, seed: int, crash_count: int) -> RaceState:
        """Record one completed probe and update the seed score distribution."""
        seed = normalize_seed(seed)
        scores = {score.seed_hex: score for score in self.seed_scores}
        hex_seed = seed_hex(seed)
        current = scores.get(hex_seed)
        if current is None:
            current = SeedScore(seed=seed, seed_hex=hex_seed, probes=0, crashes=0)
        updated = SeedScore(
            seed=current.seed,
            seed_hex=current.seed_hex,
            probes=current.probes + 1,
            crashes=current.crashes + crash_count,
        )
        scores[hex_seed] = updated
        ranked = sorted(
            scores.values(),
            key=lambda score: (-score.crashes, -score.probes, score.seed),
        )[:MAX_SEED_SCORES]
        return self._replace(
            probes=self.probes + 1,
            crashes=self.crashes + crash_count,
            seed_scores=tuple(ranked),
        )

    def record_reproduction(self, attempts: int, reproduced: bool) -> RaceState:
        """Record replay accounting for one crash claim."""
        _require_int(attempts, "attempts", minimum=1)
        return self._replace(
            repro_attempts=self.repro_attempts + attempts,
            flakes=self.flakes + (0 if reproduced else 1),
        )

    def park(self, reason: str) -> RaceState:
        _require_str(reason, "parked_reason")
        return self._replace(parked=True, parked_reason=reason)

    def next_session(self, *, updated_ms: int) -> RaceState:
        return self._replace(session=self.session + 1, updated_ms=updated_ms)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attempts": self.attempts,
            "crashes": self.crashes,
            "distribution": _mapping_to_dict(self.distribution),
            "errors": self.errors,
            "flakes": self.flakes,
            "format": self.format,
            "master_seed": self.master_seed_hex,
            "parked": self.parked,
            "parked_reason": self.parked_reason,
            "probes": self.probes,
            "repro_attempts": self.repro_attempts,
            "seed_scores": [score.to_dict() for score in self.seed_scores],
            "session": self.session,
            "target": self.target,
            "updated_ms": self.updated_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceState:
        raw = _require_dict(dict(data), "state")
        if raw.get("format") != STATE_FORMAT:
            raise FormatFail(f"race state format must be {STATE_FORMAT!r}")
        master_seed_raw = raw.get("master_seed")
        master_seed = (
            None
            if master_seed_raw is None
            else parse_seed_hex(_require_str(master_seed_raw, "state.master_seed"))
        )
        distribution = raw.get("distribution")
        if not isinstance(distribution, dict):
            raise FormatFail("race state distribution must be an object")
        scores_raw = raw.get("seed_scores", [])
        if not isinstance(scores_raw, list):
            raise FormatFail("race state seed_scores must be a list")
        scores = tuple(
            SeedScore.from_dict(_require_dict(item, "seed_score")) for item in scores_raw
        )
        parked = raw.get("parked", False)
        if not isinstance(parked, bool):
            raise FormatFail("state.parked must be bool")
        return cls(
            target=_require_str(raw.get("target"), "state.target"),
            master_seed=master_seed,
            distribution=dict(distribution),
            session=_require_int(raw.get("session"), "state.session"),
            attempts=_require_int(raw.get("attempts"), "state.attempts"),
            probes=_require_int(raw.get("probes"), "state.probes"),
            crashes=_require_int(raw.get("crashes"), "state.crashes"),
            flakes=_require_int(raw.get("flakes"), "state.flakes"),
            repro_attempts=_require_int(raw.get("repro_attempts"), "state.repro_attempts"),
            errors=_require_int(raw.get("errors"), "state.errors"),
            parked=parked,
            parked_reason=_opt_str(raw.get("parked_reason"), "state.parked_reason"),
            seed_scores=scores,
            updated_ms=_require_int(raw.get("updated_ms"), "state.updated_ms"),
        )


@dataclass(frozen=True)
class RaceClaimRecord:
    """Value payload of one ``race`` ledger claim (RA-RACE-007).

    The claim is CAS-bound: ``schedule_digest`` and the repro artifact sha256
    reference content-addressed schedule/repro bytes verified at replay time.
    """

    target: str
    target_digest: str
    ring_node: str
    build: str
    corpus_digest: str
    seed: int
    seed_hex: str
    iteration: int
    schedule_digest: str
    outcome: str
    reproduced: bool
    replay_attempts: int
    backend: str
    deterministic: bool
    flake_budget: int
    repro_budget: int
    crash: CrashSummary
    created_ms: int
    format: str = CLAIM_FORMAT

    def __post_init__(self) -> None:
        _require_str(self.target, "claim.target")
        _require_sha256_hex(self.target_digest, "claim.target_digest")
        _require_str(self.ring_node, "claim.ring_node")
        _require_str(self.build, "claim.build")
        _require_sha256_hex(self.corpus_digest, "claim.corpus_digest")
        object.__setattr__(self, "seed", normalize_seed(self.seed))
        _require_int(self.iteration, "claim.iteration")
        _require_sha256_hex(self.schedule_digest, "claim.schedule_digest")
        if self.seed_hex != seed_hex(self.seed):
            raise FormatFail("claim seed_hex does not match seed")
        if self.outcome not in {"reproduced", "flaky"}:
            raise FormatFail("race claim outcome must be 'reproduced' or 'flaky'")
        if self.outcome == "reproduced" and not self.reproduced:
            raise FormatFail("reproduced claim must have reproduced=True")
        if self.outcome == "flaky" and self.reproduced:
            raise FormatFail("flaky claim must have reproduced=False")
        _require_int(self.replay_attempts, "claim.replay_attempts", minimum=1)
        _require_str(self.backend, "claim.backend")
        _require_bool(self.deterministic, "claim.deterministic")
        _require_bool(self.reproduced, "claim.reproduced")
        if self.repro_budget < 1 or self.replay_attempts > self.repro_budget:
            raise FormatFail("claim replay_attempts exceed repro_budget")
        _require_int(self.flake_budget, "claim.flake_budget")
        if not isinstance(self.crash, CrashSummary):
            raise FormatFail("race claim crash must be a CrashSummary")
        _require_int(self.created_ms, "claim.created_ms")
        if self.format != CLAIM_FORMAT:
            raise FormatFail(f"race claim format must be {CLAIM_FORMAT!r}")

    def dedup_material(self) -> str:
        return (
            f"{self.target}|{self.schedule_digest}|{self.crash.signature()}|"
            f"{self.iteration}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "build": self.build,
            "corpus_digest": self.corpus_digest,
            "created_ms": self.created_ms,
            "crash": self.crash.to_dict(),
            "deterministic": self.deterministic,
            "flake_budget": self.flake_budget,
            "format": self.format,
            "iteration": self.iteration,
            "outcome": self.outcome,
            "replay_attempts": self.replay_attempts,
            "reproduced": self.reproduced,
            "repro_budget": self.repro_budget,
            "ring_node": self.ring_node,
            "schedule_digest": self.schedule_digest,
            "seed": self.seed_hex,
            "target": self.target,
            "target_digest": self.target_digest,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict()).decode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RaceClaimRecord:
        raw = _require_dict(dict(data), "claim")
        if raw.get("format") != CLAIM_FORMAT:
            raise FormatFail(f"race claim format must be {CLAIM_FORMAT!r}")
        crash_raw = raw.get("crash")
        if not isinstance(crash_raw, dict):
            raise FormatFail("race claim crash must be an object")
        deterministic = raw.get("deterministic")
        if not isinstance(deterministic, bool):
            raise FormatFail("race claim deterministic must be bool")
        reproduced = raw.get("reproduced", False)
        if not isinstance(reproduced, bool):
            raise FormatFail("race claim reproduced must be bool")
        return cls(
            target=_require_str(raw.get("target"), "claim.target"),
            target_digest=_require_str(raw.get("target_digest"), "claim.target_digest"),
            ring_node=_require_str(raw.get("ring_node"), "claim.ring_node"),
            build=_require_str(raw.get("build"), "claim.build"),
            corpus_digest=_require_str(raw.get("corpus_digest"), "claim.corpus_digest"),
            seed=parse_seed_hex(_require_str(raw.get("seed"), "claim.seed")),
            seed_hex=_require_str(raw.get("seed"), "claim.seed"),
            iteration=_require_int(raw.get("iteration"), "claim.iteration"),
            schedule_digest=_require_str(raw.get("schedule_digest"), "claim.schedule_digest"),
            outcome=_require_str(raw.get("outcome"), "claim.outcome"),
            reproduced=reproduced,
            replay_attempts=_require_int(raw.get("replay_attempts"), "claim.replay_attempts"),
            backend=_require_str(raw.get("backend"), "claim.backend"),
            deterministic=deterministic,
            flake_budget=_require_int(raw.get("flake_budget"), "claim.flake_budget"),
            repro_budget=_require_int(raw.get("repro_budget"), "claim.repro_budget", minimum=1),
            crash=CrashSummary.from_dict(crash_raw),
            created_ms=_require_int(raw.get("created_ms"), "claim.created_ms"),
        )

    @classmethod
    def from_json(cls, text: str) -> RaceClaimRecord:
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise FormatFail("race claim value_json is not valid JSON") from exc
        return cls.from_dict(raw)
