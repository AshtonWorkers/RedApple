"""Join programs, assertion validation, Wilson reliability, and ledger writes."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..errors import FormatFail
from ..ledger import Ledger
from ..ledger.ids import now_ms, sha256_hex
from ..obs.invariants import assert_join_repro
from .models import (
    JOIN_TRIALS,
    LIVE_LOWER_BOUND,
    REQUIRED_ASSERTION_KINDS,
    RESEARCH_LOWER_BOUND,
    WILSON_Z,
    AssertionKind,
    JoinProgram,
    JoinState,
)

_ASSERT_MARKER = "# ra-join-assert:"
_ID_MARKER = "# ra-join:id:"
_CONTEXT_KEYS = {
    AssertionKind.ADDRESS_VALIDITY: "address_valid",
    AssertionKind.RIGHT_LIVENESS: "right_live",
    AssertionKind.SIGNATURE_VALIDITY: "signature_valid",
    AssertionKind.SANDBOX_STATE: "sandbox_ok",
}


@dataclass(frozen=True)
class JoinRunResult:
    """Outcome of evaluating one join program against a repro context."""

    join_id: str
    passed: bool
    failures: tuple[str, ...]
    checked: int


@dataclass(frozen=True)
class JoinMeasurement:
    """Reliability measurement for passes out of the fixed join trial count."""

    passes: int
    trials: int
    reliability: float
    lower_bound: float
    state: JoinState


def assertion_kind(value: str) -> AssertionKind:
    """Parse an assertion kind or raise FORMAT_FAIL."""
    try:
        return AssertionKind(value)
    except ValueError as exc:
        raise FormatFail(f"unknown join assertion kind: {value}") from exc


def validate_join_program(program: JoinProgram) -> None:
    """Validate RA-JON-001 structure before a join is rendered or stored."""
    if not program.join_id.strip() or not program.a_claim.strip() or not program.b_claim.strip():
        raise FormatFail("join id and claim ids must be non-empty")
    if program.a_claim == program.b_claim:
        raise FormatFail("join claims must be distinct")
    if program.trials != JOIN_TRIALS:
        raise FormatFail(f"join trials must be exactly {JOIN_TRIALS}")
    if not program.assertions:
        raise FormatFail("join has no invariant assertions")
    names: set[str] = set()
    kinds: set[str] = set()
    for assertion in program.assertions:
        kind = assertion_kind(assertion.kind)
        if not assertion.name.strip():
            raise FormatFail("join assertion name must be non-empty")
        if assertion.name in names:
            raise FormatFail(f"duplicate join assertion name: {assertion.name}")
        names.add(assertion.name)
        kinds.add(kind.value)
    missing = {kind.value for kind in REQUIRED_ASSERTION_KINDS} - kinds
    if missing:
        raise FormatFail(f"join missing required assertion kinds: {sorted(missing)}")
    assert_join_repro([item.name for item in program.assertions], program.repro)


def render_join_source(program: JoinProgram) -> str:
    """Render the join as one deterministic Python source file (RA-JON-001)."""
    validate_join_program(program)
    lines = [
        '"""RedApple join program generated from ra.chain.joins."""',
        "",
        f"{_ID_MARKER}{program.join_id}",
        f"A_CLAIM = {program.a_claim!r}",
        f"B_CLAIM = {program.b_claim!r}",
        f"REPRO = {program.repro!r}",
        "",
        "def check(context):",
    ]
    for assertion in program.assertions:
        kind = assertion_kind(assertion.kind)
        key = _CONTEXT_KEYS[kind]
        safe_name = re.sub(r"[^A-Za-z0-9_]+", "_", assertion.name).strip("_") or "assertion"
        lines.append(f"    # {_ASSERT_MARKER}{kind.value} name={assertion.name}")
        lines.append(f"    assert context.get({key!r}, False), {safe_name!r}")
    lines.extend(
        [
            "    return {'a_claim': A_CLAIM, 'b_claim': B_CLAIM, 'repro': REPRO}",
            "",
        ]
    )
    return "\n".join(lines)


def source_assertion_kinds(source: str) -> tuple[str, ...]:
    """Extract assertion kinds from rendered join source markers."""
    kinds: list[str] = []
    for line in source.splitlines():
        if _ASSERT_MARKER in line:
            marker = line.split(_ASSERT_MARKER, 1)[1].strip()
            kind = marker.split(" ", 1)[0]
            kinds.append(kind)
    return tuple(kinds)


def assert_join_source(source: str, program: JoinProgram) -> None:
    """Fail red when any rendered assertion is removed or substituted (RA-JON-002)."""
    validate_join_program(program)
    expected = tuple(sorted(assertion_kind(item.kind).value for item in program.assertions))
    actual = tuple(sorted(source_assertion_kinds(source)))
    if actual != expected:
        raise FormatFail("join source assertions do not match the join program")
    if f"{_ID_MARKER}{program.join_id}" not in source:
        raise FormatFail("join source id marker does not match the join program")


def run_join(program: JoinProgram, context: Mapping[str, bool]) -> JoinRunResult:
    """Evaluate assertions against a deterministic repro context."""
    validate_join_program(program)
    failures: list[str] = []
    for assertion in program.assertions:
        kind = assertion_kind(assertion.kind)
        key = _CONTEXT_KEYS[kind]
        if not context.get(key, False):
            failures.append(assertion.name)
    return JoinRunResult(
        join_id=program.join_id,
        passed=not failures,
        failures=tuple(failures),
        checked=len(program.assertions),
    )


def wilson_lower_bound(
    passes: int, trials: int = JOIN_TRIALS, *, z: float = WILSON_Z
) -> float:
    """Wilson score lower bound for a binomial reliability estimate."""
    if isinstance(passes, bool) or isinstance(trials, bool):
        raise FormatFail("join trial counts must be integers")
    if trials <= 0 or passes < 0 or passes > trials:
        raise FormatFail("join passes must satisfy 0 <= passes <= trials")
    if z <= 0:
        raise FormatFail("Wilson z must be positive")
    phat = passes / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (phat + z2 / (2.0 * trials)) / denominator
    margin = z * math.sqrt((phat * (1.0 - phat) / trials) + (z2 / (4.0 * trials * trials)))
    margin /= denominator
    return max(0.0, min(1.0, centre - margin))


def reliability(passes: int, trials: int = JOIN_TRIALS) -> float:
    """Observed reliability as passes/trials."""
    if trials <= 0 or passes < 0 or passes > trials:
        raise FormatFail("join passes must satisfy 0 <= passes <= trials")
    return passes / trials


def classify_join_state(lower_bound: float) -> JoinState:
    """RA-JON-004: live at >=0.99, research at 0.90..0.99, candidate below."""
    if not 0.0 <= lower_bound <= 1.0:
        raise FormatFail("join lower_bound must be in [0, 1]")
    if lower_bound >= LIVE_LOWER_BOUND:
        return JoinState.LIVE
    if lower_bound >= RESEARCH_LOWER_BOUND:
        return JoinState.RESEARCH
    return JoinState.CANDIDATE


def measure_join(program: JoinProgram, passes: int, *, trials: int | None = None) -> JoinMeasurement:
    """Measure passes out of 10,000 trials and classify the join state."""
    validate_join_program(program)
    trial_count = program.trials if trials is None else trials
    if trial_count != JOIN_TRIALS:
        raise FormatFail(f"join trials must be exactly {JOIN_TRIALS}")
    rel = reliability(passes, trial_count)
    lower = wilson_lower_bound(passes, trial_count)
    return JoinMeasurement(
        passes=passes,
        trials=trial_count,
        reliability=rel,
        lower_bound=lower,
        state=classify_join_state(lower),
    )


def join_invariants_json(program: JoinProgram, *, artifact_id: str | None = None) -> str:
    """Stable JSON payload stored in the ledger join row."""
    validate_join_program(program)
    source = render_join_source(program)
    payload: dict[str, Any] = {
        "assertions": [item.as_dict() for item in program.assertions],
        "repro": program.repro,
        "code_sha256": sha256_hex(source.encode("utf-8")),
    }
    if artifact_id is not None:
        payload["artifact_id"] = artifact_id
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


async def register_join(
    ledger: Ledger,
    program: JoinProgram,
    passes: int,
    *,
    trials: int | None = None,
    created: int | None = None,
) -> JoinMeasurement:
    """Render, measure, and persist one join through the M0 ledger only."""
    measurement = measure_join(program, passes, trials=trials)
    source = render_join_source(program)
    assert_join_source(source, program)
    artifact = await ledger.put_artifact("join_code", source.encode("utf-8"), ttl_class="pinned")
    payload: dict[str, Any] = {
        "join_id": program.join_id,
        "a_claim": program.a_claim,
        "b_claim": program.b_claim,
        "invariants_json": join_invariants_json(program, artifact_id=artifact),
        "reliability": measurement.reliability,
        "lower_bound": measurement.lower_bound,
        "state": measurement.state.value,
        "created": now_ms() if created is None else created,
    }
    existing = ledger.get_join(program.join_id)
    if existing is None:
        await ledger.insert_join(payload)
    else:
        await ledger.update_join(
            program.join_id,
            state=measurement.state.value,
            reliability=measurement.reliability,
            lower_bound=measurement.lower_bound,
            invariants_json=payload["invariants_json"],
        )
    return measurement
