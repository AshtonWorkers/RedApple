"""Attack-surface expansion for SBPL / XPC / mach-lookup entry points (RA-SFC).

Expansion turns the surface compiler's raw ``entry_point`` rows into a richer,
deduplicated target set:

* ``regex:`` mach-lookup grants (skipped by the compiler) are expanded against a
  harvested service-name corpus into concrete targets (RA-SFC-001);
* granting sandbox profiles contribute capability families and reach records
  (RA-SFC-002);
* XPC dictionary shapes contribute risky-field counts (RA-SFC-003).

Deny semantics mirror the compiler: a name in ``mach_lookup_deny`` that is not
explicitly allowed is never granted, even when a regex allow matches it.
Everything here is pure and deterministic.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..srf.compile import (
    BAD_SERVICE_SUBSTR,
    IMAGE_SERVICE_RE,
    MACH_SERVICE_SUFFIXES,
    SERVICE_NAME_RE,
)
from ..srf.models import ReachRecord, XPCField, XPCShape, clamp_privilege_delta, parser_complexity
from ..srf.sbpl import SandboxProfile
from .models import (
    CAPABILITY_RISK,
    XPC_RISKY_TYPES,
    Capability,
    ExpandedTarget,
    IngressClass,
    base_weight_for,
    clamp_parser_complexity,
    parse_reach_records,
    safe_float,
    safe_int,
)
from .regexsafety import regex_pattern_is_safe

REGEX_PREFIX = "regex:"
MAX_SERVICE_NAMES = 20000
DEFAULT_MAX_REGEX_PER_PATTERN = 32
MAX_REGEX_MATCHES_TOTAL = 4096
DEFAULT_MAX_REGEX_CHECKS = 262_144

_OP_CAPABILITIES: tuple[tuple[str, Capability], ...] = (
    ("network-inbound", Capability.NETWORK_INBOUND),
    ("network-outbound", Capability.NETWORK_OUTBOUND),
    ("network-bind", Capability.NETWORK_BIND),
    ("file-write", Capability.FILE_WRITE),
    ("iokit", Capability.IOKIT),
    ("mach-priv", Capability.MACH_PRIV),
    ("sysctl-write", Capability.SYSCTL_WRITE),
    ("nvram", Capability.NVRAM),
    ("keychain", Capability.KEYCHAIN),
    ("process-exec", Capability.PROCESS_EXEC),
    ("process-fork", Capability.PROCESS_EXEC),
    ("xpc-message", Capability.XPC_MESSAGE),
)

ZERO_CLICK_HINTS = (
    "safari",
    "webkit",
    "imcore",
    "imdpersistence",
    "imavconference",
    "callservices",
    "avconference",
    "facetime",
)
NETWORK_HINTS = (
    "bluetooth",
    "sharing",
    "airdrop",
    "wireless",
    "wifi",
    "awdl",
    "nearfield",
    "nfc",
    "hotspot",
)


def profile_capabilities(profile: SandboxProfile) -> frozenset[Capability]:
    """Map a profile's SBPL operations onto capability families (RA-SFC-002)."""
    caps: set[Capability] = set()
    for op in profile.operations:
        if not isinstance(op, str):
            continue
        low = op.lower()
        for prefix, capability in _OP_CAPABILITIES:
            if low.startswith(prefix):
                caps.add(capability)
                break
    return frozenset(caps)


def _mach_like(name: str) -> bool:
    low = name.lower()
    return (
        any(low.endswith(suffix) for suffix in MACH_SERVICE_SUFFIXES)
        or ".xpc" in low
        or "mach" in low
    )


def harvest_service_names(strings: Iterable[str]) -> tuple[str, ...]:
    """Deterministic candidate service names from cache strings.

    Harvests ``com.apple.*`` reverse-DNS names plus mach-service-looking tokens,
    minus known non-service substrings. Bounded and sorted for determinism.
    """
    out: set[str] = set()
    for s in strings:
        if not isinstance(s, str) or not (3 <= len(s) <= 118):
            continue
        if not SERVICE_NAME_RE.match(s):
            continue
        if any(b in s for b in BAD_SERVICE_SUBSTR):
            continue
        if IMAGE_SERVICE_RE.match(s) or _mach_like(s):
            out.add(s)
    return tuple(sorted(out)[:MAX_SERVICE_NAMES])


def xpc_risk_from_spec(format_spec: str) -> int:
    """Count risky-typed fields in an ``xpc-dictionary[...]`` spec (RA-SFC-003)."""
    if not isinstance(format_spec, str):
        return 0
    if not format_spec.startswith("xpc-dictionary[") or not format_spec.endswith("]"):
        return 0
    body = format_spec[len("xpc-dictionary[") : -1]
    if not body:
        return 0
    risky_names: set[str] = set()
    for part in body.split(","):
        name, sep, typ = part.rpartition(":")
        if sep and name and typ in XPC_RISKY_TYPES:
            risky_names.add(name)
    return len(risky_names)


def xpc_risky_fields_for(
    image_paths: Sequence[str], fields_by_image: Mapping[str, Mapping[str, str]]
) -> int:
    """Merged risky-field count across the XPC shapes of an image set.

    A field name counts when any contributing image types it as risky; the
    first-seen type no longer masks a riskier type from a later image.
    """
    risky_names: set[str] = set()
    for image in image_paths:
        if not isinstance(image, str):
            continue
        fields = fields_by_image.get(image)
        if not isinstance(fields, Mapping):
            continue
        for name, typ in fields.items():
            if isinstance(name, str) and isinstance(typ, str) and typ in XPC_RISKY_TYPES:
                risky_names.add(name)
    return len(risky_names)


def classify_ingress(image_paths: Iterable[str]) -> IngressClass:
    """Heuristic attacker-reach class from referencing image paths."""
    paths = [p.lower() for p in image_paths if isinstance(p, str)]
    if not paths:
        return IngressClass.UNKNOWN
    if any(any(h in p for h in ZERO_CLICK_HINTS) for p in paths):
        return IngressClass.ZERO_CLICK
    if any(any(h in p for h in NETWORK_HINTS) for p in paths):
        return IngressClass.NETWORK
    return IngressClass.LOCAL


@dataclass
class _Builder:
    ring_node: str
    name: str
    reach: set[ReachRecord] = field(default_factory=set)
    base_weight: float = 0.0
    privilege_delta: int = 0
    parser_complexity: float = 0.0
    capabilities: set[Capability] = field(default_factory=set)
    image_paths: set[str] = field(default_factory=set)
    entry_point_id: str = ""

    def grant(self, profile: SandboxProfile, capabilities: frozenset[Capability]) -> None:
        self.capabilities.update(capabilities)
        self.reach.add(
            ReachRecord(source=f"sandbox-profile:{profile.name}", hops=1, via=profile.source)
        )

    def freeze(self, xpc_risky_fields: int) -> ExpandedTarget:
        reach = tuple(sorted(self.reach, key=lambda r: (r.hops, r.source, r.via)))
        return ExpandedTarget(
            ring_node=self.ring_node,
            name=self.name,
            reach_from=reach,
            base_weight=self.base_weight,
            privilege_delta=self.privilege_delta,
            parser_complexity=self.parser_complexity,
            capabilities=frozenset(self.capabilities),
            xpc_risky_fields=xpc_risky_fields,
            image_paths=tuple(sorted(self.image_paths)),
            entry_point_id=self.entry_point_id,
        )


def _grant_delta(profile: SandboxProfile, name: str) -> int:
    score = 0
    if profile.privilege_score > 0:
        score += 1
    if any(isinstance(op, str) and op.startswith("network") for op in profile.operations):
        score += 1
    if name.startswith("com.apple.private."):
        score += 1
    return clamp_privilege_delta(score)


def _grant_complexity(name: str) -> float:
    spec = f"mach-lookup-service[{name}]"
    return parser_complexity(spec, 1)


def _service_name_candidates(names: Iterable[str]) -> tuple[str, ...]:
    """Bounded, sorted, valid service-name candidates for regex expansion."""
    out: set[str] = set()
    for name in names:
        if isinstance(name, str) and SERVICE_NAME_RE.match(name):
            out.add(name)
    return tuple(sorted(out)[:MAX_SERVICE_NAMES])


def _regex_matches(
    pattern: str,
    names: Sequence[str],
    *,
    match_limit: int,
    check_limit: int,
) -> tuple[tuple[str, ...], int]:
    """Return matches and candidate checks consumed, both budget-bounded."""
    if match_limit <= 0 or check_limit <= 0 or not names:
        return (), 0
    if not regex_pattern_is_safe(pattern):
        return (), 0
    try:
        rx = re.compile(pattern)
    except re.error:
        return (), 0
    out: list[str] = []
    checks = 0
    for name in names:
        if checks >= check_limit or len(out) >= match_limit:
            break
        checks += 1
        if rx.search(name):
            out.append(name)
    return tuple(out), checks


def _denied(profile: SandboxProfile, name: str) -> bool:
    return name in profile.mach_lookup_deny and name not in profile.mach_lookup_allow


def expand_surface(
    rows: Iterable[Mapping[str, Any]],
    profiles: Iterable[SandboxProfile],
    *,
    ring_node: str,
    service_names: Iterable[str] = (),
    shapes: Iterable[XPCShape] = (),
    max_regex_per_pattern: int = DEFAULT_MAX_REGEX_PER_PATTERN,
    max_regex_checks: int = DEFAULT_MAX_REGEX_CHECKS,
) -> tuple[ExpandedTarget, ...]:
    """Expand compiler rows into deduplicated attack-surface targets.

    ``rows`` are surface-compiler ``entry_point`` row dicts; ``profiles`` the
    SBPL profiles discovered during compilation; ``service_names`` the harvested
    candidate corpus used to expand ``regex:`` grants; ``shapes`` the XPC
    dictionary shapes. Output is sorted by name for determinism.
    """
    builders: dict[str, _Builder] = {}

    for row in rows:
        if not isinstance(row, Mapping):
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name or not SERVICE_NAME_RE.match(name):
            continue
        reach = parse_reach_records(row.get("reach_from_json"))
        builder = builders.get(name)
        if builder is None:
            builder = _Builder(
                ring_node=ring_node,
                name=name,
                privilege_delta=clamp_privilege_delta(safe_int(row.get("privilege_delta"))),
                parser_complexity=clamp_parser_complexity(row.get("parser_complexity")),
                base_weight=max(0.0, safe_float(row.get("weight"))),
                entry_point_id=str(row.get("id", "")),
            )
            builders[name] = builder
        for record in reach:
            builder.reach.add(record)
            if record.source.startswith("image:"):
                builder.image_paths.add(record.source[len("image:") :])

    profile_list = sorted(profiles, key=lambda p: (p.name, p.source, p.sha256))
    names = set(builders)
    names.update(_service_name_candidates(service_names))
    sorted_names = tuple(sorted(names))

    regex_budget = MAX_REGEX_MATCHES_TOTAL
    check_budget = max(0, max_regex_checks)
    for profile in profile_list:
        caps = profile_capabilities(profile)
        for literal in profile.mach_lookup_allow:
            if literal.startswith(REGEX_PREFIX):
                pattern = literal[len(REGEX_PREFIX) :]
                match_limit = min(max(0, max_regex_per_pattern), regex_budget)
                if match_limit <= 0 or check_budget <= 0:
                    continue
                matches, checks = _regex_matches(
                    pattern,
                    sorted_names,
                    match_limit=match_limit,
                    check_limit=check_budget,
                )
                regex_budget -= len(matches)
                check_budget -= checks
                for match in matches:
                    if _denied(profile, match):
                        continue
                    _grant(builders, ring_node, match, profile, caps, pattern)
            elif literal in builders and not _denied(profile, literal):
                _grant(builders, ring_node, literal, profile, caps, None)

    fields_by_image = _shape_fields_by_image(shapes)
    out: list[ExpandedTarget] = []
    for name in sorted(builders):
        builder = builders[name]
        risky = xpc_risky_fields_for(tuple(sorted(builder.image_paths)), fields_by_image)
        out.append(builder.freeze(risky))
    return tuple(out)


def _grant(
    builders: dict[str, _Builder],
    ring_node: str,
    name: str,
    profile: SandboxProfile,
    caps: frozenset[Capability],
    pattern: str | None,
) -> None:
    builder = builders.get(name)
    if builder is None:
        delta = _grant_delta(profile, name)
        complexity = _grant_complexity(name)
        builder = _Builder(
            ring_node=ring_node,
            name=name,
            privilege_delta=delta,
            parser_complexity=complexity,
            base_weight=base_weight_for(delta, complexity, 1),
        )
        builders[name] = builder
    builder.grant(profile, caps)
    if pattern is not None:
        builder.reach.add(ReachRecord(source=f"regex-grant:{pattern}", hops=1, via=profile.source))


def _shape_fields_by_image(shapes: Iterable[XPCShape]) -> dict[str, dict[str, str]]:
    by_image: dict[str, dict[str, str]] = {}
    for shape in shapes:
        fields = by_image.setdefault(shape.image_path, {})
        for f in shape.fields:
            fields.setdefault(f.name, f.type)
    return by_image


def shape_risk_from_fields(fields: Iterable[XPCField]) -> int:
    """Risky-field count for an explicit field iterable (test/utility helper)."""
    return sum(1 for f in fields if f.type in XPC_RISKY_TYPES)


def capability_risk_total(capabilities: Iterable[Capability]) -> float:
    """Summed risk mass of a capability set (0..CAPABILITY_RISK_TOTAL)."""
    return sum(CAPABILITY_RISK[c] for c in capabilities)
