"""Deterministic advisory-to-surface prioritization.

This module is pure: it consumes classified CVE records and ledger ``entry_point``
rows and returns ranked targets. Persistence and network refresh live elsewhere.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..errors import FormatFail
from .models import CveRecord

_MAX_REASON_TERMS = 8
_MAX_CVE_TERMS = 32
_GENERIC_TOKENS = frozenset(
    {
        "apple",
        "security",
        "release",
        "update",
        "software",
        "available",
        "device",
        "version",
    }
)
_COMPONENT_TERMS: dict[str, tuple[str, ...]] = {
    "webkit": ("webkit", "webcontent", "web content", "safari"),
    "safari": ("safari", "webkit"),
    "kernel": ("kernel", "xnu"),
    "imageio": ("imageio",),
    "coregraphics": ("coregraphics", "core graphics", "imageio"),
    "coretext": ("coretext", "core text"),
    "bluetooth": ("bluetooth",),
    "wifi": ("wi-fi", "wifi", "wireless", "airport"),
    "wireless": ("wireless", "wi-fi", "wifi", "bluetooth"),
    "imessage": ("imessage", "messages"),
    "messages": ("messages", "imessage"),
    "gatekeeper": ("gatekeeper",),
    "tcc": ("tcc", "transparency", "consent"),
    "sandbox": ("sandbox",),
    "privatecloudcompute": ("privatecloudcompute", "pcc", "cloudcompute"),
    "pcc": ("pcc", "privatecloudcompute"),
    "remotemanagement": ("remotemanagement", "remote management", "remote-management"),
    "accelerate": ("accelerate", "accelerateframework"),
    "accelerateframework": ("accelerate", "accelerateframework"),
    "systemsettings": ("systemsettings", "system settings", "preferences"),
}
_ADVISORY_TEXT_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("webcontent", _COMPONENT_TERMS["webkit"]),
    ("web content", _COMPONENT_TERMS["webkit"]),
    ("webpage", _COMPONENT_TERMS["webkit"]),
    ("webkit", _COMPONENT_TERMS["webkit"]),
    ("safari", _COMPONENT_TERMS["safari"]),
    ("kernel", _COMPONENT_TERMS["kernel"]),
    ("xnu", _COMPONENT_TERMS["kernel"]),
    ("sandbox", ("sandbox",)),
    ("tcc", ("tcc", "transparency", "consent")),
    ("gatekeeper", ("gatekeeper",)),
    ("bluetooth", ("bluetooth",)),
    ("wi-fi", ("wi-fi", "wifi", "wireless", "airport")),
    ("wifi", ("wi-fi", "wifi", "wireless", "airport")),
    ("wireless", ("wi-fi", "wifi", "wireless", "airport")),
    ("imessage", ("imessage", "messages")),
    ("messages", ("imessage", "messages")),
    ("imageio", ("imageio",)),
    ("coregraphics", _COMPONENT_TERMS["coregraphics"]),
    ("core graphics", _COMPONENT_TERMS["coregraphics"]),
    ("coretext", _COMPONENT_TERMS["coretext"]),
    ("core text", _COMPONENT_TERMS["coretext"]),
    ("private cloud compute", _COMPONENT_TERMS["privatecloudcompute"]),
    ("pcc", _COMPONENT_TERMS["privatecloudcompute"]),
    ("remote management", _COMPONENT_TERMS["remotemanagement"]),
    ("accelerate", _COMPONENT_TERMS["accelerate"]),
    ("system settings", _COMPONENT_TERMS["systemsettings"]),
    ("systempreferences", _COMPONENT_TERMS["systemsettings"]),
    ("blastdoor", ("blastdoor",)),
)
_RELEASE_OS_RE = re.compile(r"\b(iOS|iPadOS|macOS|tvOS|watchOS|visionOS|Safari)\b", re.IGNORECASE)
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class PrioritizedTarget:
    """One CVE matched to one surface entry point."""

    cve_id: str
    entry_point_id: str
    ring_node: str
    surface_name: str
    surface_weight: float
    score: float
    match_reasons: tuple[str, ...]
    cve: CveRecord

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "entry_point_id": self.entry_point_id,
            "ring_node": self.ring_node,
            "surface_name": self.surface_name,
            "surface_weight": self.surface_weight,
            "score": self.score,
            "match_reasons": list(self.match_reasons),
            "cve": self.cve.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PrioritizedTarget:
        context = "target"
        reasons = data.get("match_reasons", [])
        if not isinstance(reasons, Sequence) or isinstance(reasons, (str, bytes)):
            raise FormatFail(f"{context}.match_reasons must be a list")
        reason_items: list[str] = []
        for item in reasons:
            if not isinstance(item, str):
                raise FormatFail(f"{context}.match_reasons[] must be str")
            reason_items.append(item)
        cve_raw = data.get("cve")
        if not isinstance(cve_raw, Mapping):
            raise FormatFail(f"{context}.cve must be an object")
        return cls(
            cve_id=_text(data, "cve_id", context=context),
            entry_point_id=_text(data, "entry_point_id", context=context),
            ring_node=_text(data, "ring_node", context=context),
            surface_name=_text(data, "surface_name", context=context),
            surface_weight=_non_negative_float(data, "surface_weight", context=context),
            score=_non_negative_float(data, "score", context=context),
            match_reasons=tuple(reason_items),
            cve=CveRecord.from_dict(cve_raw),
        )


@dataclass(frozen=True)
class PrioritizationResult:
    """Ranked advisory targets for surface prioritization."""

    generated_at: str
    snapshot_source: str | None
    snapshot_fetched_at: str | None
    cves_considered: int
    surfaces_considered: int
    matched_cves: int
    unmatched_high_value: int
    truncated: bool
    targets: tuple[PrioritizedTarget, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "snapshot_source": self.snapshot_source,
            "snapshot_fetched_at": self.snapshot_fetched_at,
            "cves_considered": self.cves_considered,
            "surfaces_considered": self.surfaces_considered,
            "matched_cves": self.matched_cves,
            "unmatched_high_value": self.unmatched_high_value,
            "truncated": self.truncated,
            "targets": [target.to_dict() for target in self.targets],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PrioritizationResult:
        context = "prioritization"
        targets_raw = data.get("targets", [])
        if not isinstance(targets_raw, Sequence) or isinstance(targets_raw, (str, bytes)):
            raise FormatFail(f"{context}.targets must be a list")
        targets: list[PrioritizedTarget] = []
        for item in targets_raw:
            if not isinstance(item, Mapping):
                raise FormatFail(f"{context}.targets[] must be an object")
            targets.append(PrioritizedTarget.from_dict(item))
        result = cls(
            generated_at=_text(data, "generated_at", context=context),
            snapshot_source=_opt_text(data, "snapshot_source", context=context),
            snapshot_fetched_at=_opt_text(data, "snapshot_fetched_at", context=context),
            cves_considered=_int(data, "cves_considered", context=context),
            surfaces_considered=_int(data, "surfaces_considered", context=context),
            matched_cves=_int(data, "matched_cves", context=context),
            unmatched_high_value=_int(data, "unmatched_high_value", context=context),
            truncated=_bool(data, "truncated", context=context),
            targets=tuple(targets),
        )
        if (
            result.matched_cves > result.cves_considered
            or result.unmatched_high_value > result.cves_considered
        ):
            raise FormatFail("prioritization counts are inconsistent")
        return result


def _mapping(value: object, *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{context} must be an object")
    return value


def _text(data: Mapping[str, Any], key: str, *, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise FormatFail(f"{context}.{key} must be str")
    return value


def _opt_text(data: Mapping[str, Any], key: str, *, context: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise FormatFail(f"{context}.{key} must be str or None")
    return value


def _int(data: Mapping[str, Any], key: str, *, context: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FormatFail(f"{context}.{key} must be a non-negative int")
    return value


def _non_negative_float(data: Mapping[str, Any], key: str, *, context: str) -> float:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FormatFail(f"{context}.{key} must be number")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise FormatFail(f"{context}.{key} must be a non-negative finite number")
    return number


def _bool(data: Mapping[str, Any], key: str, *, context: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise FormatFail(f"{context}.{key} must be bool")
    return value


@dataclass(frozen=True)
class _Surface:
    id: str
    name: str
    ring_node: str
    weight: float
    text: str
    platform: str | None


def _surface_from_row(row: Mapping[str, Any], *, index: int) -> _Surface:
    context = f"entry_points[{index}]"
    reach = row.get("reach_from_json", "[]")
    if not isinstance(reach, str):
        raise FormatFail(f"{context}.reach_from_json must be str")
    weight_value = row.get("weight", 0.0)
    if isinstance(weight_value, bool) or not isinstance(weight_value, (int, float)):
        raise FormatFail(f"{context}.weight must be number")
    weight_float = float(weight_value)
    if not math.isfinite(weight_float):
        raise FormatFail(f"{context}.weight must be finite")
    name = _text(row, "name", context=context)
    ring_node = _text(row, "ring_node", context=context)
    surface_id = row.get("id", "")
    if not isinstance(surface_id, str):
        raise FormatFail(f"{context}.id must be str")
    text = f"{name} {reach}".lower()
    return _Surface(
        id=surface_id or f"row-{index}",
        name=name,
        ring_node=ring_node,
        weight=max(0.0, weight_float),
        text=text,
        platform=_platform_for_text(ring_node),
    )


def _platform_for_text(text: str) -> str | None:
    low = text.lower()
    if "macos" in low or "mac-os" in low or "osx" in low:
        return "macos"
    if "ipados" in low or "iphone" in low or "ipad" in low or "ios" in low:
        return "ios"
    if "tvos" in low:
        return "tvos"
    if "watchos" in low:
        return "watchos"
    if "visionos" in low:
        return "visionos"
    return None


def _release_platform(cve: CveRecord) -> str | None:
    source = cve.release_os or cve.release
    match = _RELEASE_OS_RE.search(source)
    if match is None:
        return None
    os_name = match.group(1).lower()
    if os_name == "ipados":
        return "ios"
    if os_name == "safari":
        return "safari"
    return os_name


def _platforms_compatible(surface: str | None, release: str | None) -> bool:
    if surface is None or release is None or release == "safari":
        return True
    return surface == release


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _humanize(text: str) -> str:
    spaced = _CAMEL_RE.sub(" ", text.strip())
    return re.sub(r"[^a-z0-9]+", " ", spaced.lower()).strip()


def _unknown_component_terms(component: str) -> tuple[str, ...]:
    key = _compact(component)
    terms: list[str] = []
    if len(key) >= 4:
        terms.append(key)
    human = _humanize(component)
    if len(human) >= 4 and " " in human:
        terms.append(human)
        terms.append(human.replace(" ", ""))
    out: list[str] = []
    seen: set[str] = set()
    for term in terms:
        cleaned = term.strip().lower()
        if len(cleaned) < 4 or cleaned in _GENERIC_TOKENS or cleaned in seen:
            continue
        seen.add(cleaned)
        out.append(cleaned)
    return tuple(out)


def _cve_search_text(cve: CveRecord) -> str:
    parts = (
        cve.component,
        cve.original_component,
        cve.available_for,
        cve.impact,
        cve.description,
        cve.advisory_title or "",
        cve.release,
        cve.release_os or "",
    )
    return " ".join(parts).lower()


def _terms_for_cve(cve: CveRecord) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()

    def add(term: str) -> None:
        cleaned = term.strip().lower()
        if not cleaned or cleaned in seen:
            return
        seen.add(cleaned)
        out.append(cleaned)

    key = _compact(cve.component or cve.original_component)
    mapped = _COMPONENT_TERMS.get(key)
    if mapped is not None:
        for term in mapped:
            add(term)
    else:
        for term in _unknown_component_terms(cve.original_component or cve.component):
            add(term)
    text = _cve_search_text(cve)
    for keyword, terms in _ADVISORY_TEXT_TERMS:
        if keyword in text:
            for term in terms:
                add(term)
    return tuple(out[:_MAX_CVE_TERMS])


def _matched_terms(surface_text: str, terms: Sequence[str]) -> tuple[str, ...]:
    return tuple(term for term in terms if term in surface_text)


def _reward_factor(max_reward: int) -> float:
    if max_reward <= 0:
        return 1.0
    return min(20.0, 1.0 + max_reward / 100_000.0)


def _priority_factor(priority: str) -> float:
    if priority == "critical":
        return 2.0
    if priority == "high":
        return 1.5
    if priority == "review":
        return 1.15
    if priority == "normal":
        return 1.0
    return 0.8


def _confidence_factor(confidence: str) -> float:
    if confidence == "high":
        return 1.0
    if confidence == "medium":
        return 0.9
    if confidence == "low":
        return 0.75
    if confidence == "unmapped":
        return 0.5
    return 0.6


def _recency_factor(release_date: str, now: datetime) -> float:
    if not release_date:
        return 0.75
    try:
        released = datetime.strptime(release_date, "%Y-%m-%d").date()
    except ValueError:
        return 0.75
    age_days = max(0, (now.date() - released).days)
    return 0.7 + 0.3 * math.exp(-age_days / 180.0)


def _wild_factor(in_the_wild: bool) -> float:
    return 1.5 if in_the_wild else 1.0


def _score_target(cve: CveRecord, surface: _Surface, now: datetime) -> float:
    score = (
        surface.weight
        * _reward_factor(cve.max_reward)
        * _priority_factor(cve.priority)
        * _confidence_factor(cve.confidence)
        * _recency_factor(cve.release_date, now)
        * _wild_factor(cve.in_the_wild)
    )
    return round(score, 6)


def _is_high_value(cve: CveRecord) -> bool:
    return (
        cve.max_reward > 0
        or cve.in_the_wild
        or cve.priority in {"critical", "high", "review"}
    )


def prioritize(
    records: Iterable[CveRecord],
    entry_points: Iterable[Mapping[str, Any]],
    *,
    max_targets: int = 100,
    now: datetime | None = None,
    snapshot_source: str | None = None,
    snapshot_fetched_at: str | None = None,
) -> PrioritizationResult:
    """Rank CVE/surface matches deterministically.

    Matching is intentionally heuristic: component names are mapped to Mach
    service/image-path keywords, then compatible surfaces are scored by bounty
    ceiling, exploit priority, confidence, recency, and RA-SRF surface weight.
    """
    if max_targets < 1:
        raise FormatFail("max_targets must be >= 1")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    cve_list = list(records)
    surface_rows = list(entry_points)
    surfaces = [
        _surface_from_row(_mapping(row, context=f"entry_points[{index}]"), index=index)
        for index, row in enumerate(surface_rows)
    ]

    prepared: list[tuple[CveRecord, tuple[str, ...], str | None, float]] = []
    for cve in cve_list:
        prepared.append(
            (
                cve,
                _terms_for_cve(cve),
                _release_platform(cve),
                _recency_factor(cve.release_date, current),
            )
        )

    targets: list[PrioritizedTarget] = []
    matched_indexes: set[int] = set()
    for index, (cve, terms, release_platform, _recency) in enumerate(prepared):
        if not terms:
            continue
        for surface in surfaces:
            if not _platforms_compatible(surface.platform, release_platform):
                continue
            matches = _matched_terms(surface.text, terms)
            if not matches:
                continue
            score = _score_target(cve, surface, current)
            targets.append(
                PrioritizedTarget(
                    cve_id=cve.id,
                    entry_point_id=surface.id,
                    ring_node=surface.ring_node,
                    surface_name=surface.name,
                    surface_weight=surface.weight,
                    score=score,
                    match_reasons=tuple(f"match:{term}" for term in matches[:_MAX_REASON_TERMS]),
                    cve=cve,
                )
            )
            matched_indexes.add(index)

    targets.sort(key=lambda target: (-target.score, target.cve_id, target.entry_point_id))
    truncated = len(targets) > max_targets
    kept = targets[:max_targets]
    unmatched_high_value = sum(
        1
        for index, (cve, _terms, _platform, _recency) in enumerate(prepared)
        if index not in matched_indexes and _is_high_value(cve)
    )
    return PrioritizationResult(
        generated_at=current.isoformat(),
        snapshot_source=snapshot_source,
        snapshot_fetched_at=snapshot_fetched_at,
        cves_considered=len(cve_list),
        surfaces_considered=len(surfaces),
        matched_cves=len(matched_indexes),
        unmatched_high_value=unmatched_high_value,
        truncated=truncated,
        targets=tuple(kept),
    )
