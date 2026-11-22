"""Bounty category catalog and heuristic classifier.

Ported from PR #1 with strict types. The classifier is deliberately advisory:
it estimates a bounty category ceiling for prioritization and always leaves
eligibility to human review.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, NoReturn

from ..errors import FormatFail
from .models import AdvisorySnapshot, CveRecord

_CATALOG_RESOURCE = "bounty_categories.json"
_COMPONENT_ALIASES = {
    "remotemanagement": "Remote Management",
    "accelerate": "Accelerate",
    "accelerateframework": "Accelerate",
    "systempreferences": "System Settings",
    "systemsettings": "System Settings",
    "imageio": "ImageIO",
    "coregraphics": "CoreGraphics",
    "coretext": "CoreText",
    "bluetooth": "Bluetooth",
    "wifi": "Wi-Fi",
    "wireless": "Wireless",
    "imessage": "Messages",
    "pcc": "Private Cloud Compute",
    "privatecloudcompute": "Private Cloud Compute",
}
_WILD_RE = re.compile(
    r"(actively exploited|exploited in the wild|exploited against|may have been exploited)",
    re.IGNORECASE,
)
_APP_RE = re.compile(r"\b(?:an?|malicious) app(?:lication)?\b")
_IOS_RE = re.compile(r"\b(?:ios|ipados)\b", re.IGNORECASE)
_PCC_RE = re.compile(r"\bpcc\b")
_APPLE_CREDIT_RE = re.compile(r"\bApple\b", re.IGNORECASE)


def _mapping(value: object, *, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormatFail(f"{context} must be an object")
    return value


def _text(data: Mapping[str, Any], key: str, *, context: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise FormatFail(f"{context}.{key} must be str")
    return value


def _int(data: Mapping[str, Any], key: str, *, context: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FormatFail(f"{context}.{key} must be a non-negative int")
    return value


def _bool(data: Mapping[str, Any], key: str, *, context: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise FormatFail(f"{context}.{key} must be bool")
    return value


def _object_list(data: Mapping[str, Any], key: str, *, context: str) -> list[Mapping[str, Any]]:
    value = data.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise FormatFail(f"{context}.{key} must be a list")
    return [_mapping(item, context=f"{context}.{key}[]") for item in value]


@dataclass(frozen=True)
class BountyTier:
    """One reward tier inside a bounty category."""

    reward: int
    description: str
    target_flag_required: bool
    source: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "reward": self.reward,
            "description": self.description,
            "target_flag_required": self.target_flag_required,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BountyTier:
        context = "tier"
        return cls(
            reward=_int(data, "reward", context=context),
            description=_text(data, "description", context=context),
            target_flag_required=_bool(data, "target_flag_required", context=context),
            source=_text(data, "source", context=context),
        )


@dataclass(frozen=True)
class BountyCategory:
    """One Apple Security Bounty category row."""

    id: str
    program: str
    entry_point: str
    end_point: str
    max_reward: int
    description: str
    tiers: tuple[BountyTier, ...]
    source: str
    target_flag_required: bool
    examples_text: str

    @property
    def label(self) -> str:
        return f"{self.entry_point} / {self.end_point}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "program": self.program,
            "entry_point": self.entry_point,
            "end_point": self.end_point,
            "max_reward": self.max_reward,
            "description": self.description,
            "tiers": [tier.to_dict() for tier in self.tiers],
            "source": self.source,
            "target_flag_required": self.target_flag_required,
            "examples_text": self.examples_text,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BountyCategory:
        context = "category"
        return cls(
            id=_text(data, "id", context=context),
            program=_text(data, "program", context=context),
            entry_point=_text(data, "entry_point", context=context),
            end_point=_text(data, "end_point", context=context),
            max_reward=_int(data, "max_reward", context=context),
            description=_text(data, "description", context=context),
            tiers=tuple(
                BountyTier.from_dict(item) for item in _object_list(data, "tiers", context=context)
            ),
            source=_text(data, "source", context=context),
            target_flag_required=_bool(data, "target_flag_required", context=context),
            examples_text=_text(data, "examples_text", context=context)
            if "examples_text" in data
            else "",
        )


@dataclass(frozen=True)
class BountyCatalog:
    """Versioned bounty category dataset loaded from bundled JSON."""

    source: str
    fetched_at: str
    categories: tuple[BountyCategory, ...]

    def by_id(self, identifier: str) -> BountyCategory | None:
        for category in self.categories:
            if category.id == identifier:
                return category
        return None

    def by_entry_point(self, entry_point: str, end_point: str) -> BountyCategory | None:
        for category in self.categories:
            if category.entry_point == entry_point and category.end_point == end_point:
                return category
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "fetched_at": self.fetched_at,
            "categories": [category.to_dict() for category in self.categories],
        }


def _reject_json_constant(value: str) -> NoReturn:
    raise FormatFail(f"bounty catalog contains non-finite JSON constant {value}")


def parse_bounty_catalog(text: str) -> BountyCatalog:
    """Parse and validate bounty category JSON."""
    try:
        raw = json.loads(text, parse_constant=_reject_json_constant)
    except json.JSONDecodeError as exc:
        raise FormatFail("bounty catalog must be JSON") from exc
    except RecursionError as exc:
        raise FormatFail("bounty catalog JSON is nested too deeply") from exc
    data = _mapping(raw, context="catalog")
    categories_raw = data.get("categories")
    if not isinstance(categories_raw, Sequence) or isinstance(categories_raw, (str, bytes)):
        raise FormatFail("catalog.categories must be a list")
    categories = tuple(
        BountyCategory.from_dict(_mapping(item, context="catalog.categories[]"))
        for item in categories_raw
    )
    if not categories:
        raise FormatFail("catalog.categories must not be empty")
    ids = [category.id for category in categories]
    if len(ids) != len(set(ids)):
        raise FormatFail("catalog category ids must be unique")
    pairs = [(category.entry_point, category.end_point) for category in categories]
    if len(pairs) != len(set(pairs)):
        raise FormatFail("catalog entry_point/end_point pairs must be unique")
    return BountyCatalog(
        source=_text(data, "source", context="catalog"),
        fetched_at=_text(data, "fetched_at", context="catalog"),
        categories=categories,
    )


def load_bounty_catalog(path: str | Path | None = None) -> BountyCatalog:
    """Load the bundled catalog, or an explicit JSON file for tests/migrations."""
    if path is None:
        return default_bounty_catalog()
    return parse_bounty_catalog(Path(path).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def default_bounty_catalog() -> BountyCatalog:
    """Load the packaged Apple bounty category snapshot once per process."""
    text = files("ra.advisory").joinpath(_CATALOG_RESOURCE).read_text(encoding="utf-8")
    return parse_bounty_catalog(text)


def normalize_component(component: str) -> str:
    """Normalize an advisory component name for stable downstream keys."""
    key = re.sub(r"[^a-z0-9]", "", component.lower())
    if key.startswith("webkit"):
        return "WebKit"
    return _COMPONENT_ALIASES.get(key, component.strip())


@dataclass(frozen=True)
class Classification:
    """Heuristic bounty classification for one CVE/entry pair."""

    category: str
    category_id: str | None
    max_reward: int
    confidence: str
    reason: str
    needs_review: bool
    priority: str
    credit_type: str
    in_the_wild: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "category_id": self.category_id,
            "max_reward": self.max_reward,
            "confidence": self.confidence,
            "reason": self.reason,
            "needs_review": self.needs_review,
            "priority": self.priority,
            "credit_type": self.credit_type,
            "in_the_wild": self.in_the_wild,
        }


def classify(
    component: str = "",
    impact: str = "",
    credit: str = "",
    description: str = "",
    platform: str = "",
    *,
    catalog: BountyCatalog | None = None,
) -> Classification:
    """Classify an advisory entry against Apple bounty categories.

    The result is a ceiling estimate for prioritization only; it does not prove
    eligibility, target-flag compliance, chain completeness, or scope.
    """
    bounty = catalog if catalog is not None else default_bounty_catalog()
    text = f"{component} {impact}".lower()
    outcome = impact.lower()
    ios = bool(_IOS_RE.search(platform))
    mac = "macos" in platform.lower()
    browser = any(w in text for w in ("webkit", "web content", "webcontent", "safari", "webpage"))
    sandbox = "sandbox" in text and any(w in outcome for w in ("escape", "break out", "bypass"))
    code = any(
        w in outcome
        for w in (
            "code execution",
            "execute arbitrary code",
            "execute code",
            "memory corruption",
            "corrupt memory",
            "corrupt kernel memory",
            "corrupt process memory",
            "kernel privileges",
        )
    )
    data = any(
        w in outcome
        for w in (
            "sensitive user data",
            "sensitive data",
            "private information",
            "sensitive information",
            "location information",
            "protected data",
            "receive its messages",
            "photos",
            "request data",
        )
    )
    app = bool(_APP_RE.search(outcome))
    wireless = any(w in text for w in ("bluetooth", "wi-fi", "wireless", "proximity", "in range"))
    pcc = "private cloud compute" in text or bool(_PCC_RE.search(text))
    chosen: BountyCategory | None = None

    def choose(entry_point: str, end_point: str) -> BountyCategory | None:
        return bounty.by_entry_point(entry_point, end_point)

    def by_id(identifier: str) -> BountyCategory | None:
        return bounty.by_id(identifier)

    if pcc:
        if data and any(w in outcome for w in ("configuration", "deployment", "accidental disclosure")):
            chosen = by_id("pcc-config")
        elif "privileged network" in outcome:
            if "unattested" in outcome and code:
                chosen = by_id("pcc-network-code")
            elif data and "outside" in outcome:
                chosen = by_id("pcc-network-data")
        elif "remote" in outcome and "request" in outcome:
            if "unsigned code" in outcome and "arbitrary entitlements" in outcome:
                chosen = by_id("pcc-remote-code")
            elif data and "outside" in outcome:
                chosen = by_id("pcc-remote-data")
    elif "gatekeeper" in text and "bypass" in outcome:
        complete = all(w in outcome for w in ("complete", "safari", "quarantin", "standard"))
        chosen = by_id("macos-gatekeeper-complete" if complete else "macos-gatekeeper-partial")
    elif browser and sandbox:
        chosen = choose("Browser attack", "WebContent sandbox escape")
    elif ("physical access" in outcome or "lock screen" in outcome) and "locked" in outcome and data:
        chosen = choose("Unauthorized physical device access", "Access to sensitive user data")
    elif (
        wireless
        and code
        and "apple-designed" in text
        and "application processor" in outcome
        and any(w in outcome for w in ("in range", "proximity", "bluetooth range", "wi-fi range"))
    ):
        chosen = choose(
            "Wireless proximity-based attacks targeting Apple-designed radio components",
            "Application processor",
        )
    elif browser and code:
        chosen = choose("Browser attack", "Kernel" if "kernel" in text else "Web Content code execution")
    elif mac:
        if ("tcc" in text and (data or "tcc target flag" in outcome)) or (data and app):
            flag = "tcc target flag" in outcome
            identifier = (
                "macos-tcc-sandbox" if flag and sandbox else "macos-tcc-flag" if flag else "macos-tcc-data"
            )
            chosen = by_id(identifier)
        elif sandbox:
            chosen = by_id("macos-sandbox")
    elif ios and app:
        if "kernel" in text and code:
            chosen = choose("App sandbox escape", "Kernel")
        elif data:
            chosen = choose("App sandbox escape", "Access to sensitive user data")

    wild = bool(_WILD_RE.search(f"{impact} {description}"))
    reason = "Entry point or qualifying outcome not established; human review required"
    if chosen is not None:
        reason = "Likely category / heuristic, not eligibility; full chain, scope and Target Flags unverified"
    credit_type = (
        "Apple"
        if _APPLE_CREDIT_RE.search(credit)
        else "external"
        if credit.strip()
        else "unknown"
    )
    return Classification(
        category=chosen.label if chosen is not None else "Unmapped",
        category_id=chosen.id if chosen is not None else None,
        max_reward=chosen.max_reward if chosen is not None else 0,
        confidence="low" if chosen is not None else "unmapped",
        reason=reason,
        needs_review=chosen is None or wild,
        priority=(
            "high"
            if wild
            else "review"
            if chosen is None and (code or data or "root" in outcome)
            else "normal"
        ),
        credit_type=credit_type,
        in_the_wild=wild,
    )


def cves(
    snapshot: AdvisorySnapshot, *, catalog: BountyCatalog | None = None
) -> list[CveRecord]:
    """Flatten a snapshot into classified CVE records."""
    records: list[CveRecord] = []
    for release in snapshot.releases:
        for entry in release.entries:
            for cve in entry.cves:
                classification = classify(
                    entry.component,
                    entry.impact,
                    cve.credit,
                    entry.description,
                    release.name,
                    catalog=catalog,
                )
                records.append(
                    CveRecord(
                        id=cve.id,
                        credit=cve.credit,
                        component=normalize_component(entry.component),
                        original_component=entry.component,
                        available_for=entry.available_for,
                        impact=entry.impact,
                        description=entry.description,
                        release=release.name,
                        release_date=release.date,
                        advisory=release.url,
                        release_os=release.os,
                        release_version=release.version,
                        builds=release.builds,
                        diff_from=release.diff_from,
                        advisory_title=release.advisory_title,
                        category=classification.category,
                        category_id=classification.category_id,
                        max_reward=classification.max_reward,
                        confidence=classification.confidence,
                        reason=classification.reason,
                        needs_review=classification.needs_review,
                        priority=classification.priority,
                        credit_type=classification.credit_type,
                        in_the_wild=classification.in_the_wild,
                    )
                )
    return records


def catalog_summary(catalog: BountyCatalog | None = None) -> dict[str, Any]:
    """Return a compact catalog summary for health/reporting."""
    bounty = catalog if catalog is not None else default_bounty_catalog()
    return {
        "source": bounty.source,
        "fetched_at": bounty.fetched_at,
        "categories": len(bounty.categories),
        "max_reward": max((category.max_reward for category in bounty.categories), default=0),
    }

