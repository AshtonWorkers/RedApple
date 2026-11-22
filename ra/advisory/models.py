"""Typed advisory snapshot models.

These models are the ledger-facing representation of Apple security-release
intelligence. They deliberately mirror the PR #1 JSON shape while remaining
strict enough for ``mypy --strict`` and deterministic serialization.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ..errors import FormatFail


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


def _bool(data: Mapping[str, Any], key: str, *, context: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise FormatFail(f"{context}.{key} must be bool")
    return value


def _object_list(data: Mapping[str, Any], key: str, *, context: str) -> list[Mapping[str, Any]]:
    value = data.get(key, [])
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise FormatFail(f"{context}.{key} must be a list")
    out: list[Mapping[str, Any]] = []
    for item in value:
        out.append(_mapping(item, context=f"{context}.{key}[]"))
    return out


def _text_list(data: Mapping[str, Any], key: str, *, context: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise FormatFail(f"{context}.{key} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise FormatFail(f"{context}.{key}[] must be str")
        out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class CveCredit:
    """One CVE identifier and the credit text published beside it."""

    id: str
    credit: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "credit": self.credit}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CveCredit:
        context = "cve"
        return cls(
            id=_text(data, "id", context=context),
            credit=_text(data, "credit", context=context) if "credit" in data else "",
        )


@dataclass(frozen=True)
class ReleaseEntry:
    """One affected component inside an Apple security advisory."""

    component: str
    available_for: str = ""
    impact: str = ""
    description: str = ""
    cves: tuple[CveCredit, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "available_for": self.available_for,
            "impact": self.impact,
            "description": self.description,
            "cves": [cve.to_dict() for cve in self.cves],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReleaseEntry:
        context = "entry"
        return cls(
            component=_text(data, "component", context=context),
            available_for=(
                _text(data, "available_for", context=context) if "available_for" in data else ""
            ),
            impact=_text(data, "impact", context=context) if "impact" in data else "",
            description=(
                _text(data, "description", context=context) if "description" in data else ""
            ),
            cves=tuple(
                CveCredit.from_dict(item)
                for item in _object_list(data, "cves", context=context)
            ),
        )


@dataclass(frozen=True)
class DiffFrom:
    """Nearest older same-major release used for patch-diff hints."""

    name: str
    version: str
    url: str | None
    date: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "url": self.url,
            "date": self.date,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DiffFrom:
        context = "diff_from"
        return cls(
            name=_text(data, "name", context=context),
            version=_text(data, "version", context=context),
            url=_opt_text(data, "url", context=context),
            date=_text(data, "date", context=context),
        )


@dataclass(frozen=True)
class ReleaseRecord:
    """One Apple security release and its parsed advisory entries."""

    name: str
    date: str
    available_for: str = ""
    url: str | None = None
    os: str | None = None
    version: str | None = None
    builds: tuple[str, ...] = ()
    diff_from: DiffFrom | None = None
    entries: tuple[ReleaseEntry, ...] = ()
    advisory_title: str | None = None
    error: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available_for": self.available_for,
            "date": self.date,
            "url": self.url,
            "os": self.os,
            "version": self.version,
            "builds": list(self.builds),
            "diff_from": None if self.diff_from is None else self.diff_from.to_dict(),
            "entries": [entry.to_dict() for entry in self.entries],
            "advisory_title": self.advisory_title,
            "error": self.error,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReleaseRecord:
        context = "release"
        diff_raw = data.get("diff_from")
        diff_from = (
            DiffFrom.from_dict(_mapping(diff_raw, context=f"{context}.diff_from"))
            if diff_raw is not None
            else None
        )
        return cls(
            name=_text(data, "name", context=context),
            available_for=(
                _text(data, "available_for", context=context) if "available_for" in data else ""
            ),
            date=_text(data, "date", context=context),
            url=_opt_text(data, "url", context=context),
            os=_opt_text(data, "os", context=context),
            version=_opt_text(data, "version", context=context),
            builds=_text_list(data, "builds", context=context),
            diff_from=diff_from,
            entries=tuple(
                ReleaseEntry.from_dict(item)
                for item in _object_list(data, "entries", context=context)
            ),
            advisory_title=_opt_text(data, "advisory_title", context=context),
            error=_opt_text(data, "error", context=context),
            note=_opt_text(data, "note", context=context),
        )

    def with_advisory(
        self,
        *,
        entries: Sequence[ReleaseEntry] = (),
        advisory_title: str | None = None,
        builds: Sequence[str] | None = None,
        error: str | None = None,
        note: str | None = None,
    ) -> ReleaseRecord:
        """Return a copy with advisory fetch results applied."""
        return ReleaseRecord(
            name=self.name,
            date=self.date,
            available_for=self.available_for,
            url=self.url,
            os=self.os,
            version=self.version,
            builds=tuple(self.builds if builds is None else builds),
            diff_from=self.diff_from,
            entries=tuple(entries),
            advisory_title=advisory_title,
            error=error,
            note=note,
        )


@dataclass(frozen=True)
class FetchError:
    """One release whose advisory fetch failed during refresh."""

    release: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return {"release": self.release, "error": self.error}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> FetchError:
        context = "error"
        return cls(
            release=_text(data, "release", context=context),
            error=_text(data, "error", context=context),
        )


@dataclass(frozen=True)
class AdvisorySnapshot:
    """A fetched Apple security-release snapshot."""

    source: str
    fetched_at: str
    releases: tuple[ReleaseRecord, ...]
    errors: tuple[FetchError, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "fetched_at": self.fetched_at,
            "errors": [error.to_dict() for error in self.errors],
            "releases": [release.to_dict() for release in self.releases],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AdvisorySnapshot:
        context = "snapshot"
        return cls(
            source=_text(data, "source", context=context),
            fetched_at=_text(data, "fetched_at", context=context),
            errors=tuple(
                FetchError.from_dict(item)
                for item in _object_list(data, "errors", context=context)
            ),
            releases=tuple(
                ReleaseRecord.from_dict(item)
                for item in _object_list(data, "releases", context=context)
            ),
        )

    @property
    def cve_count(self) -> int:
        """Total CVE identifiers across all release entries."""
        return sum(len(entry.cves) for release in self.releases for entry in release.entries)


@dataclass(frozen=True)
class CveRecord:
    """One classified CVE joined to its advisory release context."""

    id: str
    credit: str = ""
    component: str = ""
    original_component: str = ""
    available_for: str = ""
    impact: str = ""
    description: str = ""
    release: str = ""
    release_date: str = ""
    advisory: str | None = None
    release_os: str | None = None
    release_version: str | None = None
    builds: tuple[str, ...] = ()
    diff_from: DiffFrom | None = None
    advisory_title: str | None = None
    category: str = "Unmapped"
    category_id: str | None = None
    max_reward: int = 0
    confidence: str = "unmapped"
    reason: str = ""
    needs_review: bool = True
    priority: str = "normal"
    credit_type: str = "unknown"
    in_the_wild: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "credit": self.credit,
            "component": self.component,
            "original_component": self.original_component,
            "available_for": self.available_for,
            "impact": self.impact,
            "description": self.description,
            "release": self.release,
            "release_date": self.release_date,
            "advisory": self.advisory,
            "release_os": self.release_os,
            "release_version": self.release_version,
            "builds": list(self.builds),
            "diff_from": None if self.diff_from is None else self.diff_from.to_dict(),
            "advisory_title": self.advisory_title,
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

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CveRecord:
        context = "cve_record"
        diff_raw = data.get("diff_from")
        diff_from = (
            DiffFrom.from_dict(_mapping(diff_raw, context=f"{context}.diff_from"))
            if diff_raw is not None
            else None
        )
        return cls(
            id=_text(data, "id", context=context),
            credit=_text(data, "credit", context=context) if "credit" in data else "",
            component=_text(data, "component", context=context) if "component" in data else "",
            original_component=(
                _text(data, "original_component", context=context)
                if "original_component" in data
                else ""
            ),
            available_for=(
                _text(data, "available_for", context=context) if "available_for" in data else ""
            ),
            impact=_text(data, "impact", context=context) if "impact" in data else "",
            description=(
                _text(data, "description", context=context) if "description" in data else ""
            ),
            release=_text(data, "release", context=context) if "release" in data else "",
            release_date=(
                _text(data, "release_date", context=context) if "release_date" in data else ""
            ),
            advisory=_opt_text(data, "advisory", context=context),
            release_os=_opt_text(data, "release_os", context=context),
            release_version=_opt_text(data, "release_version", context=context),
            builds=_text_list(data, "builds", context=context),
            diff_from=diff_from,
            advisory_title=_opt_text(data, "advisory_title", context=context),
            category=_text(data, "category", context=context) if "category" in data else "Unmapped",
            category_id=_opt_text(data, "category_id", context=context),
            max_reward=_int(data, "max_reward", context=context) if "max_reward" in data else 0,
            confidence=(
                _text(data, "confidence", context=context) if "confidence" in data else "unmapped"
            ),
            reason=_text(data, "reason", context=context) if "reason" in data else "",
            needs_review=_bool(data, "needs_review", context=context)
            if "needs_review" in data
            else True,
            priority=_text(data, "priority", context=context) if "priority" in data else "normal",
            credit_type=(
                _text(data, "credit_type", context=context) if "credit_type" in data else "unknown"
            ),
            in_the_wild=_bool(data, "in_the_wild", context=context)
            if "in_the_wild" in data
            else False,
        )
