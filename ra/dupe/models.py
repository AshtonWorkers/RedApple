"""Data models for the RedApple dupe oracle (RA-DUP)."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

from ..ledger.ids import now_ms, sha256_hex

_SCORE_EPSILON = 1e-12


def _unit_interval(value: float) -> float:
    """Clamp a score term to [0, 1]; non-finite input is treated as absent."""
    if not math.isfinite(value):
        return 0.0
    return min(1.0, max(0.0, value))


def compute_dupe_score(saturation: float, patch_proximity: float, shipped_coverage: float) -> float:
    """RA-DUP-001: 0.4*saturation + 0.35*patch_proximity + 0.25*(1-shipped_coverage)."""
    sat = _unit_interval(saturation)
    patch = _unit_interval(patch_proximity)
    shipped = _unit_interval(shipped_coverage)
    return 0.4 * sat + 0.35 * patch + 0.25 * (1.0 - shipped)


@dataclass(frozen=True)
class NormalizedFrame:
    """One stack frame with addresses and offsets removed."""

    module: str
    function: str
    detail: str = ""

    def key(self) -> str:
        suffix = f"#{self.detail}" if self.detail else ""
        return f"{self.module}!{self.function}{suffix}"

    def to_dict(self) -> dict[str, str]:
        return {"module": self.module, "function": self.function, "detail": self.detail}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NormalizedFrame:
        return cls(
            module=str(data.get("module", "")),
            function=str(data.get("function", "")),
            detail=str(data.get("detail", "")),
        )


@dataclass(frozen=True)
class CrashInput:
    """Lane-agnostic crash reference.

    This mirrors the fields lanes expose without importing ``ra.lanes`` outside
    ``ra.fleet`` (RA-TOP boundary).
    """

    id: str
    kind: str = "unknown"
    handle_id: str | None = None
    path: str | None = None
    digest: str | None = None
    payload: bytes = b""
    context: str = "app"
    created_ms: int = field(default_factory=now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj: object) -> CrashInput:
        """Accept CrashInput, mappings, or structural CrashRef-like objects."""
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, Mapping):
            data = obj
            return cls._from_mapping(data)
        return cls._from_attrs(obj)

    @classmethod
    def _from_mapping(cls, data: Mapping[Any, Any]) -> CrashInput:
        payload = _first_present(
            data.get("payload"), data.get("data"), data.get("body"), data.get("crash_payload")
        )
        metadata = data.get("metadata", data.get("meta", {}))
        crash_id = _first_present(data.get("id"), data.get("crash_id"), data.get("ref_id"))
        path = _first_present(data.get("path"), data.get("crash_path"), data.get("file"))
        digest = _first_present(data.get("digest"), data.get("sha256"), data.get("sha"))
        return cls(
            id=_as_str(crash_id) or _fallback_id(payload=payload, path=path, digest=digest),
            kind=_as_str(_first_present(data.get("kind"), data.get("crash_kind"))) or "unknown",
            handle_id=_as_str(data.get("handle_id")),
            path=_as_str(path),
            digest=_as_str(digest),
            payload=_as_bytes(payload),
            context=_as_str(data.get("context")) or "app",
            created_ms=_as_int(_first_present(data.get("created_ms"), data.get("created")))
            or now_ms(),
            metadata=_as_mapping(metadata),
        )

    @classmethod
    def _from_attrs(cls, obj: object) -> CrashInput:
        payload = _first_present(_field(obj, "payload", "data", "body", "crash_payload"))
        metadata = _first_present(_field(obj, "metadata", "meta"), {})
        crash_id = _first_present(_field(obj, "id", "crash_id", "ref_id"))
        path = _first_present(_field(obj, "path", "crash_path", "file"))
        digest = _first_present(_field(obj, "digest", "sha256", "sha"))
        return cls(
            id=_as_str(crash_id) or _fallback_id(payload=payload, path=path, digest=digest),
            kind=_as_str(_first_present(_field(obj, "kind"), _field(obj, "crash_kind"))) or "unknown",
            handle_id=_as_str(_field(obj, "handle_id")),
            path=_as_str(path),
            digest=_as_str(digest),
            payload=_as_bytes(payload),
            context=_as_str(_field(obj, "context")) or "app",
            created_ms=_as_int(_first_present(_field(obj, "created_ms"), _field(obj, "created")))
            or now_ms(),
            metadata=_as_mapping(metadata),
        )


@dataclass(frozen=True)
class PatchDiff:
    """Normalized patch/diff evidence used for proximity scoring."""

    paths: tuple[str, ...] = ()
    symbols: tuple[str, ...] = ()
    source: str = ""
    ring_node: str | None = None
    text_hash: str = ""

    @property
    def has_evidence(self) -> bool:
        return bool(self.paths or self.symbols)

    def fingerprint(self) -> str:
        if self.text_hash:
            return self.text_hash
        material = json.dumps(
            {"paths": list(self.paths), "symbols": list(self.symbols)},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "paths": list(self.paths),
            "symbols": list(self.symbols),
            "source": self.source,
            "ring_node": self.ring_node,
            "text_hash": self.text_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> PatchDiff:
        return cls._from_mapping(data)

    @classmethod
    def from_object(cls, obj: object) -> PatchDiff | None:
        if obj is None:
            return None
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, Mapping):
            return cls._from_mapping(obj)
        paths = getattr(obj, "paths", None)
        symbols = getattr(obj, "symbols", None)
        if paths is None and symbols is None:
            return None
        return cls(
            paths=_as_str_tuple(paths),
            symbols=_as_str_tuple(symbols),
            source=_as_str(getattr(obj, "source", "")) or "",
            ring_node=_as_str(getattr(obj, "ring_node", None)),
            text_hash=_as_str(getattr(obj, "text_hash", "")) or "",
        )

    @classmethod
    def _from_mapping(cls, data: Mapping[Any, Any]) -> PatchDiff:
        return cls(
            paths=_as_str_tuple(_first_present(data.get("paths"), data.get("files"), ())),
            symbols=_as_str_tuple(_first_present(data.get("symbols"), data.get("identifiers"), ())),
            source=_as_str(_first_present(data.get("source"), data.get("name"), "")) or "",
            ring_node=_as_str(_first_present(data.get("ring_node"), data.get("node"))),
            text_hash=_as_str(_first_present(data.get("text_hash"), data.get("sha256"), "")) or "",
        )


@dataclass(frozen=True)
class Finding:
    """Crash plus triage/score context.

    ``bug_class`` may be supplied directly; otherwise the oracle asks the
    configured triage classifier (stubbed when triage is absent).
    """

    crash: CrashInput
    bug_class: str | None = None
    primitive: str | None = None
    alloc_site: str | None = None
    saturation: float | None = None
    patch_proximity: float | None = None
    shipped_coverage: float | None = None
    patches: tuple[PatchDiff, ...] = ()
    patch_texts: tuple[str, ...] = ()
    created_ms: int = field(default_factory=now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_object(cls, obj: object) -> Finding:
        """Accept Finding, mappings, or structural finding-like objects."""
        if isinstance(obj, cls):
            return obj
        crash_obj = _extract_crash_object(obj)
        crash = CrashInput.from_object(crash_obj if crash_obj is not None else obj)
        if isinstance(obj, Mapping):
            source: Mapping[Any, Any] = obj
            metadata = _as_mapping(_first_present(source.get("metadata"), source.get("meta"), {}))
        else:
            source_attrs = obj
            metadata = _as_mapping(
                _first_present(
                    getattr(source_attrs, "metadata", None), getattr(source_attrs, "meta", None), {}
                )
            )
        patches, patch_texts = _extract_patches(obj)
        return cls(
            crash=crash,
            bug_class=_as_str(_field(obj, "bug_class", "bugClass", "class")),
            primitive=_as_str(_field(obj, "primitive", "weakest_primitive", "ladder_rung")),
            alloc_site=_as_str(_field(obj, "alloc_site", "allocation_site", "malloc_site", "site")),
            saturation=_as_optional_float(_field(obj, "saturation")),
            patch_proximity=_as_optional_float(_field(obj, "patch_proximity", "patchProximity")),
            shipped_coverage=_as_optional_float(
                _field(obj, "shipped_coverage", "shippedCoverage", "coverage")
            ),
            patches=patches,
            patch_texts=patch_texts,
            created_ms=_as_int(_field(obj, "created_ms", "created")) or now_ms(),
            metadata=metadata,
        )


@dataclass(frozen=True)
class CrashSignature:
    """Normalized crash identity used for exact and fuzzy dedup."""

    signature_hash: str
    stack_hash: str
    bug_class: str
    exception_type: str
    exception_code: str
    signal: str
    process: str
    context: str
    alloc_site: str
    frames: tuple[NormalizedFrame, ...]
    source_kind: str
    source_id: str
    source_path: str
    source_digest: str
    created_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_hash": self.signature_hash,
            "stack_hash": self.stack_hash,
            "bug_class": self.bug_class,
            "exception_type": self.exception_type,
            "exception_code": self.exception_code,
            "signal": self.signal,
            "process": self.process,
            "context": self.context,
            "alloc_site": self.alloc_site,
            "frames": [frame.to_dict() for frame in self.frames],
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "source_path": self.source_path,
            "source_digest": self.source_digest,
            "created_ms": self.created_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CrashSignature:
        frames_raw = data.get("frames", ())
        frames: list[NormalizedFrame] = []
        if isinstance(frames_raw, Sequence) and not isinstance(frames_raw, (str, bytes, bytearray)):
            for item in frames_raw:
                if isinstance(item, Mapping):
                    frames.append(NormalizedFrame.from_dict(item))
        return cls(
            signature_hash=str(data.get("signature_hash", "")),
            stack_hash=str(data.get("stack_hash", "")),
            bug_class=str(data.get("bug_class", "unknown")),
            exception_type=str(data.get("exception_type", "")),
            exception_code=str(data.get("exception_code", "")),
            signal=str(data.get("signal", "")),
            process=str(data.get("process", "")),
            context=str(data.get("context", "app")),
            alloc_site=str(data.get("alloc_site", "")),
            frames=tuple(frames),
            source_kind=str(data.get("source_kind", "")),
            source_id=str(data.get("source_id", "")),
            source_path=str(data.get("source_path", "")),
            source_digest=str(data.get("source_digest", "")),
            created_ms=_as_int(data.get("created_ms")) or 0,
        )


@dataclass(frozen=True)
class DupeScore:
    """RA-DUP score terms; every term is clamped to [0, 1]."""

    saturation: float
    patch_proximity: float
    shipped_coverage: float
    total: float

    def to_dict(self) -> dict[str, float]:
        return {
            "saturation": self.saturation,
            "patch_proximity": self.patch_proximity,
            "shipped_coverage": self.shipped_coverage,
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DupeScore:
        saturation = _unit_interval(_as_float(data.get("saturation")))
        patch = _unit_interval(_as_float(data.get("patch_proximity")))
        shipped = _unit_interval(_as_float(data.get("shipped_coverage")))
        total = _unit_interval(_as_float(data.get("total"))) if "total" in data else compute_dupe_score(saturation, patch, shipped)
        return cls(
            saturation=saturation,
            patch_proximity=patch,
            shipped_coverage=shipped,
            total=total,
        )


@dataclass(frozen=True)
class DupeVerdict:
    """Result returned to triage and chain/policy."""

    is_duplicate: bool
    canonical_id: str
    match_kind: str
    similarity: float
    score: DupeScore
    signature: CrashSignature
    claim_id: str | None = None
    artifact_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    created_ms: int = field(default_factory=now_ms)

    @property
    def suppressed(self) -> bool:
        """Dupe scoring orders submission but never suppresses a claim."""
        return False


@dataclass(frozen=True)
class SubmissionCandidate:
    """One finding offered to the chain/policy submission queue."""

    id: str
    canonical_id: str
    score: float
    is_duplicate: bool
    created_ms: int
    match_kind: str = "new"

    @classmethod
    def from_verdict(cls, verdict: DupeVerdict, *, candidate_id: str | None = None) -> SubmissionCandidate:
        return cls(
            id=candidate_id or verdict.signature.source_id or verdict.canonical_id,
            canonical_id=verdict.canonical_id,
            score=verdict.score.total,
            is_duplicate=verdict.is_duplicate,
            created_ms=verdict.created_ms,
            match_kind=verdict.match_kind,
        )


@dataclass(frozen=True)
class CorpusEvidence:
    """Artifact-bound internal-corpus overlap evidence.

    The heuristic is only allowed to influence scoring when it names at least
    one ledger artifact; the oracle ignores unbound evidence.
    """

    shipped_coverage: float = 0.0
    artifact_ids: tuple[str, ...] = ()
    source: str = ""
    saturation: float = 0.0


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _field(obj: object, *names: str) -> Any:
    if isinstance(obj, Mapping):
        for name in names:
            if name in obj:
                return obj[name]
        return None
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _extract_crash_object(obj: object) -> object | None:
    names = ("crash", "crash_ref", "finding", "ref")
    if isinstance(obj, Mapping):
        for name in names:
            value = obj.get(name)
            if value is not None:
                return cast(object, value)
        return None
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return cast(object, value)
    return None


def _extract_patches(obj: object) -> tuple[tuple[PatchDiff, ...], tuple[str, ...]]:
    patches: list[PatchDiff] = []
    texts: list[str] = []
    raw_values: list[Any] = []
    keys = ("patches", "patch", "patch_diff", "patch_diffs", "patch_texts", "diff_text", "ring_diff", "diff")
    if isinstance(obj, Mapping):
        for key in keys:
            if key in obj:
                raw_values.append(obj[key])
    else:
        for name in keys:
            if hasattr(obj, name):
                raw_values.append(getattr(obj, name))
    for raw in raw_values:
        _collect_patch_values(raw, patches, texts)
    return tuple(patches), tuple(texts)


def _collect_patch_values(raw: Any, patches: list[PatchDiff], texts: list[str]) -> None:
    if raw is None:
        return
    if isinstance(raw, PatchDiff):
        patches.append(raw)
        return
    if isinstance(raw, str):
        if raw.strip():
            texts.append(raw)
        return
    if isinstance(raw, Mapping):
        parsed = PatchDiff.from_object(raw)
        if parsed is not None:
            patches.append(parsed)
        return
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
        for item in raw:
            _collect_patch_values(item, patches, texts)
        return
    parsed = PatchDiff.from_object(raw)
    if parsed is not None:
        patches.append(parsed)


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 10)
        except ValueError:
            return None
    return None


def _as_float(value: Any) -> float:
    if isinstance(value, bool):
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return 0.0
    return 0.0


def _as_optional_float(value: Any) -> float | None:
    if value is None:
        return None
    return _as_float(value)


def _as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode("utf-8")
    return b""


def _as_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview)):
        out: list[str] = []
        for item in value:
            text = _as_str(item)
            if text is not None:
                out.append(text)
        return tuple(out)
    text = _as_str(value)
    return () if text is None else (text,)


def _fallback_id(*, payload: Any, path: Any, digest: Any) -> str:
    material = json.dumps(
        {
            "payload_sha256": sha256_hex(_as_bytes(payload)) if payload else "",
            "path": _as_str(path) or "",
            "digest": _as_str(digest) or "",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return "crash_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


_SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_:<>]*")

__all__ = [
    "compute_dupe_score",
    "CorpusEvidence",
    "CrashInput",
    "CrashSignature",
    "DupeScore",
    "DupeVerdict",
    "Finding",
    "NormalizedFrame",
    "PatchDiff",
    "SubmissionCandidate",
    "_SCORE_EPSILON",
    "_SYMBOL_RE",
]
