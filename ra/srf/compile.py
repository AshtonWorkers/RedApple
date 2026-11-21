"""RA-SRF Surface Graph compiler.

Compiles sandbox profiles, mach-lookup grants, and XPC dictionary shapes found in
a dyld shared cache into deterministic `entry_point` rows (RA-SRF-001/002/005).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .dyld import STRING_SECTION_NAMES, DyldCache
from .models import (
    EntryPoint,
    ReachRecord,
    XPCField,
    clamp_privilege_delta,
    parser_complexity,
    sort_entry_points,
    xpc_format_spec,
)
from .sbpl import (
    SandboxProfile,
    profile_denies_service,
    profile_grants_service,
    profiles_from_strings,
)
from .store import EntryPointStore
from .xpc import extract_xpc_shape, image_has_xpc_markers

IMAGE_SERVICE_RE = re.compile(r"^com\.apple\.[A-Za-z0-9][A-Za-z0-9_.-]{2,118}$")
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,118}$")
BAD_SERVICE_SUBSTR = (
    "com.apple.security.",
    "com.apple.private.",
    "Notification",
    "Description",
    "Keys",
    "Error",
    "Version",
    "anonymous",
    "%",
    ".did",
    ".will",
    ".changed",
    ".event",
    ".callback",
    ".queue",
    "Queue",
    "Tests",
    "FaultLogged",
    ".telemetry",
)
SERVICE_PATH_HINTS = (
    "XPC",
    "xpc",
    "Service",
    "Daemon",
    "Agent",
    "Server",
    "RunningBoard",
    "Containment",
    "containermanager",
    "launchservices",
    "bluetooth",
    "imageio",
    "safari",
    "imessage",
)
MAX_MERGED_FIELDS = 64
MACH_SERVICE_SUFFIXES = (
    "d",
    "xpc",
    "service",
    "server",
    "agent",
    "daemon",
    "manager",
    "helper",
    "socket",
    "port",
    "pipe",
)


@dataclass
class CompileResult:
    ring_node: str
    rows: Tuple[Dict[str, Any], ...]
    images_scanned: int
    strings_scanned: int
    profiles: Tuple[SandboxProfile, ...]
    xpc_shapes: int
    service_candidates: int
    sha256: str
    cache_path: str


@dataclass
class _Candidate:
    name: str
    reach: Set[ReachRecord] = field(default_factory=set)
    fields: Dict[str, str] = field(default_factory=dict)
    image_paths: Set[str] = field(default_factory=set)
    granting_profiles: Set[SandboxProfile] = field(default_factory=set)

    def add_reach(self, record: ReachRecord) -> None:
        self.reach.add(record)

    def add_fields(self, fields: Iterable[XPCField]) -> None:
        for f in fields:
            if f.name not in self.fields and len(self.fields) < MAX_MERGED_FIELDS:
                self.fields[f.name] = f.type

    def add_image(self, path: str) -> None:
        self.image_paths.add(path)

    def grant(self, profile: SandboxProfile) -> None:
        self.granting_profiles.add(profile)
        self.add_reach(
            ReachRecord(source=f"sandbox-profile:{profile.name}", hops=1, via=profile.source)
        )


def _path_hint(path: str) -> bool:
    return any(h in path for h in SERVICE_PATH_HINTS)


def _bad_service(name: str) -> bool:
    return any(b in name for b in BAD_SERVICE_SUBSTR)


def _looks_like_mach_service(name: str) -> bool:
    low = name.lower()
    return (
        any(low.endswith(suffix) for suffix in MACH_SERVICE_SUFFIXES)
        or ".xpc" in low
        or "mach" in low
    )


def _image_service_names(strings: Sequence[str]) -> Set[str]:
    out: Set[str] = set()
    for s in strings:
        if not IMAGE_SERVICE_RE.match(s):
            continue
        if _bad_service(s):
            continue
        out.add(s)
    return out


def _candidate_to_entry_point(cand: _Candidate, ring_node: str) -> EntryPoint:
    fields = tuple(XPCField(name=name, type=typ) for name, typ in sorted(cand.fields.items()))
    if fields:
        spec = xpc_format_spec(fields)
        complexity = parser_complexity(spec, len(fields))
    else:
        spec = f"mach-lookup-service[{cand.name}]"
        complexity = parser_complexity(spec, 1)
    return EntryPoint(
        ring_node=ring_node,
        name=cand.name,
        format_spec=spec,
        reach_from=tuple(sorted(cand.reach, key=lambda r: (r.hops, r.source, r.via))),
        privilege_delta=0,  # filled by caller
        parser_complexity=complexity,
    )


def _with_delta(ep: EntryPoint, delta: int) -> EntryPoint:
    return EntryPoint(
        ring_node=ep.ring_node,
        name=ep.name,
        format_spec=ep.format_spec,
        reach_from=ep.reach_from,
        privilege_delta=clamp_privilege_delta(delta),
        parser_complexity=ep.parser_complexity,
    )


def _privilege_delta(cand: _Candidate) -> int:
    score = 0
    granting = sorted(
        cand.granting_profiles, key=lambda p: (p.name, p.source, p.sha256)
    )
    if granting:
        score += 1
    if any(p.privilege_score > 0 for p in granting):
        score += 1
    if any(op.startswith("network") for p in granting for op in p.operations):
        score += 1
    if cand.name.startswith("com.apple.private."):
        score += 1
    if any(_path_hint(p) for p in sorted(cand.image_paths)):
        score += 1
    return clamp_privilege_delta(score)


async def compile_surface(
    cache: DyldCache,
    *,
    ring_node: str = "macos-dyld-cache",
    store: Optional[EntryPointStore] = None,
    section_names: Iterable[str] = STRING_SECTION_NAMES,
    image_limit: Optional[int] = None,
) -> CompileResult:
    """Compile the surface graph from an opened dyld cache.

    `image_limit` is an explicit reduced-input knob for proof runs; omitted, the
    compiler scans every image in the cache deterministically.
    """
    candidates: Dict[str, _Candidate] = {}
    profiles: List[SandboxProfile] = []
    images_scanned = 0
    strings_scanned = 0
    xpc_shapes = 0

    images = sorted(cache.images, key=lambda im: (im.path, im.address))
    if image_limit is not None:
        images = images[: max(0, image_limit)]

    for image in images:
        strings = await cache.image_strings(image, section_names)
        images_scanned += 1
        strings_scanned += len(strings)
        for profile in profiles_from_strings(strings, source=image.path):
            profiles.append(profile)
        has_xpc = image_has_xpc_markers(strings)
        shape = (
            extract_xpc_shape(image.path, strings)
            if has_xpc or _path_hint(image.path)
            else None
        )
        if shape is not None:
            xpc_shapes += 1
        if not (has_xpc or shape is not None or _path_hint(image.path)):
            continue
        for service in sorted(_image_service_names(strings)):
            cand = candidates.get(service)
            if cand is None:
                cand = _Candidate(name=service)
                candidates[service] = cand
            cand.add_image(image.path)
            cand.add_reach(ReachRecord(source=f"image:{image.path}", hops=2, via="dyld-cache"))
            if shape is not None:
                cand.add_fields(shape.fields)

    profiles_sorted = sorted(profiles, key=lambda p: (p.name, p.source, p.sha256))
    for profile in profiles_sorted:
        for literal in profile.mach_lookup_allow:
            if literal.startswith("regex:") or not SERVICE_NAME_RE.match(literal):
                continue
            if literal not in candidates:
                candidates[literal] = _Candidate(name=literal)

    for profile in profiles_sorted:
        for cand in candidates.values():
            explicitly_allowed = cand.name in profile.mach_lookup_allow
            if not explicitly_allowed and profile_denies_service(profile, cand.name):
                continue
            if profile_grants_service(profile, cand.name):
                cand.grant(profile)

    rows: List[Dict[str, Any]] = []
    for cand in candidates.values():
        if not cand.reach:
            continue
        if not cand.granting_profiles and not _looks_like_mach_service(cand.name):
            continue
        ep = _candidate_to_entry_point(cand, ring_node)
        ep = _with_delta(ep, _privilege_delta(cand))
        rows.append(ep.to_row())
    rows = sort_entry_points(rows)
    digest = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(digest).hexdigest()
    result = CompileResult(
        ring_node=ring_node,
        rows=tuple(rows),
        images_scanned=images_scanned,
        strings_scanned=strings_scanned,
        profiles=tuple(sorted(profiles, key=lambda p: (p.name, p.source, p.sha256))),
        xpc_shapes=xpc_shapes,
        service_candidates=len(candidates),
        sha256=sha,
        cache_path=getattr(cache, "path", ""),
    )
    if store is not None:
        await store.replace_ring_node(ring_node, rows)
    return result
