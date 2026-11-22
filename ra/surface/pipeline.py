"""End-to-end surface pipeline: compile, expand, rank, persist, feed."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..ledger import Ledger
from ..srf.compile import SERVICE_PATH_HINTS, compile_surface
from ..srf.dyld import STRING_SECTION_NAMES
from ..srf.models import XPCShape
from ..srf.sbpl import SandboxProfile, looks_like_sbpl, profiles_from_strings
from ..srf.xpc import extract_xpc_shape, image_has_xpc_markers
from .expand import expand_surface, harvest_service_names
from .models import TargetList
from .rank import RankConfig, rank_targets
from .regexsafety import MAX_SBPL_PROFILE_CHARS, sbpl_profile_is_safe
from .store import LedgerSurfaceStore, SurfaceStore

MAX_SURFACE_STRING_CHARS = MAX_SBPL_PROFILE_CHARS


class _SafeStringCache:
    """Cache wrapper that filters strings before SBPL/XPC parsers see them."""

    def __init__(self, cache: Any) -> None:
        self._cache = cache

    @property
    def path(self) -> str:
        value = getattr(self._cache, "path", "")
        return "" if value is None else str(value)

    @property
    def images(self) -> Any:
        images = getattr(self._cache, "images", ())
        return () if images is None else images

    async def image_strings(
        self, image: Any, names: Iterable[str] = STRING_SECTION_NAMES
    ) -> list[str]:
        raw = await self._cache.image_strings(image, names)
        return _sanitize_strings(raw)


def _sanitize_strings(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return []
    try:
        items = list(raw)
    except TypeError:
        return []
    out: list[str] = []
    for item in items:
        if not isinstance(item, str) or len(item) > MAX_SURFACE_STRING_CHARS:
            continue
        if looks_like_sbpl(item) and not sbpl_profile_is_safe(item):
            continue
        out.append(item)
    return out


def _as_safe_cache(cache: Any) -> Any:
    return cache if isinstance(cache, _SafeStringCache) else _SafeStringCache(cache)


@dataclass(frozen=True)
class SurfaceInputs:
    """Everything expansion needs beyond compiler rows."""

    ring_node: str
    profiles: tuple[SandboxProfile, ...]
    service_names: tuple[str, ...]
    shapes: tuple[XPCShape, ...]


@dataclass(frozen=True)
class RankResult:
    """Outcome of a compile+rank run."""

    ring_node: str
    target_list: TargetList
    persisted: bool
    rows_written: int


def _path_hint(path: str) -> bool:
    return any(h in path for h in SERVICE_PATH_HINTS)


async def scan_surface_inputs(
    cache: Any,
    *,
    ring_node: str,
    section_names: Iterable[str] = STRING_SECTION_NAMES,
    image_limit: int | None = None,
) -> SurfaceInputs:
    """Harvest SBPL profiles, service names, and XPC shapes from a cache.

    Mirrors the compiler's per-image logic so expansion sees the same profiles
    and shapes the compiler used, plus the service-name corpus needed to expand
    ``regex:`` mach-lookup grants.
    """
    profiles: list[SandboxProfile] = []
    service_names: set[str] = set()
    shapes: list[XPCShape] = []
    safe_cache: Any = _as_safe_cache(cache)
    images = list(safe_cache.images)
    if image_limit is not None:
        images = images[: max(0, image_limit)]
    for image in images:
        strings = await safe_cache.image_strings(image, section_names)
        profiles.extend(profiles_from_strings(strings, source=image.path))
        service_names.update(harvest_service_names(strings))
        has_xpc = image_has_xpc_markers(strings)
        shape = extract_xpc_shape(image.path, strings) if has_xpc or _path_hint(image.path) else None
        if shape is not None:
            shapes.append(shape)
    profiles.sort(key=lambda p: (p.name, p.source, p.sha256))
    return SurfaceInputs(
        ring_node=ring_node,
        profiles=tuple(profiles),
        service_names=tuple(sorted(service_names)),
        shapes=tuple(shapes),
    )


async def compile_and_rank(
    cache: Any,
    store: SurfaceStore,
    *,
    ring_node: str,
    config: RankConfig | None = None,
    section_names: Iterable[str] = STRING_SECTION_NAMES,
    image_limit: int | None = None,
) -> RankResult:
    """Compile surface, expand, rank, persist, and return the target list.

    Runs two deterministic passes over the cache: one through the surface
    compiler (rows) and one through :func:`scan_surface_inputs` (profiles,
    service corpus, XPC shapes). The compiler's store is bypassed so ranked
    targets are the only rows persisted for the ring node.
    """
    safe_cache: Any = _as_safe_cache(cache)
    compiled = await compile_surface(
        safe_cache,
        ring_node=ring_node,
        store=None,
        section_names=section_names,
        image_limit=image_limit,
    )
    inputs = await scan_surface_inputs(
        safe_cache, ring_node=ring_node, section_names=section_names, image_limit=image_limit
    )
    expanded = expand_surface(
        compiled.rows,
        inputs.profiles,
        ring_node=ring_node,
        service_names=inputs.service_names,
        shapes=inputs.shapes,
    )
    target_list = rank_targets(expanded, config, ring_node=ring_node)
    await store.replace_targets(target_list)
    return RankResult(
        ring_node=ring_node,
        target_list=target_list,
        persisted=True,
        rows_written=len(target_list.rows),
    )


def ledger_store(ledger: Ledger) -> LedgerSurfaceStore:
    """Convenience constructor for the ledger-backed surface store."""
    return LedgerSurfaceStore(ledger)


__all__ = [
    "RankResult",
    "SurfaceInputs",
    "compile_and_rank",
    "ledger_store",
    "scan_surface_inputs",
]
