"""Compiled PRESS packets (RA-MDL-001, RA-MDL-002, RA-MDL-011)."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, replace
from typing import Any

from ..errors import FormatFail
from .routing import RouteSpec, TaskType, route_for

_CACHE_TTL_S = 24 * 60 * 60


@dataclass(frozen=True)
class Packet:
    """Uncompiled packet fields."""

    task_type: TaskType
    goal: str
    artifacts: tuple[str, ...] = ()
    vocab: tuple[str, ...] = ()
    exemplar: str = ""
    near_miss: str = ""


@dataclass(frozen=True)
class CompiledPacket:
    """Canonical packet bytes under the Appendix D budget."""

    task_type: TaskType
    packet: Packet
    body: bytes
    sha: str
    route: RouteSpec


class PacketCompiler:
    """Compile packets and cache them by SHA for 24 hours."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, str], tuple[float, CompiledPacket]] = {}

    def compile(self, packet: Packet) -> CompiledPacket:
        """Compile ``packet`` to canonical bytes within its task budget."""
        if len(packet.artifacts) > 3:
            raise FormatFail("packet artifacts are capped at 3")
        route = route_for(packet.task_type)
        candidate = packet
        compiled = self._compile_once(candidate, route)
        if len(compiled.body) <= route.max_bytes:
            return self._cache_get_or_store(compiled)
        # RA-MDL-002 truncation order: near_miss first, then exemplar, then goal.
        if candidate.near_miss:
            candidate = replace(candidate, near_miss="")
            compiled = self._compile_once(candidate, route)
        if len(compiled.body) > route.max_bytes and candidate.exemplar:
            candidate = replace(candidate, exemplar="")
            compiled = self._compile_once(candidate, route)
        while len(compiled.body) > route.max_bytes and candidate.goal:
            overflow = len(compiled.body) - route.max_bytes
            keep = max(0, len(candidate.goal) - overflow - 16)
            candidate = replace(candidate, goal=candidate.goal[:keep])
            compiled = self._compile_once(candidate, route)
        if len(compiled.body) > route.max_bytes:
            raise FormatFail("packet cannot fit Appendix D byte budget")
        return self._cache_get_or_store(compiled)

    def _compile_once(self, packet: Packet, route: RouteSpec) -> CompiledPacket:
        body_obj: dict[str, Any] = {
            "goal": packet.goal,
            "artifacts": list(packet.artifacts),
        }
        if packet.vocab:
            body_obj["vocab"] = list(packet.vocab)
        if packet.exemplar:
            body_obj["exemplar"] = packet.exemplar
        if packet.near_miss:
            body_obj["near_miss"] = packet.near_miss
        body = json.dumps(
            body_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        sha = hashlib.sha256(body).hexdigest()
        return CompiledPacket(packet.task_type, packet, body, sha, route)

    def _cache_get_or_store(self, compiled: CompiledPacket) -> CompiledPacket:
        now = time.monotonic()
        key = (compiled.task_type.value, compiled.sha)
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < _CACHE_TTL_S:
            return cached[1]
        self._cache[key] = (now, compiled)
        return compiled
