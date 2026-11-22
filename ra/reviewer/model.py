"""Reviewer model adapters and artifact resolvers."""

from __future__ import annotations

import json
from collections.abc import Mapping

from ra.errors import FormatFail
from ra.press.harness import PressHarness
from ra.press.routing import TaskType

from .checks import detect_bug_class, detect_primitive
from .models import (
    BUG_CLASSES,
    INSUFFICIENT_EVIDENCE,
    NO_PRIMITIVE,
    PRIMITIVES,
    REVIEW_GOAL,
    ArtifactLink,
    IndependentDerivation,
    ReviewPacket,
)


class MappingArtifactResolver:
    """Resolve artifact ids or sha256 values from an in-memory mapping."""

    def __init__(self, artifacts: Mapping[str, bytes] | None = None, *, by_sha: bool = False):
        self._artifacts = dict(artifacts or {})
        self._by_sha = by_sha

    async def resolve(self, link: ArtifactLink) -> bytes | None:
        key = link.sha256 if self._by_sha else link.artifact_id
        return self._artifacts.get(key)


class MetadataOnlyArtifactResolver:
    """Resolver stub for stores that only keep ledger metadata."""

    async def resolve(self, link: ArtifactLink) -> bytes | None:
        return None


def _answer(result: object) -> str:
    output = getattr(result, "output", None)
    if isinstance(output, dict) and isinstance(output.get("answer"), str):
        return str(output["answer"])
    raise FormatFail("PRESS review task returned no enum answer")


class HeuristicReviewModel:
    """Offline deterministic reviewer model for tests and replay."""

    family = "heuristic_reviewer"

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        text = "\n".join(item.excerpt for item in packet.artifacts)
        bug_class = detect_bug_class(text)
        primitive = detect_primitive(text, bug_class)
        confident = bug_class != INSUFFICIENT_EVIDENCE
        return IndependentDerivation(
            bug_class=bug_class,
            primitive=primitive,
            confidence=0.55 if confident else 0.0,
            reasons=("heuristic_keywords",),
            model_family=self.family,
        ).normalized()


class PressReviewModel:
    """PRESS-backed reviewer using bug_class and rung_select tasks."""

    def __init__(self, harness: PressHarness, *, family: str = "press_reviewer"):
        self._harness = harness
        self.family = family

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        artifacts = packet.artifact_strings(max_artifacts=3, max_chars=1000)
        bug_result = await self._harness.complete(
            TaskType.BUG_CLASS,
            REVIEW_GOAL,
            artifacts=artifacts,
            vocab=BUG_CLASSES,
        )
        primitive_result = await self._harness.complete(
            TaskType.RUNG_SELECT,
            "Independently select the weakest proven exploit primitive from artifacts only.",
            artifacts=artifacts,
            vocab=PRIMITIVES,
        )
        bug_class = _answer(bug_result)
        primitive = _answer(primitive_result)
        if bug_class == INSUFFICIENT_EVIDENCE or primitive in {NO_PRIMITIVE, INSUFFICIENT_EVIDENCE}:
            confidence = 0.0
        else:
            confidence = 0.75
        return IndependentDerivation(
            bug_class=bug_class,
            primitive=primitive,
            confidence=confidence,
            reasons=(
                f"press_bug_class:{bug_result.packet.sha[:12]}",
                f"press_rung_select:{primitive_result.packet.sha[:12]}",
            ),
            model_family=self.family,
        ).normalized()


class PacketDumpReviewModel:
    """Test helper: returns a fixed derivation while recording packets."""

    def __init__(self, bug_class: str, primitive: str, *, family: str = "stub_reviewer"):
        self.family = family
        self.bug_class = bug_class
        self.primitive = primitive
        self.packets: list[ReviewPacket] = []

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        self.packets.append(packet)
        return IndependentDerivation(
            bug_class=self.bug_class,
            primitive=self.primitive,
            confidence=0.9,
            reasons=("stub",),
            model_family=self.family,
        ).normalized()


class RaisingReviewModel:
    """Failure-injection model that always raises."""

    family = "raising_reviewer"

    def __init__(self, error: Exception | None = None):
        self._error = error or RuntimeError("review model failed")
        self.calls = 0

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        self.calls += 1
        raise self._error


class JsonlPacketReviewModel:
    """Deterministic model that hashes artifact-only packet JSON."""

    family = "jsonl_reviewer"

    async def derive(self, packet: ReviewPacket) -> IndependentDerivation:
        payload = json.loads(packet.canonical_json())
        blob = json.dumps(payload["artifacts"], sort_keys=True)
        bug_class = detect_bug_class(blob)
        primitive = detect_primitive(blob, bug_class)
        return IndependentDerivation(
            bug_class=bug_class,
            primitive=primitive,
            confidence=0.5 if bug_class != INSUFFICIENT_EVIDENCE else 0.0,
            reasons=("jsonl_hash",),
            model_family=self.family,
        ).normalized()
