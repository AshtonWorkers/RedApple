"""Dependency interfaces for triage, patch/N-day intel, corpus overlap, and policy."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from .models import CorpusEvidence, CrashSignature, Finding, SubmissionCandidate


class TriageClassifier(Protocol):
    """Triage bug-class interface; stubbed when triage is absent."""

    async def classify(self, finding: Finding) -> str:
        """Return a bug class for the finding."""
        ...  # pragma: no cover


class PatchProximityProvider(Protocol):
    """Patch-diff/N-day proximity interface; stubbed when mining is absent."""

    async def proximity(self, finding: Finding, signature: CrashSignature) -> float | None:
        """Return patch proximity in [0, 1], or None when unknown."""
        ...  # pragma: no cover


class CorpusIndex(Protocol):
    """Internal-corpus overlap heuristic; must be artifact-bound."""

    async def evidence(self, finding: Finding, signature: CrashSignature) -> Sequence[CorpusEvidence]:
        """Return corpus overlap evidence for score inputs."""
        ...  # pragma: no cover


class SubmissionQueue(Protocol):
    """Chain/policy submission queue interface; stubbed when absent."""

    async def enqueue(self, candidate: SubmissionCandidate) -> str:
        """Enqueue one submission candidate and return its queue id."""
        ...  # pragma: no cover


class NullTriageClassifier:
    """Default triage stub: use explicit finding/metadata bug class, else unknown."""

    async def classify(self, finding: Finding) -> str:
        if finding.bug_class and finding.bug_class.strip():
            return finding.bug_class.strip()
        for key in ("bug_class", "bugClass", "class"):
            value = finding.metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        crash_metadata = finding.crash.metadata
        for key in ("bug_class", "bugClass", "class"):
            value = crash_metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "unknown"


class NullPatchProximityProvider:
    """Default patch-intel stub: no external proximity signal."""

    async def proximity(self, finding: Finding, signature: CrashSignature) -> float | None:
        return None


class NullCorpusIndex:
    """Default corpus stub: no internal-corpus evidence."""

    async def evidence(self, finding: Finding, signature: CrashSignature) -> Sequence[CorpusEvidence]:
        return ()


class NullSubmissionQueue:
    """Default policy stub: accept candidates without side effects."""

    async def enqueue(self, candidate: SubmissionCandidate) -> str:
        return f"stub:{candidate.id}"


__all__ = [
    "CorpusIndex",
    "NullCorpusIndex",
    "NullPatchProximityProvider",
    "NullSubmissionQueue",
    "NullTriageClassifier",
    "PatchProximityProvider",
    "SubmissionQueue",
    "TriageClassifier",
]
