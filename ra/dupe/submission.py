"""Submission ordering for RA-DUP-002.

The dupe score orders the chain/policy submission queue. Ordering is stable:
unchanged scores keep their incoming relative order, and no candidate is ever
dropped or suppressed.
"""

from __future__ import annotations

from collections.abc import Sequence

from .models import DupeVerdict, SubmissionCandidate


def rank_submissions(candidates: Sequence[SubmissionCandidate]) -> list[SubmissionCandidate]:
    """Return all candidates ordered by dupe score descending.

    ``sorted`` is stable, so candidates whose scores did not change keep their
    original relative order (RA-DUP-002).
    """
    return sorted(candidates, key=lambda candidate: -candidate.score)


def candidates_from_verdicts(verdicts: Sequence[DupeVerdict]) -> list[SubmissionCandidate]:
    """Convert dupe verdicts to submission candidates without filtering."""
    return [SubmissionCandidate.from_verdict(verdict) for verdict in verdicts]


__all__ = ["candidates_from_verdicts", "rank_submissions"]
