"""System invariant assertions I1-I12 (RA-INV)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..errors import InvariantBreach
from ..ledger import Ledger
from ..press.redact import redact_text

_STORE_KEYS = {
    "i1": ("I1", "promoted claim with zero artifact links"),
    "i2": ("I2", "artifact id is not content-addressed"),
    "i3": ("I3", "claim transition audit lacks idempotency row"),
    "i4": ("I4", "non-integer micro-USD spend"),
    "i6": ("I6", "hot query plan uses a table scan"),
}


def assert_store_invariants(ledger: Ledger) -> None:
    """Raise INVARIANT_BREACH if database-checkable invariants fail."""
    counts = ledger.invariant_counts()
    breaches = [
        f"{name}: {description} ({counts[key]})"
        for key, (name, description) in _STORE_KEYS.items()
        if counts.get(key, 0) > 0
    ]
    if breaches:
        raise InvariantBreach("; ".join(breaches))


def assert_no_sensitive_egress(text: str) -> None:
    """Raise INVARIANT_BREACH when unredacted egress text reaches the boundary (I9)."""
    if redact_text(text) != text:
        raise InvariantBreach("I9: sensitive text reached model egress")


def assert_sort_key_ends_with_id(sort_key_names: Sequence[str]) -> None:
    """Assert a total-order sort key ends in id (I5)."""
    if not sort_key_names or sort_key_names[-1] != "id":
        raise InvariantBreach("I5: ordering does not end in id")


def assert_join_repro(invariants: Sequence[str], repro: str) -> None:
    """Assert a join stores assertions and a repro (I11)."""
    if not invariants or any(not item.strip() for item in invariants):
        raise InvariantBreach("I11: join has no invariant assertions")
    if not repro.strip():
        raise InvariantBreach("I11: join has no repro")


def assert_retention_safe(*, ttl_class: str, remaining_after: int, min_set: int) -> None:
    """Assert retention will not evict pinned artifacts or the corpus min-set (I12)."""
    if ttl_class == "pinned":
        raise InvariantBreach("I12: pinned artifacts are not retention-eligible")
    if remaining_after < min_set:
        raise InvariantBreach("I12: retention would cross the corpus min-set floor")


def invariant_catalog() -> dict[str, str]:
    """Return the I1-I12 catalog for diagnostics."""
    return {
        "I1": "No promoted claim with zero artifact links",
        "I2": "No artifact mutation; identical bytes imply identical ID",
        "I3": "Every state transition is exactly-once and idempotent by key",
        "I4": "Money is integer micro-USD; no float in any budget path",
        "I5": "Every ordering is total: all sort keys end in id",
        "I6": "No table scan over 10k rows without an index hit",
        "I7": "A parked unit never blocks dispatch",
        "I8": "Caps enforced at executor before side effect",
        "I9": "Every LLM egress passes the redactor",
        "I10": "Corpus bytes never parsed on the host",
        "I11": "Every join stores a repro that fails when an assertion is removed",
        "I12": "Retention never evicts pinned artifacts or the corpus min-set",
    }


def invariant_rows() -> list[dict[str, Any]]:
    """Return catalog rows for health/doctor output."""
    return [{"id": key, "rule": value} for key, value in invariant_catalog().items()]
