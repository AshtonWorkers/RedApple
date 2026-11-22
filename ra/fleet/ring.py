"""Version ring compatibility exports (RA-RING)."""

from __future__ import annotations

from ..ring import (
    BOOT_FAILURE_THRESHOLD,
    MIN_CURRENT_NODES,
    MIN_PINNED_NODES,
    RingManager,
    RingNodeSpec,
)

__all__ = [
    "BOOT_FAILURE_THRESHOLD",
    "MIN_CURRENT_NODES",
    "MIN_PINNED_NODES",
    "RingManager",
    "RingNodeSpec",
]
