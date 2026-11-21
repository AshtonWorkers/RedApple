"""Fleet, version ring, and lane adapter selection (hardware-free M0 core)."""

from __future__ import annotations

from .fake import FakeLane
from .ring import RingManager, RingNodeSpec

__all__ = ["FakeLane", "RingManager", "RingNodeSpec"]
