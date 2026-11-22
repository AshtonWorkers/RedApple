"""Race errors."""

from __future__ import annotations

from ..errors import RaError


class RaceError(RaError):
    """Base class for race harness errors."""

    code = "RACE_ERROR"


class RaceBackendError(RaceError):
    """Race backend failed repeatedly during probing."""

    code = "RACE_BACKEND_ERROR"
