"""Foundry error types named after Appendix H."""


class FoundryError(Exception):
    """Base class for Harness Foundry failures."""


class HarnessRejected(FoundryError):
    """Raised when a harness cannot be accepted or rolled back."""


class DialectDefect(FoundryError):
    """Raised when a groom dialect fails schema validation."""


class CasCorrupt(FoundryError):
    """Raised when a content-addressed object fails integrity checks."""
