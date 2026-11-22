"""Shared RED APPLE error taxonomy (Appendix H)."""

from __future__ import annotations


class RaError(Exception):
    """Base class for RED APPLE errors."""

    code = "RA_ERROR"
    retryable = True

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class OutOfRing(RaError):
    """Build is not present in the version ring."""

    code = "OUT_OF_RING"
    retryable = False


class ArmBlocked(RaError):
    """Run arm preconditions failed."""

    code = "ARM_BLOCKED"
    retryable = False


class NotProvisioned(RaError):
    """Device is not provisioned."""

    code = "NOT_PROVISIONED"


class SigningExpired(RaError):
    """Signing lease expired."""

    code = "SIGNING_EXPIRED"


class InstallFailed(RaError):
    """Harness install failed."""

    code = "INSTALL_FAILED"


class DeviceLost(RaError):
    """Device disappeared mid-run."""

    code = "DEVICE_LOST"


class ThermalDrain(RaError):
    """Thermal state requires drain."""

    code = "THERMAL_DRAIN"


class Hang(RaError):
    """Feed exceeded the lane deadline."""

    code = "HANG"


class HarnessRejected(RaError):
    """Foundry harness failed acceptance."""

    code = "HARNESS_REJECTED"


class DialectDefect(RaError):
    """Groom dialect failed validation."""

    code = "DIALECT_DEFECT"


class CasCorrupt(RaError):
    """CAS object failed integrity check."""

    code = "CAS_CORRUPT"


class IngestHashMismatch(RaError):
    """Fetched ring source bytes did not match the expected SHA-256."""

    code = "INGEST_HASH_MISMATCH"
    retryable = False


class BudgetExhausted(RaError):
    """Nightly budget exhausted."""

    code = "BUDGET_EXHAUSTED"


class BudgetGate(RaError):
    """Policy cap gate refused an action before side effects."""

    code = "BUDGET_GATE"
    retryable = False


class AdapterShipBlocked(RaError):
    """LoRA-style adapter failed the golden-set ship gate."""

    code = "ADAPTER_SHIP_BLOCKED"
    retryable = False


class FormatFail(RaError):
    """Schema or grammar validation failure."""

    code = "FORMAT_FAIL"


class Truncated(RaError):
    """Model task exceeded caps and returned partial output."""

    code = "TRUNCATED"


class TriageSplit(RaError):
    """Triage votes did not converge."""

    code = "TRIAGE_SPLIT"


class LadderExhausted(RaError):
    """All primitive ladder rungs failed."""

    code = "LADDER_EXHAUSTED"


class DensityLow(RaError):
    """Join density per ingress is below floor."""

    code = "DENSITY_LOW"


class InvariantBreach(RaError):
    """A system invariant I1-I12 was violated."""

    code = "INVARIANT_BREACH"
    retryable = False


class DuplicateDedup(RaError):
    """Duplicate ledger dedup key."""

    code = "DUPLICATE_DEDUP"


class IllegalTransition(RaError):
    """Illegal claim state transition."""

    code = "ILLEGAL_TRANSITION"


class LocalOnlyQueued(RaError):
    """Packet queued for offline replay in local-only mode."""

    code = "LOCAL_ONLY_QUEUED"
    retryable = False


class CorpusParseOnHost(RaError):
    """Corpus bytes were parsed on the host (I10)."""

    code = "CORPUS_PARSE_ON_HOST"
    retryable = False


class PacketTooLarge(RaError):
    """Packet exceeded its compiled budget irreducibly."""

    code = "PACKET_TOO_LARGE"
    retryable = False
