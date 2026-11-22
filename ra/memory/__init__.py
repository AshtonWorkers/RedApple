"""Compounding campaign memory (RA-MEM)."""

from .models import (
    ADAPTER_STATES,
    GLOBAL_SURFACE,
    PRIOR_KINDS,
    MemoryAdapter,
    MemoryPrior,
    PreferencePair,
    RetrievalContext,
    SlaStatus,
)
from .service import AdapterTrainer, CampaignMemory, StubAdapterTrainer

__all__ = [
    "ADAPTER_STATES",
    "GLOBAL_SURFACE",
    "PRIOR_KINDS",
    "AdapterTrainer",
    "CampaignMemory",
    "MemoryAdapter",
    "MemoryPrior",
    "PreferencePair",
    "RetrievalContext",
    "SlaStatus",
    "StubAdapterTrainer",
]
