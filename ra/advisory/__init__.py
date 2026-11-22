"""Apple advisory and bounty intelligence."""

from ra.advisory.classifier import (
    BountyCatalog,
    BountyCategory,
    BountyTier,
    Classification,
    catalog_summary,
    classify,
    cves,
    load_bounty_catalog,
    normalize_component,
    parse_bounty_catalog,
)
from ra.advisory.models import (
    AdvisorySnapshot,
    CveCredit,
    CveRecord,
    DiffFrom,
    FetchError,
    ReleaseEntry,
    ReleaseRecord,
)
from ra.advisory.parser import (
    APPLE_INDEX_URL,
    ReleaseMetadata,
    enrich_versions,
    parse_advisory,
    parse_index,
    release_metadata,
)
from ra.advisory.prioritize import PrioritizationResult, PrioritizedTarget, prioritize
from ra.advisory.service import AdvisoryService, default_download
from ra.advisory.store import (
    PRIORITY_CLAIM_TYPE,
    SNAPSHOT_CLAIM_TYPE,
    LedgerAdvisoryStore,
)

__all__ = [
    "APPLE_INDEX_URL",
    "PRIORITY_CLAIM_TYPE",
    "SNAPSHOT_CLAIM_TYPE",
    "AdvisoryService",
    "AdvisorySnapshot",
    "BountyCatalog",
    "BountyCategory",
    "BountyTier",
    "Classification",
    "CveCredit",
    "CveRecord",
    "DiffFrom",
    "FetchError",
    "LedgerAdvisoryStore",
    "PrioritizationResult",
    "PrioritizedTarget",
    "ReleaseEntry",
    "ReleaseMetadata",
    "ReleaseRecord",
    "catalog_summary",
    "classify",
    "cves",
    "default_download",
    "enrich_versions",
    "load_bounty_catalog",
    "normalize_component",
    "parse_advisory",
    "parse_bounty_catalog",
    "parse_index",
    "prioritize",
    "release_metadata",
]
