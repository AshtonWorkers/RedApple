"""Mailbox operation passed to the single-writer ledger actor."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LedgerOperation:
    """One write operation and its estimated SQL row count for batching."""

    kind: str
    payload: Mapping[str, Any]
    rows: int = 1
    immediate: bool = False
    future: asyncio.Future[object] | None = field(default=None, repr=False)
