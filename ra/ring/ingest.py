"""Hash-verified ingestion for version-ring source artifacts."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from ..errors import FormatFail, IngestHashMismatch
from ..ledger import Ledger
from ..ledger.ids import UlidFactory, now_ms, sha256_hex
from .models import IngestedSource, RingSource


class ArtifactFetcher(Protocol):
    """Fetch bytes for one ring source URI."""

    async def fetch(self, uri: str) -> bytes:
        """Return the source bytes or raise."""
        ...  # pragma: no cover


class ArtifactStore(Protocol):
    """Content-addressed artifact sink (the ledger artifact table)."""

    async def put_artifact(self, kind: str, data: bytes, *, ttl_class: str = "run") -> str:
        """Store bytes and return their artifact id."""
        ...  # pragma: no cover


class RingIngester:
    """Fetch ring sources, verify SHA-256 parity, and record them in the ledger."""

    def __init__(
        self,
        ledger: Ledger,
        fetcher: ArtifactFetcher,
        *,
        artifact_store: ArtifactStore | None = None,
        id_factory: UlidFactory | None = None,
    ) -> None:
        self.ledger = ledger
        self.fetcher = fetcher
        self.artifact_store = artifact_store
        self._ids = id_factory or UlidFactory()

    async def ingest_source(
        self,
        source: RingSource,
        *,
        epoch: int,
        expected_sha256: str | None = None,
        ttl_class: str = "pinned",
        created: int | None = None,
    ) -> IngestedSource:
        """Fetch, hash, store, and ledger-record one ring source."""
        if epoch < 0:
            raise FormatFail("epoch must be non-negative")
        if source.epoch is not None and source.epoch != epoch:
            raise FormatFail("source epoch does not match ingest epoch")
        if (
            expected_sha256 is not None
            and source.expected_sha256 is not None
            and expected_sha256 != source.expected_sha256
        ):
            raise FormatFail("conflicting expected sha256 values")
        expected = expected_sha256 if expected_sha256 is not None else source.expected_sha256
        data = await self.fetcher.fetch(source.uri)
        digest = sha256_hex(data)
        if expected is not None and digest != expected:
            raise IngestHashMismatch(
                f"ring source {source.uri} sha256 mismatch: expected {expected}, got {digest}"
            )
        artifact_id: str | None = None
        if self.artifact_store is not None:
            artifact_id = await self.artifact_store.put_artifact(
                source.kind, data, ttl_class=ttl_class
            )
        ingest_id = await self.ledger.record_ring_ingest(
            kind=source.kind,
            uri=source.uri,
            sha256=digest,
            size_bytes=len(data),
            epoch=epoch,
            artifact_id=artifact_id,
            ingest_id=self._ids.new("ring_ingest"),
            created=now_ms() if created is None else created,
        )
        return IngestedSource(
            ingest_id=ingest_id,
            kind=source.kind,
            uri=source.uri,
            sha256=digest,
            size_bytes=len(data),
            epoch=epoch,
            artifact_id=artifact_id,
        )

    async def ingest_many(
        self,
        sources: Sequence[RingSource],
        *,
        epoch: int,
        expected_sha256: Sequence[str | None] | None = None,
        ttl_class: str = "pinned",
        created: int | None = None,
    ) -> list[IngestedSource]:
        """Ingest sources in input order."""
        if expected_sha256 is not None and len(expected_sha256) != len(sources):
            raise FormatFail("expected_sha256 length must match sources")
        out: list[IngestedSource] = []
        for index, source in enumerate(sources):
            expected = None if expected_sha256 is None else expected_sha256[index]
            out.append(
                await self.ingest_source(
                    source,
                    epoch=epoch,
                    expected_sha256=expected,
                    ttl_class=ttl_class,
                    created=created,
                )
            )
        return out
