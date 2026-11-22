"""Advisory refresh and prioritization service.

The service ports PR #1's fetch semantics onto the ledger: the previous snapshot
is loaded from the claim ledger (not a filesystem cache), failures preserve the
last good advisory entries, and every successful refresh is persisted as a bound
claim before prioritization feeds surface ranking.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable, Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ..errors import FormatFail
from ..ledger import Ledger
from .classifier import BountyCatalog, cves
from .models import AdvisorySnapshot, CveRecord, FetchError, ReleaseRecord
from .parser import (
    APPLE_INDEX_URL,
    enrich_versions,
    parse_advisory,
    parse_index,
    release_metadata,
)
from .prioritize import PrioritizationResult, prioritize
from .store import LedgerAdvisoryStore

Downloader = Callable[[str], str]
Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], datetime]

_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 Safari/605.1.15 RedApple/1.0"
)


def default_download(url: str) -> str:
    """Download one Apple advisory page; host allowlist matches PR #1."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "support.apple.com":
        raise ValueError("Unexpected advisory host")
    request = Request(url, headers={"User-Agent": _USER_AGENT})
    with urlopen(request, timeout=40) as response:
        data = response.read()
    if not isinstance(data, bytes):
        raise ValueError("advisory response was not bytes")
    return data.decode("utf-8")


def _clock_iso(clock: Clock) -> str:
    value = clock()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


class AdvisoryService:
    """Refresh Apple advisories and produce ledger-backed priority feeds."""

    def __init__(
        self,
        ledger: Ledger,
        *,
        store: LedgerAdvisoryStore | None = None,
        downloader: Downloader | None = None,
        sleep: Sleep | None = None,
        clock: Clock | None = None,
        catalog: BountyCatalog | None = None,
        request_delay: float = 0.5,
        window_days: int = 365,
    ) -> None:
        if request_delay < 0:
            raise FormatFail("request_delay must be >= 0")
        if window_days < 0:
            raise FormatFail("window_days must be >= 0")
        self._ledger = ledger
        self._store = store if store is not None else LedgerAdvisoryStore(ledger)
        self._downloader = downloader if downloader is not None else default_download
        self._sleep = sleep if sleep is not None else asyncio.sleep
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._catalog = catalog
        self._request_delay = request_delay
        self._window_days = window_days

    async def _fetch_text(self, url: str) -> str:
        return await asyncio.to_thread(self._downloader, url)

    def _previous_release(
        self, release: ReleaseRecord, previous: AdvisorySnapshot | None
    ) -> ReleaseRecord | None:
        if previous is None:
            return None
        for candidate in previous.releases:
            if release.url is not None and candidate.url == release.url:
                return candidate
        for candidate in previous.releases:
            if candidate.name == release.name and candidate.date == release.date:
                return candidate
        return None

    def _fallback_release(
        self,
        release: ReleaseRecord,
        previous: AdvisorySnapshot | None,
        error: str,
    ) -> ReleaseRecord:
        prior = self._previous_release(release, previous)
        return release.with_advisory(
            entries=() if prior is None else prior.entries,
            advisory_title=None if prior is None else prior.advisory_title,
            builds=None if prior is None else prior.builds,
            error=error,
            note=None if prior is None else prior.note,
        )

    async def refresh(self, *, limit: int | None = None) -> AdvisorySnapshot:
        """Fetch the Apple index, refresh advisories, merge history, persist."""
        if limit is not None and limit < 0:
            raise FormatFail("limit must be >= 0")
        index_html = await self._fetch_text(APPLE_INDEX_URL)
        releases = parse_index(index_html)
        if limit is None:
            newest = date.fromisoformat(releases[0].date)
            cutoff = (newest - timedelta(days=self._window_days)).isoformat()
            releases = [release for release in releases if release.date >= cutoff]
        else:
            releases = releases[:limit]

        previous = await self._store.load_latest_snapshot()
        errors: list[FetchError] = []
        refreshed: list[ReleaseRecord] = []
        for release in releases:
            if release.url is None:
                refreshed.append(
                    release.with_advisory(note="No published advisory link / CVE entries")
                )
                continue
            if self._request_delay > 0:
                await self._sleep(self._request_delay)
            try:
                html = await self._fetch_text(release.url)
                entries = parse_advisory(html)
                if not entries:
                    raise ValueError("No component entries recognized")
                metadata = release_metadata(html)
                refreshed.append(
                    release.with_advisory(
                        entries=entries,
                        advisory_title=metadata.advisory_title,
                        builds=metadata.builds,
                    )
                )
            except Exception as exc:  # advisory failure must not lose prior intelligence
                error = str(exc)
                errors.append(FetchError(release=release.name, error=error))
                refreshed.append(self._fallback_release(release, previous, error))

        merged = list(refreshed)
        seen = {(release.name, release.date) for release in refreshed}
        if previous is not None:
            merged.extend(
                release for release in previous.releases if (release.name, release.date) not in seen
            )
        merged = enrich_versions(merged)
        merged.sort(key=lambda release: release.date, reverse=True)
        snapshot = AdvisorySnapshot(
            source=APPLE_INDEX_URL,
            fetched_at=_clock_iso(self._clock),
            releases=tuple(merged),
            errors=tuple(errors),
        )
        await self._store.save_snapshot(snapshot)
        return snapshot

    async def latest_cves(self) -> list[CveRecord]:
        """Classify CVEs from the newest stored snapshot."""
        snapshot = await self._store.load_latest_snapshot()
        if snapshot is None:
            raise FormatFail("no advisory snapshot; run refresh first")
        return cves(snapshot, catalog=self._catalog)

    async def prioritize_current(
        self,
        entry_points: Iterable[Mapping[str, Any]],
        *,
        max_targets: int = 100,
        now: datetime | None = None,
    ) -> PrioritizationResult:
        """Prioritize the newest stored snapshot against surface rows and persist it."""
        snapshot = await self._store.load_latest_snapshot()
        if snapshot is None:
            raise FormatFail("no advisory snapshot; run refresh first")
        records = cves(snapshot, catalog=self._catalog)
        result = prioritize(
            records,
            entry_points,
            max_targets=max_targets,
            now=now,
            snapshot_source=snapshot.source,
            snapshot_fetched_at=snapshot.fetched_at,
        )
        await self._store.save_prioritization(result)
        return result

    async def refresh_and_prioritize(
        self,
        entry_points: Iterable[Mapping[str, Any]],
        *,
        limit: int | None = None,
        max_targets: int = 100,
        now: datetime | None = None,
    ) -> tuple[AdvisorySnapshot, PrioritizationResult]:
        """Refresh advisories, then produce and persist the priority feed."""
        snapshot = await self.refresh(limit=limit)
        records = cves(snapshot, catalog=self._catalog)
        result = prioritize(
            records,
            entry_points,
            max_targets=max_targets,
            now=now,
            snapshot_source=snapshot.source,
            snapshot_fetched_at=snapshot.fetched_at,
        )
        await self._store.save_prioritization(result)
        return snapshot, result
