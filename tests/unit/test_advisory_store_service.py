"""RA-ADV ledger-backed store and refresh service tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from ra.advisory import (
    APPLE_INDEX_URL,
    AdvisoryService,
    AdvisorySnapshot,
    LedgerAdvisoryStore,
    default_download,
)
from ra.advisory.store import _canonical_json, _iso_to_ms, _loads_json
from ra.errors import FormatFail
from ra.ledger import Ledger
from ra.ledger.ids import now_ms
from tests.conftest import run

INDEX = """<table><tr><th>Name</th><th>Available for</th><th>Date</th></tr>
<tr><td><p><a href="/en-us/123456">iOS 27</a></p></td><td>iPhone &amp; iPad</td><td>09 Nov 2026</td></tr>
<tr><td><p><a href="/en-us/654321">macOS 27</a></p></td><td>Mac</td><td>08 Nov 2026</td></tr></table>"""

INDEX_NOLINK = """<table><tr><td><p>iOS 27</p></td><td>iPhone</td><td>09 Nov 2026</td></tr></table>"""

ADVISORY = """<h1>About iOS 27</h1><p>Build 23A123</p><h3>WebKit</h3>
<p>Impact: Processing web content may lead to arbitrary code execution</p>
<p>Description: Improved checks.</p>
<p>CVE-2026-12345: Researcher</p>"""

ENTRY_POINTS = [
    {
        "id": "ep-webkit",
        "name": "com.apple.WebKit.WebContent",
        "reach_from_json": '[{"source":"image:/System/Library/WebKit","hops":2}]',
        "privilege_delta": 2,
        "parser_complexity": 0.5,
        "weight": 1.0,
        "ring_node": "ios-node",
    }
]


class FakeDownloader:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = dict(pages)
        self.calls: list[str] = []
        self.failures: set[str] = set()

    def __call__(self, url: str) -> str:
        self.calls.append(url)
        if url in self.failures:
            raise OSError("offline")
        if url not in self.pages:
            raise KeyError(f"unexpected url {url}")
        return self.pages[url]


class FakeSleep:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def clock() -> datetime:
    return datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def test_advisory_refresh_persists_snapshot_in_ledger():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                    "https://support.apple.com/en-us/654321": ADVISORY,
                }
            )
            sleep = FakeSleep()
            service = AdvisoryService(
                ledger,
                downloader=downloader,
                sleep=sleep,
                clock=clock,
                request_delay=0.25,
            )
            snapshot = await service.refresh(limit=1)
            self_assert_snapshot(snapshot, "iOS 27")
            assert sleep.delays == [0.25]
            assert downloader.calls == [APPLE_INDEX_URL, "https://support.apple.com/en-us/123456"]

            claims = ledger.claims_by_type("advisory_snapshot")
            assert len(claims) == 1
            assert claims[0]["state"] == "bound"
            assert claims[0]["type"] == "advisory_snapshot"

            store = LedgerAdvisoryStore(ledger)
            loaded = await store.load_latest_snapshot()
            assert loaded == snapshot
            again = await store.save_snapshot(snapshot)
            assert again == claims[0]["id"]
            assert len(ledger.claims_by_type("advisory_snapshot")) == 1
            assert ledger.artifact_ttl_counts().get("pinned", 0) >= 1
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_failure_preserves_previous_entries():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                }
            )
            service = AdvisoryService(ledger, downloader=downloader, sleep=FakeSleep(), clock=clock)
            first = await service.refresh(limit=1)
            assert first.errors == ()

            downloader.failures.add("https://support.apple.com/en-us/123456")
            second = await service.refresh(limit=1)
            assert len(second.errors) == 1
            assert second.errors[0].release == "iOS 27"
            assert second.errors[0].error == "offline"
            release = second.releases[0]
            assert release.error == "offline"
            assert len(release.entries) == 1
            assert release.builds == ("23A123",)
            assert release.advisory_title == "About iOS 27"

            loaded = await LedgerAdvisoryStore(ledger).load_latest_snapshot()
            assert loaded is not None
            assert loaded.errors[0].release == "iOS 27"
            assert loaded.errors[0].error == "offline"
            assert len(loaded.releases[0].entries) == 1
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_window_and_no_link_note():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                    "https://support.apple.com/en-us/654321": ADVISORY,
                }
            )
            service_window0 = AdvisoryService(
                ledger, downloader=downloader, sleep=FakeSleep(), clock=clock, window_days=0
            )
            latest_only = await service_window0.refresh()
            assert [release.name for release in latest_only.releases] == ["iOS 27"]

            service_window1 = AdvisoryService(
                ledger, downloader=downloader, sleep=FakeSleep(), clock=clock, window_days=1
            )
            both = await service_window1.refresh()
            assert [release.name for release in both.releases] == ["iOS 27", "macOS 27"]
            assert len(both.releases[0].entries) == 1
            assert len(both.releases[1].entries) == 1

            service_nolink = AdvisoryService(
                ledger,
                downloader=FakeDownloader({APPLE_INDEX_URL: INDEX_NOLINK}),
                sleep=FakeSleep(),
                clock=clock,
            )
            nolink = await service_nolink.refresh(limit=1)
            assert nolink.releases[0].url is None
            assert nolink.releases[0].note == "No published advisory link / CVE entries"
            assert nolink.errors == ()
        finally:
            await ledger.close()

    run(body())


def test_advisory_prioritize_current_persists_results():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                }
            )
            service = AdvisoryService(ledger, downloader=downloader, sleep=FakeSleep(), clock=clock)
            await service.refresh(limit=1)
            cve_records = await service.latest_cves()
            assert [record.id for record in cve_records] == ["CVE-2026-12345"]

            result = await service.prioritize_current(ENTRY_POINTS)
            assert result.cves_considered == 1
            assert result.surfaces_considered == 1
            assert result.matched_cves == 1
            assert result.targets[0].entry_point_id == "ep-webkit"
            assert result.targets[0].cve.category == "Browser attack / Web Content code execution"

            claims = ledger.claims_by_type("advisory_priorities")
            assert len(claims) == 1
            assert claims[0]["state"] == "bound"
            loaded = await LedgerAdvisoryStore(ledger).load_latest_prioritization()
            assert loaded == result
            assert loaded is not None
            assert loaded.generated_at == result.generated_at
        finally:
            await ledger.close()

    run(body())


def test_advisory_service_validation_and_empty_state():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            with pytest.raises(FormatFail):
                AdvisoryService(ledger, request_delay=-1.0)
            with pytest.raises(FormatFail):
                AdvisoryService(ledger, window_days=-1)
            service = AdvisoryService(ledger, downloader=FakeDownloader({}), sleep=FakeSleep(), clock=clock)
            with pytest.raises(FormatFail):
                await service.refresh(limit=-1)
            with pytest.raises(FormatFail):
                await service.latest_cves()
            with pytest.raises(FormatFail):
                await service.prioritize_current(ENTRY_POINTS)

            naive_service = AdvisoryService(
                ledger,
                downloader=FakeDownloader({APPLE_INDEX_URL: INDEX_NOLINK}),
                sleep=FakeSleep(),
                clock=lambda: datetime(2026, 1, 1, 1, 1),
            )
            naive_snapshot = await naive_service.refresh(limit=1)
            assert naive_snapshot.fetched_at == "2026-01-01T01:01:00+00:00"
        finally:
            await ledger.close()

    run(body())


def test_advisory_snapshot_from_dict_and_fetch_error_roundtrip():
    snapshot = AdvisorySnapshot.from_dict(
        {
            "source": "s",
            "fetched_at": "2026-11-22T00:00:00+00:00",
            "releases": [],
            "errors": [{"release": "iOS 27", "error": "boom"}],
        }
    )
    assert snapshot.errors[0].error == "boom"
    assert snapshot.to_dict()["errors"] == [{"release": "iOS 27", "error": "boom"}]
    assert json.loads(json.dumps(snapshot.to_dict()))["source"] == "s"


def test_default_download_host_allowlist_and_response():
    def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
        assert request.full_url == "https://support.apple.com/en-us/100100"
        assert "RedApple/1.0" in request.headers["User-agent"]

        class Response:
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *args):  # type: ignore[no-untyped-def]
                return False

            def read(self) -> bytes:
                return b"<html>ok</html>"

        return Response()

    for url in ("http://support.apple.com/en-us/100100", "https://evil.example/en-us/100100"):
        with pytest.raises(ValueError):
            default_download(url)
    with patch("ra.advisory.service.urlopen", side_effect=fake_urlopen):
        assert default_download("https://support.apple.com/en-us/100100") == "<html>ok</html>"


def test_default_download_rejects_non_bytes_response():
    class Response:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *args):  # type: ignore[no-untyped-def]
            return False

        def read(self) -> str:
            return "not bytes"

    with patch("ra.advisory.service.urlopen", return_value=Response()):
        try:
            default_download("https://support.apple.com/en-us/100100")
        except ValueError:
            pass
        else:  # pragma: no cover - defensive
            raise AssertionError("expected non-bytes response failure")


def test_advisory_store_iso_fallback_and_non_dict_rows():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            store = LedgerAdvisoryStore(ledger)
            expected = int(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC).timestamp() * 1000)
            assert _iso_to_ms("2026-01-02T03:04:05") == expected
            assert _iso_to_ms("2026-01-02T03:04:05Z") == expected
            before = now_ms()
            fallback = _iso_to_ms("not-a-date")
            after = now_ms()
            assert before <= fallback <= after

            await store._save_claim(
                claim_type="advisory_snapshot",
                dedup_key="adv-test-non-dict-snapshot",
                value_json="[]",
                artifact_kind="advisory_snapshot",
                role="snapshot",
                created=1,
            )
            assert await store.load_latest_snapshot() is None
            await store._save_claim(
                claim_type="advisory_priorities",
                dedup_key="adv-test-non-dict-priorities",
                value_json="[]",
                artifact_kind="advisory_priorities",
                role="priorities",
                created=1,
            )
            assert await store.load_latest_prioritization() is None
        finally:
            await ledger.close()

    run(body())


def test_advisory_store_json_guards_reject_nonfinite_and_malformed():
    with pytest.raises(FormatFail):
        _canonical_json({"x": float("nan")})
    for bad_json in ("not json", '{"x": NaN}', "[" * 10000 + "]" * 10000):
        with pytest.raises(FormatFail):
            _loads_json(bad_json)
    assert _loads_json('{"x": 1}') == {"x": 1}


def test_advisory_refresh_and_prioritize_persists_feed():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                }
            )
            service = AdvisoryService(
                ledger,
                downloader=downloader,
                sleep=FakeSleep(),
                clock=clock,
                request_delay=0,
            )
            snapshot, result = await service.refresh_and_prioritize(ENTRY_POINTS, limit=1)
            assert snapshot.cve_count == 1
            assert result.targets[0].entry_point_id == "ep-webkit"
            loaded = await LedgerAdvisoryStore(ledger).load_latest_prioritization()
            assert loaded == result

            empty_ledger = await Ledger.open(":memory:")
            try:
                assert await LedgerAdvisoryStore(empty_ledger).load_latest_prioritization() is None
            finally:
                await empty_ledger.close()
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_failure_without_previous_release():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            service = AdvisoryService(
                ledger,
                downloader=FakeDownloader({APPLE_INDEX_URL: INDEX}),
                sleep=FakeSleep(),
                clock=clock,
            )
            snapshot = await service.refresh(limit=2)
            assert len(snapshot.errors) == 2
            assert all(release.error is not None for release in snapshot.releases)
            assert all(len(release.entries) == 0 for release in snapshot.releases)
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_matches_previous_by_name_and_date():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                }
            )
            service = AdvisoryService(ledger, downloader=downloader, sleep=FakeSleep(), clock=clock)
            first = await service.refresh(limit=1)
            assert len(first.releases[0].entries) == 1

            changed_index = INDEX.replace("/en-us/123456", "/en-us/222222")
            downloader.pages[APPLE_INDEX_URL] = changed_index
            second = await service.refresh(limit=1)
            release = second.releases[0]
            assert release.url == "https://support.apple.com/en-us/222222"
            assert release.error is not None
            assert "unexpected url https://support.apple.com/en-us/222222" in release.error
            assert len(release.entries) == 1
            assert release.builds == ("23A123",)
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_empty_advisory_records_error():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": "<p>No CVEs</p>",
                }
            )
            service = AdvisoryService(
                ledger,
                downloader=downloader,
                sleep=FakeSleep(),
                clock=clock,
                request_delay=0,
            )
            snapshot = await service.refresh(limit=1)
            assert snapshot.errors[0].error == "No component entries recognized"
            assert snapshot.releases[0].error == "No component entries recognized"
            assert snapshot.releases[0].entries == ()
        finally:
            await ledger.close()

    run(body())


def test_advisory_refresh_failure_with_unmatched_previous_release():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            downloader = FakeDownloader(
                {
                    APPLE_INDEX_URL: INDEX,
                    "https://support.apple.com/en-us/123456": ADVISORY,
                }
            )
            service = AdvisoryService(ledger, downloader=downloader, sleep=FakeSleep(), clock=clock)
            first = await service.refresh(limit=1)
            assert first.releases[0].name == "iOS 27"

            macos_only = """<table><tr><th>Name</th><th>Available for</th><th>Date</th></tr>
<tr><td><p><a href="/en-us/654321">macOS 27</a></p></td><td>Mac</td><td>08 Nov 2026</td></tr></table>"""
            downloader.pages[APPLE_INDEX_URL] = macos_only
            second = await service.refresh(limit=1)
            release = next(row for row in second.releases if row.name == "macOS 27")
            assert release.error is not None
            assert "unexpected url https://support.apple.com/en-us/654321" in release.error
            assert release.entries == ()
            assert release.builds == ()
            assert release.advisory_title is None
        finally:
            await ledger.close()

    run(body())


def self_assert_snapshot(snapshot: AdvisorySnapshot, name: str) -> None:
    assert snapshot.source == APPLE_INDEX_URL
    assert snapshot.fetched_at == "2026-11-22T12:00:00+00:00"
    assert snapshot.cve_count == 1
    assert len(snapshot.releases) == 1
    release = snapshot.releases[0]
    assert release.name == name
    assert release.entries[0].component == "WebKit"
    assert release.builds == ("23A123",)
    assert release.advisory_title == "About iOS 27"
    assert release.error is None

