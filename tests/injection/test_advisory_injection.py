"""Failure-injection tests for RA-ADV advisory intelligence."""

from __future__ import annotations

import json

import pytest

from ra.advisory import (
    APPLE_INDEX_URL,
    AdvisoryService,
    LedgerAdvisoryStore,
    parse_advisory,
    parse_index,
    release_metadata,
)
from ra.errors import FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger
from tests.conftest import run


class FailingDownloader:
    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def __call__(self, url: str) -> str:
        self.calls.append(url)
        if url not in self.pages:
            raise OSError(f"offline {url}")
        return self.pages[url]


def test_advisory_index_markup_change_fails_closed():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            service = AdvisoryService(
                ledger,
                downloader=FailingDownloader({APPLE_INDEX_URL: "<p>Apple changed the page</p>"}),
                sleep=no_sleep,
            )
            try:
                await service.refresh()
            except ValueError:
                pass
            else:  # pragma: no cover - defensive
                raise AssertionError("changed index markup should fail")
            assert ledger.claims_by_type("advisory_snapshot") == []
            assert ledger.integrity_check() == "ok"
        finally:
            await ledger.close()

    run(body())


def test_advisory_download_failure_after_index_leaves_no_snapshot():
    async def body():
        index = """<table><tr><td><p><a href="/en-us/123456">iOS 27</a></p></td><td>iPhone</td><td>09 Nov 2026</td></tr></table>"""
        ledger = await Ledger.open(":memory:")
        try:
            service = AdvisoryService(ledger, downloader=FailingDownloader({APPLE_INDEX_URL: index}), sleep=no_sleep)
            snapshot = await service.refresh(limit=1)
            assert snapshot.errors[0].error.startswith("offline ")
            assert snapshot.releases[0].error is not None
            assert snapshot.releases[0].entries == ()
            assert len(ledger.claims_by_type("advisory_snapshot")) == 1
        finally:
            await ledger.close()

    run(body())


def test_malformed_stored_advisory_claim_is_rejected():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            payload = b"{}"
            claim = ClaimInput(
                claim_id="cl_advisory_bad",
                type="advisory_snapshot",
                value_json="{}",
                confidence=1.0,
                dedup_key="advisory_snapshot:bad",
                created=1,
                artifacts=(ClaimArtifactInput(ArtifactInput(kind="advisory_snapshot", data=payload, ttl_class="pinned"), role="state"),),
            )
            claim_id = await ledger.create_claim(claim)
            await ledger.transition_claim(claim_id, ClaimState.BOUND)
            with pytest.raises(FormatFail):
                await LedgerAdvisoryStore(ledger).load_latest_snapshot()
        finally:
            await ledger.close()

    run(body())


def test_advisory_claim_type_vocabulary_is_closed():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            claim = ClaimInput(
                claim_id="cl_bad_type",
                type="advisory_signal",
                value_json=json.dumps({"x": 1}),
                confidence=1.0,
                dedup_key="advisory_signal:bad",
                created=1,
                artifacts=(ClaimArtifactInput(ArtifactInput(kind="crash", data=b"x"), role="evidence"),),
            )
            with pytest.raises(FormatFail):
                await ledger.create_claim(claim)
        finally:
            await ledger.close()

    run(body())


def test_parse_index_property_shape_for_generated_rows():
    rows = parse_index(
        """<table>
        <tr><td><p><a href="/en-us/123456">iOS 26.1</a></p></td><td>iPhone</td><td>01 Sep 2026</td></tr>
        <tr><td><p><a href="https://support.apple.com/en-us/654321">macOS 26.0.1</a></p></td><td>Mac</td><td>15 Sep 2026</td></tr>
        </table>"""
    )
    assert [row.name for row in rows] == ["macOS 26.0.1", "iOS 26.1"]
    assert all(row.url is not None for row in rows)


def test_advisory_store_rejects_nonfinite_claim_values():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            store = LedgerAdvisoryStore(ledger)
            await store._save_claim(
                claim_type="advisory_snapshot",
                dedup_key="adv-bad-nonfinite",
                value_json='{"source": "s", "fetched_at": "f", "releases": [], "x": NaN}',
                artifact_kind="advisory_snapshot",
                role="snapshot",
                created=1,
            )
            with pytest.raises(FormatFail):
                await store.load_latest_snapshot()
        finally:
            await ledger.close()

    run(body())


def test_advisory_parser_property_survives_adversarial_html():
    cases = (
        "<h3>WebKit</h3><p>Impact: May execute code</p><p>CVE-2026-1234: A<br>CVE-2026-1234: B</p>",
        "<h3> </h3><p>Impact: x</p><p>CVE-2026-1234</p><h3>Kernel</h3><p>CVE-2026-1235</p>",
        "<p>unclosed <b>markup",
        "<table><tr><td><p><a href=\"javascript:alert(1)\">x</a></p></td><td>iOS</td><td>09 Nov 2026</td></tr></table>",
    )
    for html in cases:
        entries = parse_advisory(html)
        assert all(entry.component.strip() for entry in entries)
        for entry in entries:
            ids = [cve.id for cve in entry.cves]
            assert len(ids) == len(set(ids))
        metadata = release_metadata(html)
        assert len(metadata.builds) == len(set(metadata.builds))
        try:
            rows = parse_index(html)
        except ValueError:
            continue
        assert [row.date for row in rows] == sorted((row.date for row in rows), reverse=True)
        assert all(row.url is None or row.url.startswith("https://support.apple.com/") for row in rows)


async def no_sleep(delay: float) -> None:
    return None
