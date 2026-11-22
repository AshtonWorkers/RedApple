"""RA-ADV parser and model tests."""

from __future__ import annotations

import unittest

from ra.advisory import (
    AdvisorySnapshot,
    CveCredit,
    CveRecord,
    DiffFrom,
    ReleaseRecord,
    enrich_versions,
    parse_advisory,
    parse_index,
    release_metadata,
)
from ra.errors import FormatFail

INDEX = """<table><tr><th>Name</th><th>Available for</th><th>Date</th></tr>
<tr><td><p><a href="/en-us/123456">iOS 27</a></p></td><td>iPhone &amp; iPad</td><td>09 Nov 2026</td></tr>
<tr><td><p>No CVEs</p><p>This update has no published CVE entries.</p></td>
<td>Watch</td><td>8 Nov 2026</td></tr></table>"""

ADVISORY = """<h2>About this release</h2><p>Intro</p><h3>WebKit</h3>
<p>Available for: iPhone</p><p>Impact: May execute arbitrary code</p>
<p>Description: See also CVE-2020-1234. Improved checks.</p>
<p>CVE-2026-12345: Researcher &amp; team<br>CVE-2026-12346: Apple</p>
<h3>Kernel</h3><p>Impact: An app may crash</p><p>Description: Fixed.</p>
<h3>Ignored</h3><p>Description: no impact or CVEs</p>
<h2>Acknowledgements</h2><p>Thanks.</p>"""


def release(name: str, date: str, url: str | None = None) -> ReleaseRecord:
    return ReleaseRecord(name=name, date=date, url=url)


class AdvisoryParserTests(unittest.TestCase):
    def test_parse_index_sorts_and_normalizes_links(self) -> None:
        rows = parse_index(INDEX)
        self.assertEqual([row.date for row in rows], ["2026-11-09", "2026-11-08"])
        self.assertEqual(rows[0].name, "iOS 27")
        self.assertEqual(rows[0].available_for, "iPhone & iPad")
        self.assertEqual(rows[0].url, "https://support.apple.com/en-us/123456")
        self.assertIsNone(rows[1].url)

    def test_parse_index_rejects_changed_markup(self) -> None:
        with self.assertRaises(ValueError):
            parse_index("<p>Changed markup</p>")

    def test_parse_advisory_extracts_entries_and_credits(self) -> None:
        entries = parse_advisory(ADVISORY)
        self.assertEqual([entry.component for entry in entries], ["WebKit", "Kernel"])
        first = entries[0]
        self.assertEqual(first.available_for, "iPhone")
        self.assertEqual(first.impact, "May execute arbitrary code")
        self.assertEqual(first.description, "See also CVE-2020-1234. Improved checks.")
        self.assertEqual([cve.id for cve in first.cves], ["CVE-2026-12345", "CVE-2026-12346"])
        self.assertEqual(first.cves[0].credit, "Researcher & team")
        self.assertEqual(first.cves[1].credit, "Apple")
        self.assertEqual(entries[1].cves, ())

    def test_parse_advisory_missing_credit_and_empty(self) -> None:
        parsed = parse_advisory("<h3>ImageIO</h3><p>CVE-2026-12345</p>")
        self.assertEqual(parsed[0].cves[0].credit, "")
        self.assertEqual(parse_advisory("<p>No CVEs</p>"), [])

    def test_release_metadata_extracts_title_and_builds(self) -> None:
        metadata = release_metadata("<h1>About iOS 26</h1><p>Build 23A123</p><p>build 23A123</p><p>Build 24B1</p>")
        self.assertEqual(metadata.advisory_title, "About iOS 26")
        self.assertEqual(metadata.builds, ("23A123", "24B1"))
        self.assertEqual(release_metadata("<p>iOS 26</p>").builds, ())

    def test_enrich_versions_pairs_same_major_previous_release(self) -> None:
        rows = [
            release("macOS Tahoe 26.2", "2026-11-01"),
            release("macOS Tahoe 26.1", "2026-10-01"),
            release("macOS Sequoia 15.8", "2026-10-01"),
            release("iOS 26", "2026-09-01"),
        ]
        enriched = enrich_versions(rows)
        self.assertEqual([row.version for row in enriched], ["26.2", "26.1", "15.8", "26"])
        self.assertEqual([row.os for row in enriched], ["macOS", "macOS", "macOS", "iOS"])
        self.assertEqual(enriched[0].diff_from.version if enriched[0].diff_from else None, "26.1")
        self.assertIsNone(enriched[2].diff_from)
        self.assertIsNone(enriched[3].diff_from)
        self.assertIsNone(rows[0].diff_from)  # pure function does not mutate input

    def test_snapshot_and_cve_roundtrip(self) -> None:
        original = ReleaseRecord(
            name="iOS 27",
            date="2026-11-09",
            available_for="iPhone",
            url="https://support.apple.com/en-us/123456",
            os="iOS",
            version="27",
            builds=("23A123",),
            entries=tuple(parse_advisory(ADVISORY)),
            advisory_title="About iOS 27",
        )
        snapshot = AdvisorySnapshot(
            source="https://support.apple.com/en-us/100100",
            fetched_at="2026-11-22T00:00:00+00:00",
            releases=(original,),
        )
        self.assertEqual(snapshot.cve_count, 2)
        restored = AdvisorySnapshot.from_dict(snapshot.to_dict())
        self.assertEqual(restored, snapshot)

        cve = CveRecord(id="CVE-2026-12345", component="WebKit", release="iOS 27")
        self.assertEqual(CveRecord.from_dict(cve.to_dict()), cve)

    def test_model_validation_rejects_bad_shapes(self) -> None:
        with self.assertRaises(FormatFail):
            AdvisorySnapshot.from_dict({})
        with self.assertRaises(FormatFail):
            ReleaseRecord.from_dict({"name": "x", "date": "2026-01-01", "builds": "23A123"})
        with self.assertRaises(FormatFail):
            CveRecord.from_dict({"id": "CVE-1", "max_reward": "10000"})


    def test_diff_from_roundtrip_and_model_validation_edges(self) -> None:
        diff = DiffFrom(name="macOS 26.1", version="26.1", url=None, date="2026-10-01")
        record = ReleaseRecord(name="macOS 26.2", date="2026-11-01", diff_from=diff)
        snapshot = AdvisorySnapshot(
            source="s",
            fetched_at="2026-11-22T00:00:00+00:00",
            releases=(record,),
        )
        restored = AdvisorySnapshot.from_dict(snapshot.to_dict())
        self.assertEqual(restored, snapshot)
        self.assertEqual(restored.releases[0].diff_from, diff)
        self.assertEqual(CveCredit.from_dict({"id": "CVE-1"}).credit, "")

        with self.assertRaises(FormatFail):
            ReleaseRecord.from_dict({"name": "x", "date": "2026-01-01", "entries": "bad"})
        with self.assertRaises(FormatFail):
            AdvisorySnapshot.from_dict({"source": "s", "fetched_at": "f", "releases": "bad"})
        with self.assertRaises(FormatFail):
            CveRecord.from_dict({"id": "CVE-1", "builds": [1]})
        with self.assertRaises(FormatFail):
            CveRecord.from_dict({"id": "CVE-1", "needs_review": "yes"})
        with self.assertRaises(FormatFail):
            DiffFrom.from_dict({"name": "n", "version": "1", "date": "d", "url": 1})
        with self.assertRaises(FormatFail):
            ReleaseRecord.from_dict({"name": "x", "date": "2026-01-01", "diff_from": 1})

    def test_parse_index_skips_malformed_rows_and_missing_hrefs(self) -> None:
        html = """<td>orphan</td><table>
<tr><td><p><a>iOS 27</a></p></td><td>iPhone</td><td>09 Nov 2026</td></tr>
<tr><td><p><a href="/en-us/123456">macOS 27</a></p></td><td>Mac</td></tr>
<tr><td><p><a href="/en-us/654321">iPadOS 27</a></p></td><td>iPad</td><td>08 Nov 2026</td></tr>
</table>"""
        rows = parse_index(html)
        self.assertEqual([row.name for row in rows], ["iOS 27", "iPadOS 27"])
        self.assertIsNone(rows[0].url)
        self.assertEqual(rows[1].url, "https://support.apple.com/en-us/654321")

    def test_enrich_versions_skips_unknown_and_later_candidates(self) -> None:
        rows = [
            release("Custom Platform", "2026-01-01"),
            release("macOS 26.1", "2026-10-01"),
            release("macOS 26.0", "2026-11-01"),
        ]
        enriched = enrich_versions(rows)
        self.assertIsNone(enriched[0].os)
        self.assertIsNone(enriched[0].version)
        self.assertIsNone(enriched[0].diff_from)
        by_name = {row.name: row for row in enriched}
        self.assertIsNone(by_name["macOS 26.1"].diff_from)
        self.assertIsNone(by_name["macOS 26.0"].diff_from)

    def test_parse_functions_reject_non_string_html(self) -> None:
        for parser in (parse_index, parse_advisory, release_metadata):
            with self.assertRaises(ValueError):
                parser(b"<p>not html</p>")

    def test_parse_index_filters_adversarial_links(self) -> None:
        html = """<table><tr><td><p>
        <a href="javascript:alert(1)">bad scheme</a>
        <a href="http://support.apple.com/en-us/111111">http apple</a>
        <a href="https://evil.example/en-us/222222">evil host</a>
        <a href="https://support.apple.com/en-us/notanumber">bad path</a>
        <a href="https://support.apple.com/en-us/1234567">long id</a>
        <a href="/en-us/123456">iOS 27</a>
        </p></td><td>iPhone</td><td>09 Nov 2026</td></tr></table>"""
        rows = parse_index(html)
        self.assertEqual(rows[0].url, "https://support.apple.com/en-us/123456")

    def test_parse_advisory_skips_empty_components_and_dedupes_cves(self) -> None:
        html = """<h3> </h3><p>Impact: May execute code</p><p>CVE-2026-1234: Ignored</p>
<h3>WebKit</h3><p>Impact: May execute code</p>
<p>CVE-2026-1234: First<br>CVE-2026-1234: Second<br>CVE-2026-1235: Third</p>"""
        entries = parse_advisory(html)
        self.assertEqual([entry.component for entry in entries], ["WebKit"])
        self.assertEqual([cve.id for cve in entries[0].cves], ["CVE-2026-1234", "CVE-2026-1235"])
        self.assertEqual([cve.credit for cve in entries[0].cves], ["First", "Third"])

    def test_parse_advisory_property_invariants_on_adversarial_html(self) -> None:
        cases = (
            "<h3>WebKit</h3><p>CVE-2026-1234</p>",
            "<h3>  </h3><p>Impact: x</p><p>CVE-2026-1234</p><h3>Kernel</h3><p>CVE-2026-1235</p>",
            "<p>no advisory blocks</p>",
            "<h2>Section</h2><p>text only</p>",
        )
        for html in cases:
            entries = parse_advisory(html)
            self.assertTrue(all(entry.component.strip() for entry in entries))
            for entry in entries:
                ids = [cve.id for cve in entry.cves]
                self.assertEqual(len(ids), len(set(ids)))
            metadata = release_metadata(html)
            self.assertEqual(len(metadata.builds), len(set(metadata.builds)))
            self.assertEqual(list(metadata.builds), sorted(metadata.builds))


if __name__ == "__main__":
    unittest.main()
