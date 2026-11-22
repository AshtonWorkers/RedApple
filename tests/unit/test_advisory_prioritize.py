"""RA-ADV surface prioritization tests."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from ra.advisory import CveRecord, PrioritizationResult, PrioritizedTarget, prioritize
from ra.errors import FormatFail

NOW = datetime(2026, 11, 22, tzinfo=UTC)


def cve(
    cve_id: str,
    *,
    component: str = "WebKit",
    original_component: str | None = None,
    release: str = "iOS 27",
    release_date: str = "2026-11-09",
    release_os: str | None = "iOS",
    max_reward: int = 10000,
    priority: str = "normal",
    confidence: str = "low",
    impact: str = "",
    description: str = "",
    advisory_title: str | None = None,
    category: str = "Browser attack / Web Content code execution",
    in_the_wild: bool = False,
) -> CveRecord:
    return CveRecord(
        id=cve_id,
        component=component,
        original_component=original_component if original_component is not None else component,
        impact=impact,
        description=description,
        advisory_title=advisory_title,
        release=release,
        release_date=release_date,
        release_os=release_os,
        max_reward=max_reward,
        priority=priority,
        confidence=confidence,
        category=category,
        category_id="category-9",
        in_the_wild=in_the_wild,
    )


def entry(
    entry_id: str,
    name: str,
    *,
    ring_node: str = "ios-node",
    weight: float = 1.0,
    reach: str = "",
) -> dict[str, object]:
    return {
        "id": entry_id,
        "name": name,
        "reach_from_json": f'[{{"source":"{reach}","hops":2}}]',
        "privilege_delta": 2,
        "parser_complexity": 0.5,
        "weight": weight,
        "ring_node": ring_node,
    }


class AdvisoryPrioritizeTests(unittest.TestCase):
    def test_matches_component_to_surface_and_scores(self) -> None:
        result = prioritize(
            [cve("CVE-1")],
            [
                entry("ep1", "com.apple.WebKit.WebContent", weight=1.2, reach="image:/System/Library/WebKit"),
                entry("ep2", "com.apple.Safari", ring_node="macos-node", weight=0.8),
                entry("ep3", "com.apple.bluetoothd", weight=5.0),
            ],
            now=NOW,
            snapshot_source="source",
            snapshot_fetched_at="fetched",
        )
        self.assertEqual(result.cves_considered, 1)
        self.assertEqual(result.surfaces_considered, 3)
        self.assertEqual(result.matched_cves, 1)
        self.assertEqual(len(result.targets), 1)
        target = result.targets[0]
        self.assertEqual(target.cve_id, "CVE-1")
        self.assertEqual(target.entry_point_id, "ep1")
        self.assertEqual(target.ring_node, "ios-node")
        self.assertIn("match:webkit", target.match_reasons)
        self.assertGreater(target.score, 0.9)
        self.assertLess(target.score, 1.0)
        self.assertEqual(result.snapshot_source, "source")
        self.assertEqual(result.snapshot_fetched_at, "fetched")

    def test_platform_compatibility_filters_surfaces(self) -> None:
        mac_cve = cve("CVE-MAC", release="macOS 27", release_os="macOS", category="macOS")
        result = prioritize(
            [mac_cve],
            [
                entry("ep-ios", "com.apple.WebKit.WebContent", ring_node="ios-node"),
                entry("ep-mac", "com.apple.WebKit.WebContent", ring_node="macos-node"),
            ],
            now=NOW,
        )
        self.assertEqual([target.entry_point_id for target in result.targets], ["ep-mac"])
        self.assertEqual(result.surfaces_considered, 2)

    def test_no_platform_constraint_matches_any_ring(self) -> None:
        generic = cve("CVE-GEN", release="Safari 27", release_os="Safari", category="Browser")
        result = prioritize(
            [generic],
            [
                entry("ep-ios", "com.apple.WebKit.WebContent", ring_node="ios-node"),
                entry("ep-mac", "com.apple.WebKit.WebContent", ring_node="macos-node"),
            ],
            now=NOW,
        )
        self.assertEqual(len(result.targets), 2)

    def test_order_truncation_and_roundtrip(self) -> None:
        records = [
            cve("CVE-LOW", max_reward=1000, priority="normal", confidence="medium"),
            cve("CVE-HIGH", max_reward=1000000, priority="critical", confidence="high", in_the_wild=True),
            cve("CVE-MID", max_reward=10000, priority="normal", confidence="low"),
        ]
        surfaces = [entry(f"ep{i}", "com.apple.WebKit.WebContent", weight=float(i + 1)) for i in range(3)]
        result = prioritize(records, surfaces, max_targets=4, now=NOW)
        self.assertEqual(len(result.targets), 4)
        self.assertTrue(result.truncated)
        self.assertEqual(result.targets[0].cve_id, "CVE-HIGH")
        restored = PrioritizationResult.from_dict(result.to_dict())
        self.assertEqual(restored, result)

    def test_unmatched_high_value_count_uses_record_index(self) -> None:
        duplicate_a = cve("CVE-DUP", component="Bluetooth", category="Wireless", max_reward=1000000)
        duplicate_b = cve("CVE-DUP", component="Bluetooth", category="Wireless", max_reward=1000000)
        critical_only = cve(
            "CVE-CRITICAL-ONLY",
            component="CriticalOnly",
            original_component="Critical Only",
            max_reward=0,
            priority="critical",
            confidence="high",
        )
        result = prioritize(
            [duplicate_a, duplicate_b, critical_only, cve("CVE-WEB", component="WebKit")],
            [entry("ep1", "com.apple.WebKit.WebContent")],
            now=NOW,
        )
        self.assertEqual(result.matched_cves, 1)
        self.assertEqual(result.unmatched_high_value, 3)
        self.assertEqual(len(result.targets), 1)

    def test_deterministic_order_for_generated_inputs(self) -> None:
        components = ["WebKit", "Kernel", "ImageIO", "Bluetooth", "Wi-Fi", "Gatekeeper"]
        records = [
            cve(
                f"CVE-{i:04d}",
                component=components[i % len(components)],
                release_os="iOS" if i % 2 else "macOS",
                max_reward=1000 * (i + 1),
                priority=["normal", "high", "critical"][i % 3],
                confidence=["low", "medium", "high"][i % 3],
                release_date=f"2026-11-{(i % 28) + 1:02d}",
            )
            for i in range(40)
        ]
        surfaces = [
            entry(
                f"ep{i}",
                name,
                ring_node="ios-node" if i % 2 else "macos-node",
                weight=0.5 + (i % 5) * 0.25,
                reach=f"image:/System/Library/{name}",
            )
            for i, name in enumerate(
                [
                    "com.apple.WebKit.WebContent",
                    "com.apple.Safari",
                    "com.apple.kernel",
                    "com.apple.imageio",
                    "com.apple.bluetoothd",
                    "com.apple.wifid",
                    "com.apple.gatekeeper",
                ]
            )
        ]
        first = prioritize(records, surfaces, max_targets=1, now=NOW)
        second = prioritize(records, surfaces, max_targets=1, now=NOW)
        self.assertEqual(first.to_dict(), second.to_dict())
        keys = [(-target.score, target.cve_id, target.entry_point_id) for target in first.targets]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(first.targets), 1)
        self.assertTrue(first.truncated)
        self.assertLessEqual(first.matched_cves, len(records))
        self.assertGreaterEqual(first.unmatched_high_value, 0)

    def test_advisory_text_terms_map_unknown_components_to_surfaces(self) -> None:
        record = cve(
            "CVE-WEBPAGE",
            component="App Store",
            original_component="App Store",
            impact="Processing a malicious webpage may lead to arbitrary code execution",
            description="Improved checks.",
            release="iOS 27",
            release_os="iOS",
            max_reward=10000,
            priority="normal",
            confidence="low",
        )
        result = prioritize(
            [record],
            [
                entry("ep-webkit", "com.apple.WebKit.WebContent"),
                entry("ep-other", "com.apple.otherd", ring_node="ios-node"),
            ],
            now=NOW,
        )
        self.assertEqual([target.entry_point_id for target in result.targets], ["ep-webkit"])
        self.assertIn("match:webkit", result.targets[0].match_reasons)

    def test_score_factors_wild_critical_and_unknown_priority(self) -> None:
        records = [
            cve("CVE-BASE", max_reward=0, priority="normal", confidence="high", in_the_wild=False),
            cve("CVE-WILD", max_reward=0, priority="normal", confidence="high", in_the_wild=True),
            cve("CVE-CRIT", max_reward=0, priority="critical", confidence="high", in_the_wild=False),
            cve("CVE-UNKNOWNPRI", max_reward=0, priority="other", confidence="high", in_the_wild=False),
        ]
        result = prioritize(records, [entry("ep1", "com.apple.WebKit.WebContent")], now=NOW)
        scores = {target.cve_id: target.score for target in result.targets}
        self.assertEqual(
            set(scores), {"CVE-BASE", "CVE-WILD", "CVE-CRIT", "CVE-UNKNOWNPRI"}
        )
        self.assertGreater(scores["CVE-WILD"], scores["CVE-BASE"])
        self.assertGreater(scores["CVE-CRIT"], scores["CVE-WILD"])
        self.assertLess(scores["CVE-UNKNOWNPRI"], scores["CVE-BASE"])

    def test_validation_and_edges(self) -> None:
        with self.assertRaises(FormatFail):
            prioritize([cve("CVE-1")], [], max_targets=0)
        with self.assertRaises(FormatFail):
            prioritize([cve("CVE-1")], [], max_targets=-1)
        with self.assertRaises(FormatFail):
            prioritize([cve("CVE-1")], [{"id": "ep", "name": "x", "weight": "bad"}])
        with self.assertRaises(FormatFail):
            prioritize([cve("CVE-1")], [{"id": "ep", "name": "", "weight": 1.0}])
        empty_component = cve("CVE-EMPTY", component="", original_component="")
        self.assertEqual(prioritize([empty_component], [entry("ep1", "com.apple.WebKit.WebContent")], now=NOW).targets, ())
        self.assertEqual(
            prioritize([], [entry("ep1", "com.apple.WebKit.WebContent")], now=NOW).cves_considered,
            0,
        )
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict({})
        with self.assertRaises(FormatFail):
            PrioritizedTarget.from_dict({"cve_id": "CVE-1"})
        with self.assertRaises(FormatFail):
            prioritize(
                [cve("CVE-1")],
                [{"id": "ep", "name": "x", "ring_node": "r", "reach_from_json": 1, "weight": 1.0}],
            )
        with self.assertRaises(FormatFail):
            prioritize(
                [cve("CVE-1")],
                [{"id": 1, "name": "x", "ring_node": "r", "weight": 1.0}],
            )
        with self.assertRaises(FormatFail):
            prioritize(
                [cve("CVE-1")],
                [{"id": "ep", "name": "x", "ring_node": "r", "weight": float("nan")}],
            )
        valid_result = prioritize([cve("CVE-1")], [entry("ep1", "com.apple.WebKit.WebContent")], now=NOW)
        bad_targets = valid_result.to_dict()
        bad_targets["targets"] = "not-a-list"
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_targets)
        bad_items = valid_result.to_dict()
        bad_items["targets"] = [1]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_items)

        target_dict = dict(valid_result.to_dict()["targets"][0])
        bad_reasons = valid_result.to_dict()
        bad_reasons["targets"] = [{**target_dict, "match_reasons": "x"}]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_reasons)
        bad_reason_item = valid_result.to_dict()
        bad_reason_item["targets"] = [{**target_dict, "match_reasons": ["ok", 1]}]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_reason_item)
        bad_score = valid_result.to_dict()
        bad_score["targets"] = [{**target_dict, "score": "high"}]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_score)
        bad_score_nan = valid_result.to_dict()
        bad_score_nan["targets"] = [{**target_dict, "score": float("nan")}]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_score_nan)
        bad_weight_negative = valid_result.to_dict()
        bad_weight_negative["targets"] = [{**target_dict, "surface_weight": -1.0}]
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_weight_negative)

        bad_row = valid_result.to_dict()
        bad_row["snapshot_source"] = 1
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_row)
        bad_count = valid_result.to_dict()
        bad_count["cves_considered"] = "1"
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_count)
        inconsistent = valid_result.to_dict()
        inconsistent["cves_considered"] = 0
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(inconsistent)
        bad_unmatched = valid_result.to_dict()
        bad_unmatched["unmatched_high_value"] = 2
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_unmatched)
        bad_truncated = valid_result.to_dict()
        bad_truncated["truncated"] = "yes"
        with self.assertRaises(FormatFail):
            PrioritizationResult.from_dict(bad_truncated)
        with self.assertRaises(FormatFail):
            prioritize([cve("CVE-1")], [1])

        naive = prioritize(
            [cve("CVE-1")],
            [entry("ep1", "com.apple.WebKit.WebContent")],
            now=datetime(2026, 11, 22),
        )
        self.assertEqual(naive.generated_at, "2026-11-22T00:00:00+00:00")
        generic = prioritize(
            [cve("CVE-1")],
            [entry("ep-generic", "com.apple.WebKit.WebContent", ring_node="generic-node")],
            now=NOW,
        )
        self.assertEqual(generic.targets[0].ring_node, "generic-node")

    def test_scoring_edges_platforms_and_unmapped_terms(self) -> None:
        records = [
            cve("CVE-IPADOS", component="WebKit", release="iPadOS 27", release_os="iPadOS"),
            cve("CVE-TVO", component="WebKit", release="tvOS 27", release_os="tvOS"),
            cve("CVE-WATCH", component="WebKit", release="watchOS 27", release_os="watchOS"),
            cve("CVE-VISION", component="WebKit", release="visionOS 27", release_os="visionOS"),
            cve(
                "CVE-CUSTOM",
                component="CustomParser",
                original_component="Custom Parser",
                release="Unknown",
                release_os=None,
                max_reward=0,
                priority="review",
                confidence="other",
                release_date="bad",
            ),
            cve(
                "CVE-EMPTYDATE",
                component="WebKit",
                max_reward=0,
                priority="high",
                confidence="unmapped",
                release_date="",
            ),
            cve(
                "CVE-UNKNOWNCONF",
                component="WebKit",
                max_reward=0,
                priority="normal",
                confidence="other",
                release_date="not-a-date",
            ),
        ]
        surfaces = [
            entry("ep-ipad", "com.apple.WebKit.WebContent", ring_node="ios-node"),
            entry("ep-tvos", "com.apple.WebKit.WebContent", ring_node="tvos-node"),
            entry("ep-watch", "com.apple.WebKit.WebContent", ring_node="watchos-node"),
            entry("ep-vision", "com.apple.WebKit.WebContent", ring_node="visionos-node"),
            entry("ep-custom", "com.apple.customparser", ring_node="macos-node"),
        ]
        result = prioritize(records, surfaces, now=NOW, max_targets=50)
        by_cve: dict[str, list[str]] = {}
        for target in result.targets:
            by_cve.setdefault(target.cve_id, []).append(target.entry_point_id)
        self.assertIn("ep-ipad", by_cve["CVE-IPADOS"])
        self.assertEqual(by_cve["CVE-TVO"], ["ep-tvos"])
        self.assertEqual(by_cve["CVE-WATCH"], ["ep-watch"])
        self.assertEqual(by_cve["CVE-VISION"], ["ep-vision"])
        self.assertEqual(by_cve["CVE-CUSTOM"], ["ep-custom"])
        self.assertIn("ep-ipad", by_cve["CVE-EMPTYDATE"])
        self.assertIn("ep-ipad", by_cve["CVE-UNKNOWNCONF"])
        self.assertEqual(result.cves_considered, len(records))
        self.assertGreater(result.matched_cves, 0)


if __name__ == "__main__":
    unittest.main()
