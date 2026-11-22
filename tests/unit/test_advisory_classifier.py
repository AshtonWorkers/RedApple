"""RA-ADV bounty classifier tests, ported from PR #1 acceptance cases."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ra.advisory import (
    AdvisorySnapshot,
    CveCredit,
    ReleaseEntry,
    ReleaseRecord,
    catalog_summary,
    classify,
    cves,
    load_bounty_catalog,
    normalize_component,
    parse_bounty_catalog,
)
from ra.errors import FormatFail


class AdvisoryClassifierTests(unittest.TestCase):
    def test_kernel_control_requires_ios_app(self) -> None:
        for platform in ("macOS 27", "tvOS 27", "watchOS 27", "visionOS 27", ""):
            self.assertEqual(
                classify(
                    "Kernel",
                    "An app may execute arbitrary code with kernel privileges",
                    platform=platform,
                ).max_reward,
                0,
            )
        self.assertEqual(
            classify(
                "Kernel",
                "An app may execute arbitrary code with kernel privileges",
                platform="iOS 27",
            ).max_reward,
            500000,
        )
        for impact in (
            "An app may disclose kernel memory",
            "An app may cause unexpected system termination",
        ):
            self.assertEqual(classify("Kernel", impact, platform="iOS 27").max_reward, 0)

    def test_wireless_requires_control_and_radio_scope(self) -> None:
        for impact in (
            "An attacker in Bluetooth range may cause a denial of service",
            "An app may read sensitive location information",
            "An attacker in range may bypass pairing rate limits",
            "An attacker in range may cause memory corruption",
        ):
            self.assertEqual(classify("Bluetooth", impact).max_reward, 0)
        self.assertEqual(
            classify(
                "Apple-designed radio",
                "An attacker in wireless proximity may execute code on the application processor",
            ).max_reward,
            1000000,
        )

    def test_webcontent_escape_independent_of_component(self) -> None:
        for platform in ("iOS 27", "macOS 27"):
            self.assertEqual(
                classify(
                    "App Store",
                    "An app may break out of the WebContent sandbox",
                    platform=platform,
                ).max_reward,
                300000,
            )
        self.assertEqual(
            classify("WebKit", "Processing web content may lead to arbitrary code execution").max_reward,
            10000,
        )
        self.assertEqual(classify("WebKit", "Processing web content may cause a crash").max_reward, 0)

    def test_app_triggered_wireless_falls_through_to_platform_rules(self) -> None:
        impact = "An app may be able to execute arbitrary code with kernel privileges"
        self.assertEqual(classify("Wi-Fi", impact, platform="iOS 18.7.9").max_reward, 500000)
        for platform in ("macOS Tahoe 26.5", "tvOS 27", ""):
            self.assertEqual(classify("Wi-Fi", impact, platform=platform).max_reward, 0)
        for impact in (
            "An app may cause unexpected system termination",
            "An app may cause a denial of service",
        ):
            self.assertEqual(classify("Wi-Fi", impact, platform="iOS 18").max_reward, 0)

    def test_macos_tcc_tiers(self) -> None:
        cases = [
            ("An app may access sensitive user data", 1000),
            ("An unsandboxed app may capture the TCC Target Flag", 5000),
            ("An app may escape its sandbox and capture the TCC Target Flag", 10000),
        ]
        for impact, reward in cases:
            self.assertEqual(classify("TCC", impact, platform="macOS 27").max_reward, reward)
        self.assertEqual(
            classify("Sandbox", "An app may escape its sandbox", platform="macOS 27").max_reward,
            5000,
        )

    def test_gatekeeper_and_physical(self) -> None:
        self.assertEqual(classify("Gatekeeper", "An app may bypass Gatekeeper").max_reward, 10000)
        self.assertEqual(
            classify(
                "Gatekeeper",
                "A complete bypass for Safari-downloaded quarantined apps with standard user interaction",
            ).max_reward,
            100000,
        )
        for impact in (
            "An attacker with physical access to a trust-paired device may access data",
            "An attacker may pair an AirPlay receiver from the lock screen",
        ):
            self.assertEqual(classify("Lock Screen", impact).max_reward, 0)
        self.assertEqual(
            classify(
                "Lock Screen",
                "An attacker with physical access to a locked device may extract sensitive user data",
            ).max_reward,
            500000,
        )

    def test_pcc_categories(self) -> None:
        cases = [
            (
                "A remote attack on request data may allow unsigned code execution with arbitrary entitlements",
                1000000,
            ),
            ("A remote attack may access request data outside the trust boundary", 250000),
            ("A privileged network attacker may access request data outside the trust boundary", 150000),
            ("A privileged network attacker may achieve unattested code execution", 100000),
            ("A deployment configuration issue may disclose sensitive data", 50000),
        ]
        for impact, reward in cases:
            self.assertEqual(classify("Private Cloud Compute", impact).max_reward, reward)
        self.assertEqual(classify("PCC", "An attacker may crash a service").max_reward, 0)

    def test_wild_is_priority_not_invented_eligibility(self) -> None:
        impact = (
            "Processing a maliciously crafted file may lead to arbitrary code execution. "
            "Apple is aware this may have been exploited against specific individuals"
        )
        result = classify("CoreGraphics", impact)
        self.assertTrue(result.in_the_wild)
        self.assertEqual(result.priority, "high")
        self.assertTrue(result.needs_review)
        self.assertEqual(result.category, "Unmapped")
        self.assertEqual(classify("WebKit", impact).max_reward, 10000)

    def test_human_review_empty_and_credit_type(self) -> None:
        self.assertEqual(
            classify("Messages", "A remote attacker may receive its messages").priority,
            "review",
        )
        self.assertEqual(
            classify("Kernel", "An app may gain root privileges", platform="macOS 27").priority,
            "review",
        )
        empty = classify()
        self.assertEqual(empty.category, "Unmapped")
        self.assertEqual(empty.confidence, "unmapped")
        self.assertEqual(classify(credit="Apple").credit_type, "Apple")
        self.assertEqual(classify(credit="Researcher").credit_type, "external")
        self.assertEqual(classify(credit="").credit_type, "unknown")

    def test_normalization_and_catalog_summary(self) -> None:
        self.assertEqual(normalize_component("RemoteManagement"), "Remote Management")
        self.assertEqual(normalize_component("WebKit Web Inspector"), "WebKit")
        self.assertEqual(normalize_component("Accelerate Framework"), "Accelerate")
        self.assertEqual(normalize_component("System Preferences"), "System Settings")
        self.assertEqual(normalize_component("Core Text"), "CoreText")
        self.assertEqual(normalize_component("iMessage"), "Messages")
        self.assertEqual(normalize_component("PCC"), "Private Cloud Compute")
        summary = catalog_summary()
        self.assertEqual(summary["categories"], 28)
        self.assertGreater(summary["max_reward"], 0)
        self.assertTrue(summary["source"])

    def test_cves_flattens_snapshot_with_release_context(self) -> None:
        entry = ReleaseEntry(
            component="WebKit",
            available_for="iPhone",
            impact="Processing web content may lead to arbitrary code execution",
            description="Fixed.",
            cves=(CveCredit(id="CVE-2026-12345", credit="Researcher"),),
        )
        release = ReleaseRecord(
            name="iOS 27",
            date="2026-11-09",
            available_for="iPhone",
            url="https://support.apple.com/en-us/123456",
            os="iOS",
            version="27",
            builds=("23A123",),
            entries=(entry,),
            advisory_title="About iOS 27",
        )
        snapshot = AdvisorySnapshot(
            source="https://support.apple.com/en-us/100100",
            fetched_at="2026-11-22T00:00:00+00:00",
            releases=(release,),
        )
        records = cves(snapshot)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.id, "CVE-2026-12345")
        self.assertEqual(record.component, "WebKit")
        self.assertEqual(record.release_os, "iOS")
        self.assertEqual(record.max_reward, 10000)
        self.assertEqual(record.credit_type, "external")
        self.assertEqual(cves(AdvisorySnapshot(source="s", fetched_at="f", releases=())), [])

    def test_catalog_validation(self) -> None:
        with self.assertRaises(FormatFail):
            parse_bounty_catalog("not json")
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(json.dumps({"source": "s", "fetched_at": "f", "categories": []}))
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(
                json.dumps(
                    {
                        "source": "s",
                        "fetched_at": "f",
                        "categories": [
                            {"id": "x"},
                            {"id": "x"},
                        ],
                    }
                )
            )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_text(json.dumps(load_bounty_catalog().to_dict()), encoding="utf-8")
            loaded = load_bounty_catalog(path)
            self.assertEqual(loaded.categories[0].id, load_bounty_catalog().categories[0].id)


    def test_catalog_lookup_misses_and_classification_dict(self) -> None:
        catalog = load_bounty_catalog()
        self.assertIsNone(catalog.by_id("does-not-exist"))
        self.assertIsNone(catalog.by_entry_point("does-not-exist", "does-not-exist"))
        result = classify("WebKit", "Processing web content may lead to arbitrary code execution")
        self.assertEqual(result.to_dict()["category_id"], "category-9")
        self.assertEqual(result.to_dict()["max_reward"], 10000)

    def test_catalog_validation_details(self) -> None:
        def valid_category(identifier: str = "cat-1", entry_point: str = "Entry", end_point: str = "End") -> dict[str, object]:
            return {
                "id": identifier,
                "program": "program",
                "entry_point": entry_point,
                "end_point": end_point,
                "max_reward": 1,
                "description": "description",
                "tiers": [],
                "source": "source",
                "target_flag_required": False,
                "examples_text": "",
            }

        def payload(categories: object) -> str:
            return json.dumps({"source": "s", "fetched_at": "f", "categories": categories})

        with self.assertRaises(FormatFail):
            parse_bounty_catalog(json.dumps([1]))
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload("not-a-list"))
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([1]))

        bad_int = valid_category()
        bad_int["max_reward"] = "1"
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([bad_int]))

        bad_bool = valid_category()
        bad_bool["target_flag_required"] = "no"
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([bad_bool]))

        bad_tiers = valid_category()
        bad_tiers["tiers"] = "not-a-list"
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([bad_tiers]))

        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([valid_category("dup", "A", "B"), valid_category("dup", "C", "D")]))
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([valid_category("pair-1", "Same", "End"), valid_category("pair-2", "Same", "End")]))

        negative_reward = valid_category()
        negative_reward["max_reward"] = -1
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([negative_reward]))

        negative_tier = valid_category()
        negative_tier["tiers"] = [
            {"reward": -1, "description": "tier", "target_flag_required": False, "source": "source"}
        ]
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(payload([negative_tier]))

        with self.assertRaises(FormatFail):
            parse_bounty_catalog('{"source": "s", "fetched_at": "f", "categories": [], "bad": NaN}')
        with self.assertRaises(FormatFail):
            parse_bounty_catalog("[" * 10000 + "]" * 10000)

        missing_source = json.dumps({"fetched_at": "f", "categories": [valid_category()]})
        with self.assertRaises(FormatFail):
            parse_bounty_catalog(missing_source)

    def test_classification_is_deterministic_for_generated_inputs(self) -> None:
        components = ("WebKit", "Kernel", "Bluetooth", "Private Cloud Compute", "Custom Parser")
        impacts = (
            "Processing web content may lead to arbitrary code execution",
            "An app may escape its sandbox and access sensitive user data",
            "An attacker in wireless proximity may execute code on the application processor",
            "A remote attack on request data may allow unsigned code execution with arbitrary entitlements",
        )
        platforms = ("iOS 27", "macOS 27", "")
        for component in components:
            for impact in impacts:
                for platform in platforms:
                    first = classify(component, impact, platform=platform).to_dict()
                    second = classify(component, impact, platform=platform).to_dict()
                    self.assertEqual(first, second)

    def test_pcc_unmatched_branches_stay_unmapped(self) -> None:
        for impact in (
            "A privileged network attacker may cause a denial of service",
            "A remote attack on request data may cause a denial of service",
            "A remote attack may crash a service",
        ):
            result = classify("Private Cloud Compute", impact)
            self.assertEqual(result.max_reward, 0)
            self.assertEqual(result.category, "Unmapped")
            self.assertTrue(result.needs_review)

    def test_ios_app_sensitive_data_branch(self) -> None:
        result = classify(
            "Kernel",
            "A malicious app may access sensitive user data",
            platform="iOS 27",
        )
        self.assertNotEqual(result.category, "Unmapped")
        self.assertGreater(result.max_reward, 0)
        self.assertFalse(result.needs_review)


if __name__ == "__main__":
    unittest.main()
