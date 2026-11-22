"""Tests for ``ra.discovery.store`` ledger persistence."""

from __future__ import annotations

import json
import signal
import tempfile
import unittest
from pathlib import Path

from ra.discovery.harness import classify_run
from ra.discovery.store import (
    CLAIM_TYPE_CAMPAIGN,
    CLAIM_TYPE_CRASH,
    MAX_INLINE_INPUT,
    CampaignSummary,
    CrashRecord,
    LedgerCrashStore,
    records_from_rows,
)
from ra.errors import FormatFail
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, Ledger


def crash_result(**overrides: object):
    base: dict[str, object] = {
        "returncode": -int(signal.SIGSEGV),
        "stderr": "segv at 0x1234\n",
    }
    base.update(overrides)
    return classify_run(**base)  # type: ignore[arg-type]


class LedgerCrashStoreTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = await Ledger.open(Path(self._tmp.name) / "ledger.sqlite")
        self.store = LedgerCrashStore(self.ledger)

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    async def test_record_crash_creates_claim_with_artifacts(self) -> None:
        result = crash_result()
        record = await self.store.record_crash(
            "print('crash');", result, {"handle_id": "h1", "target": "webkit"}
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertTrue(record.claim_id.startswith("jsc_"))
        self.assertEqual(record.handle_id, "h1")
        self.assertEqual(record.input_js, b"print('crash');")
        self.assertEqual(len(record.artifact_ids), 3)

        rows = self.ledger.claims_by_type(CLAIM_TYPE_CRASH)
        self.assertEqual(len(rows), 1)
        value = json.loads(rows[0]["value_json"])
        self.assertEqual(value["signature"], result.signature)
        self.assertEqual(value["crash_type"], "SIGSEGV")
        self.assertEqual(value["handle_id"], "h1")
        self.assertEqual(value["target"], "webkit")
        self.assertIsNotNone(value["input_inline"])
        self.assertEqual(value["input_sha256"], record.artifact_ids[0])

        links = self.ledger.claim_artifacts(record.claim_id)
        self.assertEqual(len(links), 3)
        kinds = {link["kind"] for link in links}
        self.assertEqual(kinds, {"jsc_input", "jsc_stderr", "jsc_stack"})

    async def test_record_crash_rejects_non_crash(self) -> None:
        result = classify_run(0, "")
        with self.assertRaises(FormatFail):
            await self.store.record_crash("x", result, {"handle_id": "h"})

    async def test_record_crash_requires_handle_id(self) -> None:
        result = crash_result()
        with self.assertRaises(FormatFail):
            await self.store.record_crash("x", result, {})
        with self.assertRaises(FormatFail):
            await self.store.record_crash("x", result, {"handle_id": ""})

    async def test_duplicate_signature_returns_none(self) -> None:
        result = crash_result()
        first = await self.store.record_crash("same", result, {"handle_id": "h1"})
        second = await self.store.record_crash("same", result, {"handle_id": "h2"})
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        rows = self.ledger.claims_by_type(CLAIM_TYPE_CRASH)
        self.assertEqual(len(rows), 1)

    async def test_known_signatures(self) -> None:
        self.assertEqual(await self.store.known_signatures(), set())
        result = crash_result()
        await self.store.record_crash("x", result, {"handle_id": "h"})
        known = await self.store.known_signatures()
        self.assertEqual(known, {result.signature})

    async def test_crashes_for_handle_filters_and_sorts(self) -> None:
        r1 = crash_result(stderr="first fault 0x111\n")
        r2 = crash_result(stderr="second fault 0x222\n")
        await self.store.record_crash("a", r1, {"handle_id": "h1"})
        await self.store.record_crash("b", r2, {"handle_id": "h2"})
        records_h1 = await self.store.crashes_for_handle("h1")
        self.assertEqual(len(records_h1), 1)
        self.assertEqual(records_h1[0].handle_id, "h1")
        self.assertEqual(records_h1[0].input_js, b"a")
        self.assertEqual(records_h1[0].stderr, r1.stderr)
        self.assertEqual(await self.store.crashes_for_handle("unknown"), [])

    async def test_large_input_not_inlined_but_hash_kept(self) -> None:
        big = "x" * (MAX_INLINE_INPUT + 10)
        result = crash_result()
        record = await self.store.record_crash(big, result, {"handle_id": "h"})
        assert record is not None
        rows = self.ledger.claims_by_type(CLAIM_TYPE_CRASH)
        value = json.loads(rows[0]["value_json"])
        self.assertIsNone(value["input_inline"])
        self.assertTrue(value["input_sha256"].startswith("art_"))
        # Rehydrated record has empty input (bytes live only in artifacts)
        rehydrated = await self.store.crashes_for_handle("h")
        self.assertEqual(rehydrated[0].input_js, b"")
        self.assertEqual(rehydrated[0].signature, result.signature)

    async def test_small_input_inline_roundtrip(self) -> None:
        result = crash_result()
        await self.store.record_crash("print(1);", result, {"handle_id": "h"})
        rehydrated = await self.store.crashes_for_handle("h")
        self.assertEqual(rehydrated[0].input_js, b"print(1);")
        self.assertEqual(len(rehydrated[0].artifact_ids), 3)

    async def test_record_campaign_and_summaries(self) -> None:
        summary = CampaignSummary(
            campaign_id="camp-1",
            handle_id="h1",
            target="webkit",
            ring_node="node",
            build="b1",
            jsc_binary="jsc",
            jsc_args=("--x",),
            seed=1,
            executions=10,
            unique_crashes=1,
            total_crashes=2,
            exec_errors=0,
            timeouts=1,
            duration_ms=100,
        )
        claim_id = await self.store.record_campaign(summary)
        self.assertTrue(claim_id.startswith("camp_"))
        rows = self.ledger.claims_by_type(CLAIM_TYPE_CAMPAIGN)
        self.assertEqual(len(rows), 1)
        summaries = await self.store.campaign_summaries()
        self.assertEqual(summaries, [summary])

    async def test_record_campaign_idempotent(self) -> None:
        summary = CampaignSummary(
            campaign_id="camp-1",
            handle_id="h",
            target="",
            ring_node=None,
            build=None,
            jsc_binary="jsc",
            jsc_args=(),
            seed=0,
            executions=1,
            unique_crashes=0,
            total_crashes=0,
            exec_errors=0,
            timeouts=0,
            duration_ms=0,
        )
        first = await self.store.record_campaign(summary)
        second = await self.store.record_campaign(summary)
        self.assertEqual(first, second)
        self.assertEqual(len(self.ledger.claims_by_type(CLAIM_TYPE_CAMPAIGN)), 1)

    async def test_campaign_summaries_skip_malformed(self) -> None:
        # Valid JSON but missing required keys -> skipped by from_dict.
        await self.ledger.create_claim(
            ClaimInput(
                claim_id="camp_bad",
                type=CLAIM_TYPE_CAMPAIGN,
                value_json="{}",
                confidence=1.0,
                dedup_key="discovery_campaign:bad",
                created=1,
                artifacts=(
                    ClaimArtifactInput(
                        artifact=ArtifactInput(
                            kind="discovery_campaign", data=b"{}", ttl_class="run"
                        ),
                        role="summary",
                    ),
                ),
            )
        )
        summaries = await self.store.campaign_summaries()
        self.assertEqual(summaries, [])

    async def test_records_from_rows(self) -> None:
        result = crash_result()
        await self.store.record_crash("payload", result, {"handle_id": "h"})
        rows = self.ledger.claims_by_type(CLAIM_TYPE_CRASH)
        records = records_from_rows(rows)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].signature, result.signature)
        self.assertEqual(records[0].input_js, b"payload")

    async def test_records_from_rows_skips_malformed(self) -> None:
        records = records_from_rows([{"id": "x", "value_json": "not-json"}])
        self.assertEqual(records, [])

    async def test_record_crash_accepts_bytes_content(self) -> None:
        result = crash_result()
        record = await self.store.record_crash(b"\x00\xffbinary", result, {"handle_id": "h"})
        assert record is not None
        self.assertEqual(record.input_js, b"\x00\xffbinary")

    async def test_known_signatures_skips_non_string(self) -> None:
        await self.ledger.create_claim(
            ClaimInput(
                claim_id="crash_bad",
                type=CLAIM_TYPE_CRASH,
                value_json='{"signature": 123, "handle_id": "h"}',
                confidence=1.0,
                dedup_key="discovery_crash:bad",
                created=1,
                artifacts=(
                    ClaimArtifactInput(
                        artifact=ArtifactInput(kind="jsc_input", data=b"x", ttl_class="run"),
                        role="repro",
                    ),
                ),
            )
        )
        self.assertEqual(await self.store.known_signatures(), set())

    async def test_records_from_rows_tolerates_bad_values(self) -> None:
        row = {
            "id": "crash_x",
            "value_json": json.dumps(
                {
                    "signature": "s1",
                    "crash_type": "SIGSEGV",
                    "handle_id": "h",
                    "input_inline": "!!!not-base64!!!",
                    "created_ms": "not-a-number",
                }
            ),
        }
        records = records_from_rows([row])
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].input_js, b"")
        self.assertEqual(records[0].created_ms, 0)

    async def test_crashes_for_handle_skips_malformed_record(self) -> None:
        await self.ledger.create_claim(
            ClaimInput(
                claim_id="crash_min",
                type=CLAIM_TYPE_CRASH,
                value_json='{"handle_id": "h", "signature": "s"}',
                confidence=1.0,
                dedup_key="discovery_crash:min",
                created=1,
                artifacts=(
                    ClaimArtifactInput(
                        artifact=ArtifactInput(kind="jsc_input", data=b"x", ttl_class="run"),
                        role="repro",
                    ),
                ),
            )
        )
        # Missing crash_type/returncode etc -> _record_from_row returns None -> skipped
        records = await self.store.crashes_for_handle("h")
        self.assertEqual(records, [])

    async def test_state_survives_ledger_reopen(self) -> None:
        path = Path(self._tmp.name) / "reopen.sqlite"
        ledger = await Ledger.open(path)
        store = LedgerCrashStore(ledger)
        result = crash_result()
        await store.record_crash("persist", result, {"handle_id": "h"})
        await ledger.close()

        ledger2 = await Ledger.open(path)
        try:
            store2 = LedgerCrashStore(ledger2)
            known = await store2.known_signatures()
            self.assertEqual(known, {result.signature})
            records = await store2.crashes_for_handle("h")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0].input_js, b"persist")
        finally:
            await ledger2.close()


class CrashRecordTest(unittest.TestCase):
    def test_record_defaults(self) -> None:
        record = CrashRecord(
            claim_id="c",
            signature="s",
            crash_type="t",
            signal="",
            returncode=0,
            stack=(),
            input_js=b"",
            stderr="",
            handle_id="h",
            target="",
            ring_node=None,
            build=None,
            artifact_ids=(),
            created_ms=0,
        )
        self.assertEqual(record.campaign_id, None)
        self.assertEqual(record.metadata, {})
