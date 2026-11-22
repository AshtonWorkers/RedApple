import json
from pathlib import Path

import pytest

import ra.submit.extract as submit_extract
from ra.ledger import ArtifactInput, ClaimArtifactInput, ClaimInput, ClaimState, Ledger
from ra.submit import (
    PACKET_SCHEMA,
    EvidenceRef,
    SubmissionPacket,
    SubmitReportService,
    estimate_bounty_tier,
    finalize_packet,
    packet_from_claim,
    packet_id_for,
    packet_json,
    packet_sha256,
    redact_json_value,
    redact_text,
    render_report_markdown,
    validate_packet_schema,
)
from tests.conftest import run

GOLDEN_DIR = Path(__file__).parents[1] / "golden" / "submit"

GOLDEN_VALUE = {
    "schema": "ra.triage.v1",
    "title": "WebKit use-after-free in SVG animation",
    "bug_class": "uaf",
    "component": "WebContent",
    "surface": "webkit svg",
    "root_cause": "The animation timeline retains a raw pointer after the node is freed.\nContact researcher@example.com for details.",
    "repro_steps": [
        "1. Open the attached HTML in WebKit",
        "- Trigger the SVG animation removal",
        "2. Observe the crash",
    ],
    "crash_signature": "SIGSEGV in WebCore::SVGAnimationElement",
    "exploitability": {
        "rating": "high",
        "primitive": "controlled heap reuse",
        "assessment": "Reachable from web content with script.",
        "signals": ["js_reachable", "payload_present"],
    },
    "impact": "Potential renderer compromise; no kernel escape demonstrated.",
    "chain_summary": "Chains with a separate sandbox escape candidate.",
    "escalation_summary": "No escalation beyond renderer demonstrated.",
    "bounty_tier": "high",
    "target": {"revision": "abc123", "build_type": "release"},
}
GOLDEN_ARTIFACTS = [
    {
        "artifact_id": "art_" + "a" * 64,
        "kind": "crash",
        "role": "evidence",
        "sha256": "b" * 64,
        "bytes": 4096,
        "created": 1720000000000,
        "ttl_class": "pinned",
    }
]


def golden_packet() -> SubmissionPacket:
    row = {
        "id": "cl_golden",
        "run_id": "run_golden",
        "type": "bug_class",
        "value_json": json.dumps(GOLDEN_VALUE, sort_keys=True),
        "confidence": 0.91,
        "state": "promoted",
        "dedup_key": "dedup-golden",
        "created": 1720000000000,
    }
    return packet_from_claim(row, GOLDEN_ARTIFACTS)


def valid_packet(**overrides) -> SubmissionPacket:
    packet = golden_packet()
    values = {
        "packet_id": packet.packet_id,
        "claim_id": packet.claim_id,
        "claim_type": packet.claim_type,
        "title": packet.title,
        "component": packet.component,
        "surface": packet.surface,
        "root_cause": packet.root_cause,
        "repro_steps": packet.repro_steps,
        "crash_signature": packet.crash_signature,
        "exploitability": packet.exploitability,
        "impact": packet.impact,
        "chain_summary": packet.chain_summary,
        "escalation_summary": packet.escalation_summary,
        "bounty_tier": packet.bounty_tier,
        "bounty_rationale": packet.bounty_rationale,
        "confidence": packet.confidence,
        "created": packet.created,
        "run_id": packet.run_id,
        "dedup_key": packet.dedup_key,
        "evidence": packet.evidence,
        "warnings": packet.warnings,
        "schema": packet.schema,
    }
    values.update(overrides)
    return finalize_packet(SubmissionPacket(**values))


def claim_input(
    claim_id: str,
    key: str,
    value: dict,
    *,
    data: bytes = b"submit-evidence",
) -> ClaimInput:
    return ClaimInput(
        claim_id=claim_id,
        type="bug_class",
        value_json=json.dumps(value, sort_keys=True),
        confidence=0.75,
        dedup_key=key,
        created=1720000000000,
        artifacts=(ClaimArtifactInput(ArtifactInput(kind="crash", data=data), role="evidence"),),
    )


async def promote(ledger: Ledger, claim_id: str) -> None:
    await ledger.transition_claim(claim_id, ClaimState.BOUND)
    await ledger.transition_claim(claim_id, ClaimState.REVIEWED)
    await ledger.transition_claim(claim_id, ClaimState.PROMOTED)


def test_RA_SUB_001_golden_packet_json_fixture():
    packet = golden_packet()
    expected = (GOLDEN_DIR / "packet.json").read_text(encoding="utf-8")
    assert packet_json(packet) == expected


def test_RA_SUB_001_golden_report_markdown_fixture():
    packet = golden_packet()
    expected = (GOLDEN_DIR / "report.md").read_text(encoding="utf-8")
    assert render_report_markdown(packet) == expected


def test_RA_SUB_001_rendering_is_deterministic():
    first = golden_packet()
    second = golden_packet()
    assert first == second
    assert packet_json(first) == packet_json(second)
    assert render_report_markdown(first) == render_report_markdown(second)
    assert packet_sha256(first) == packet_sha256(second)
    assert packet_id_for(first) == packet_id_for(second)


def test_RA_SUB_002_redacts_secrets_and_pii():
    secret = "hunter2-password"
    token = "sk-live_abcdefghijklmnop"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    text = (
        "email researcher@example.com path /Users/alice/project serial F2LX1234ABC "
        "device iPhone 15 Pro ip 192.168.1.20 "
        f"Authorization: Bearer abc.def.ghi password={secret} api_key: {token} jwt {jwt} "
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
    )
    redacted = redact_text(text)
    for leaked in ("researcher@example.com", "/Users/alice", "F2LX1234ABC", "192.168.1.20", secret, token, jwt, "MIIB"):
        assert leaked not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted
    assert "[REDACTED_TOKEN]" in redacted


def test_RA_SUB_002_redact_json_value_is_recursive_and_safe():
    class BadStr:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    redacted = redact_json_value(
        {
            "nan": float("nan"),
            "bytes": b"token=abc123",
            "bad": BadStr(),
            "email": "a@b.com",
        }
    )
    assert isinstance(redacted, dict)
    assert redacted["nan"] is None
    assert "[UNPRINTABLE]" in str(redacted)
    assert "abc123" not in str(redacted)
    assert "a@b.com" not in str(redacted)

    nested: dict = {"value": "token=abc123"}
    for _ in range(10):
        nested = {"child": nested}
    deep = redact_json_value({"nested": nested})
    assert "[TRUNCATED]" in str(deep)
    assert "abc123" not in str(deep)


def test_RA_SUB_003_packet_payload_is_canonical_redacted_and_schema_valid():
    packet = valid_packet(
        title="Find attacker@example.com token=abcdef",
        root_cause="see /Users/bob and iPhone 15 Pro",
    )
    payload = packet.to_dict()
    assert validate_packet_schema(packet) == []
    assert payload["schema"] == PACKET_SCHEMA
    assert "attacker@example.com" not in packet_json(packet)
    assert "[REDACTED_EMAIL]" in packet_json(packet)
    assert packet_json(packet) == json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_RA_SUB_003_validate_packet_schema_reports_errors():
    packet = valid_packet()
    assert validate_packet_schema(packet) == []
    broken = valid_packet(schema="bad", confidence=float("nan"), bounty_tier="enormous", created=-1)
    errors = validate_packet_schema(broken)
    assert {"schema", "confidence", "bounty_tier", "created"} <= set(errors)
    not_tuple = valid_packet(repro_steps=["x"])  # type: ignore[arg-type]
    assert "repro_steps" in validate_packet_schema(not_tuple)
    bad_evidence = valid_packet(evidence=({},))  # type: ignore[arg-type]
    assert "evidence" in validate_packet_schema(bad_evidence)
    bad_warnings = valid_packet(warnings=["x"])  # type: ignore[arg-type]
    assert "warnings" in validate_packet_schema(bad_warnings)
    bad_run = valid_packet(run_id=123)  # type: ignore[arg-type]
    assert "run_id" in validate_packet_schema(bad_run)
    for name in ("claim_id", "claim_type", "title", "component", "surface", "root_cause", "crash_signature", "exploitability", "impact", "chain_summary", "escalation_summary", "bounty_tier", "bounty_rationale", "dedup_key"):
        assert name in validate_packet_schema(valid_packet(**{name: 123}))


def test_RA_SUB_004_estimate_bounty_tier_explicit_and_insufficient():
    assert estimate_bounty_tier(
        explicit_tier="High",
        bug_class="uaf",
        surface="webkit",
        component="WebContent",
        exploitability="Rating: high",
        impact="renderer compromise",
        chain_summary="chain",
        escalation_summary="none",
    ) == ("high", "Tier supplied by the promoted claim.")
    assert estimate_bounty_tier(
        explicit_tier="",
        bug_class="",
        surface="unknown surface",
        component="unknown component",
        exploitability="Exploitability not established from the promoted claim.",
        impact="Impact not established from the promoted claim.",
        chain_summary="No chain evidence was present in the promoted claim.",
        escalation_summary="No escalation evidence was present in the promoted claim.",
    ) == ("unknown", "Insufficient promoted-claim evidence for a bounty-tier estimate.")


def test_RA_SUB_004_estimate_bounty_tier_heuristics():
    base = {
        "explicit_tier": "",
        "bug_class": "other",
        "surface": "unknown surface",
        "component": "unknown component",
        "exploitability": "Rating: low",
        "impact": "limited impact",
        "chain_summary": "No chain evidence was present in the promoted claim.",
        "escalation_summary": "No escalation evidence was present in the promoted claim.",
    }
    critical = estimate_bounty_tier(
        **{
            **base,
            "bug_class": "uaf",
            "surface": "xnu kernel",
            "impact": "sandbox escape to kernel",
            "exploitability": "Rating: high",
        }
    )
    high = estimate_bounty_tier(**{**base, "bug_class": "uaf", "impact": "renderer compromise"})
    medium = estimate_bounty_tier(**{**base, "bug_class": "oob_read", "impact": "information leak"})
    low = estimate_bounty_tier(**base)
    medium_primitives = estimate_bounty_tier(
        **{
            **base,
            "exploitability": "Rating: medium\nPrimitive: arbitrary read",
            "chain_summary": "chain",
        }
    )
    chained = estimate_bounty_tier(
        **{
            **base,
            "bug_class": "info_leak",
            "chain_summary": "multi-stage chain with escalation",
            "escalation_summary": "escalates to TCC",
        }
    )
    assert critical[0] == "critical"
    assert high[0] == "high"
    assert medium[0] == "medium"
    assert low[0] == "low"
    assert "medium exploitability rating" in medium_primitives[1]
    assert "strong primitive language" in medium_primitives[1]
    assert chained[0] in {"medium", "high"}
    assert "chain or escalation evidence" in chained[1]


def test_RA_SUB_005_packet_from_claim_handles_garbage_values():
    rows = [
        {"id": "cl_bad_json", "type": "bug_class", "value_json": "{not json", "confidence": "bad", "created": "bad"},
        {"id": "cl_list", "type": "bug_class", "value_json": "[1,2,3]", "confidence": -2, "created": -1},
        {"id": "cl_missing", "type": "bug_class", "confidence": float("inf"), "created": None},
        {"type": "bug_class", "value_json": {"bug_class": "uaf"}, "confidence": 2, "created": 5},
    ]
    for row in rows:
        packet = packet_from_claim(row, extra_warnings=["injected warning"])
        assert validate_packet_schema(packet) == []
        assert packet.bounty_tier in {"critical", "high", "medium", "low", "unknown"}
        assert "injected warning" in packet.warnings or row.get("value_json") == {"bug_class": "uaf"}
    assert packet_from_claim(rows[0]).warnings[0] == "claim value_json is not valid JSON"
    assert packet_from_claim(rows[1]).warnings[0] == "claim value_json is not a JSON object"
    assert packet_from_claim(rows[2]).warnings[0] == "claim value_json missing or empty"


def test_RA_SUB_005_property_style_garbage_findings_stay_valid_and_redacted():
    secrets = ["token=abc123", "researcher@example.com", "/Users/alice", "password=hunter2"]
    for index in range(120):
        value = {
            "bug_class": ["uaf", "oob_read", "other"][index % 3],
            "title": f"finding {index} {secrets[index % len(secrets)]}",
            "root_cause": secrets[(index + 1) % len(secrets)],
            "nested": {"deep": [{"x": index}]},
            "repro_steps": [f"step {index}", f"step {index}"],
        }
        value_json = "not-json" if index % 5 == 0 else json.dumps(value)
        row = {
            "id": f"cl_prop_{index}",
            "type": "bug_class" if index % 2 else ["bad", "root_cause"],
            "value_json": value_json,
            "confidence": index - 10,
            "created": index,
            "run_id": f"run_{index}",
            "dedup_key": f"dedup-{index}",
        }
        artifacts = [
            {
                "artifact_id": f"art_prop_{index}",
                "kind": "crash",
                "role": "evidence",
                "sha256": f"{index:064x}",
                "bytes": index,
                "created": index,
                "ttl_class": "run",
            }
        ]
        packet = packet_from_claim(row, artifacts, extra_warnings=["", "injected warning", "injected warning"])
        assert validate_packet_schema(packet) == []
        rendered = packet_json(packet) + render_report_markdown(packet)
        for secret in secrets:
            assert secret not in rendered


def test_RA_SUB_006_extracts_repro_signature_exploitability_chain_and_title():
    value = {
        "title": "Explicit title",
        "bug_class": "type_confusion",
        "target": {"process": "mediaremoted", "surface": "xpc"},
        "repro_steps": [
            "1. First step",
            "- Second step",
            {"step": "Third step"},
            {"description": "Fourth step"},
            123,
            "Second step",
            {"unknown": "ignored"},
        ],
        "symbolication": {"frames": ["frame one", "frame two", "", "frame three"]},
        "dedup": {"stack_hash": "stack", "alloc_site": "site"},
        "exploitability": {"rating": "medium", "primitive": "type confusion", "signals": ["kernel_reachable", 7]},
        "impact": "media daemon compromise",
        "chain": [{"a": 1, "b": ["x", "y"]}],
        "escalation": "escalates to root",
        "bounty_tier": "medium",
    }
    packet = packet_from_claim(
        {"id": "cl_rich", "type": "bug_class", "value_json": json.dumps(value), "confidence": 0.4, "created": 7},
        GOLDEN_ARTIFACTS,
    )
    assert packet.title == "Explicit title"
    assert packet.component == "mediaremoted"
    assert packet.surface == "xpc"
    assert packet.repro_steps == ("First step", "Second step", "Third step", "Fourth step")
    assert packet.crash_signature == "frame one <- frame two <- frame three"
    assert "Rating: medium" in packet.exploitability
    assert "kernel_reachable" in packet.exploitability
    assert packet.chain_summary.startswith('[{"a":1,"b":["x","y"]}]')
    assert packet.escalation_summary == "escalates to root"
    assert packet.bounty_tier == "medium"


def test_RA_SUB_006_extract_fallbacks_for_signature_exploitability_and_steps():
    row = {
        "id": "cl_fallback",
        "type": "bug_class",
        "value_json": json.dumps(
            {
                "bug_class": "oob_read",
                "crash_class": "out-of-bounds",
                "dedup": {"alloc_site": "malloc zone", "top_frame": "top"},
                "primitive": "relative read",
                "rating": "low",
                "exploit_assessment": "limited",
                "repro": "open packet\nwait for callback\nobserve leak",
            }
        ),
        "confidence": 0.2,
        "created": 9,
        "run_id": "run_fallback",
    }
    packet = packet_from_claim(row)
    assert packet.crash_signature == "alloc_site=malloc zone | top_frame=top"
    assert "Primitive: relative read" in packet.exploitability
    assert packet.repro_steps[0] == "open packet"
    assert packet.repro_steps[1] == "wait for callback"
    assert packet.repro_steps[2] == "observe leak"

    dedup_only = packet_from_claim(
        {
            "id": "cl_dedup",
            "type": "root_cause",
            "value_json": json.dumps({"signature": {"hash": "abc", "bug_class": "uaf"}}),
        }
    )
    assert dedup_only.crash_signature == "hash=abc | bug_class=uaf"

    crash_class = packet_from_claim(
        {"id": "cl_class", "type": "bug_class", "value_json": json.dumps({"crash_class": "null-deref"})}
    )
    assert crash_class.crash_signature == "null-deref"


def test_RA_SUB_006_generated_repro_steps_with_and_without_evidence():
    with_evidence = packet_from_claim(
        {"id": "cl_steps", "type": "bug_class", "value_json": json.dumps({"bug_class": "uaf"})},
        GOLDEN_ARTIFACTS,
    )
    assert with_evidence.repro_steps[0].startswith("Reproduce on the pinned build")
    assert "art_" in with_evidence.repro_steps[1]
    assert "Replay the recorded crash input" in with_evidence.repro_steps[2]

    without_evidence = packet_from_claim(
        {"id": "cl_steps_empty", "type": "bug_class", "value_json": json.dumps({"bug_class": "uaf"})},
        [],
    )
    assert without_evidence.repro_steps[-1].startswith("Obtain the original crash artifact")
    assert "no artifact metadata available" in without_evidence.warnings


def test_RA_SUB_006_evidence_parsing_skips_bad_rows_and_caps_refs():
    artifacts = [{"kind": "missing-id", "role": "x"}]
    artifacts.extend(
        {
            "artifact_id": f"art_{index:03d}",
            "kind": "crash",
            "role": "evidence",
            "sha256": "0" * 64,
            "bytes": "bad" if index == 0 else index,
            "created": "bad" if index == 1 else index,
            "ttl_class": "run",
        }
        for index in range(40)
    )
    packet = packet_from_claim({"id": "cl_evidence", "type": "bug_class", "value_json": "{}"}, artifacts)
    assert len(packet.evidence) == 32
    assert all(isinstance(item, EvidenceRef) for item in packet.evidence)
    assert packet.evidence[0].byte_size == 0
    assert packet.evidence[1].created == 0


def test_RA_SUB_009_extraction_edge_coverage():
    assert submit_extract._scalar_text(bytearray(b"hello"), limit=3) == "hel"
    assert submit_extract._scalar_text(True) == "true"
    assert submit_extract._scalar_text(12.5) == "12.5"
    assert submit_extract._multiline_text(bytearray(b"a\r\nb\rc\n\n\nd")) == "a\nb\nc\n\nd"
    assert submit_extract._string_list(bytearray(b"one\ntwo"), limit=5) == ["one", "two"]
    assert submit_extract._string_list("line1\n-\nline2", limit=5) == ["line1", "line2"]
    assert len(submit_extract._string_list([f"step {index}" for index in range(30)], limit=20)) == 20
    assert len(submit_extract._string_list("\n".join(f"s{index}" for index in range(25)), limit=20)) == 20
    assert (
        len(submit_extract._string_list(["\n".join(f"m{index}" for index in range(25))], limit=20))
        == 20
    )
    assert submit_extract._describe_value("hello") == "hello"
    assert submit_extract._describe_value(3) == "3"
    assert submit_extract._describe_value(object()) == ""
    assert "bytes" in submit_extract._describe_value([1, {"a": b"bytes"}])
    assert len(list(submit_extract._iter_mappings([{"a": 1}, {"b": 2}]))) == 2
    assert list(submit_extract._iter_mappings("not-mapping")) == []
    wide = {"many": {f"k{index}": {"x": index} for index in range(70)}}
    assert len(list(submit_extract._iter_mappings(wide))) > 60
    assert submit_extract._find_raw({"a": "", "b": "value"}, ("a", "b")) == "value"
    assert submit_extract._find_raw({"a": {}}, ("a",)) is None

    long_steps = packet_from_claim(
        {
            "id": "cl_long_steps",
            "type": "bug_class",
            "value_json": json.dumps(
                {"repro_steps": [f"{index:04d}" + "x" * 996 for index in range(9)]}
            ),
        }
    )
    assert len(long_steps.repro_steps) == 8

    edge_cases = [
        {"symbolication": {"frames": ["", "  "]}, "dedup": {"hash": "hash-value"}},
        {"dedup": {"unknown": "x"}, "class_signature": "class-sig"},
        {"exploitability": {"rating": "medium", "signals": "js_reachable"}},
        {"exploitability": "rating high primitive arbitrary read"},
        {"chain": {"bad": b"bytes"}},
    ]
    packets = [packet_from_claim({"id": f"cl_edge_{index}", "type": "bug_class", "value_json": json.dumps(value) if index != 4 else value}) for index, value in enumerate(edge_cases)]
    assert packets[0].crash_signature == "hash=hash-value"
    assert packets[1].crash_signature == "class-sig"
    assert "Signals: none" in packets[2].exploitability
    assert packets[3].exploitability == "rating high primitive arbitrary read"
    assert "bytes" in packets[4].chain_summary

    untitled = packet_from_claim({"id": "cl_untitled", "type": "bug_class", "value_json": "{}"})
    assert untitled.title == "bug class in unknown component"

    blank_signature = packet_from_claim(
        {
            "id": "cl_blank_signature",
            "type": "bug_class",
            "value_json": json.dumps({"class_signature": "   ", "crash_class": "crash-class"}),
        }
    )
    assert blank_signature.crash_signature == "crash-class"
    raw_exploit = packet_from_claim(
        {
            "id": "cl_raw_exploit",
            "type": "bug_class",
            "value_json": {"exploitability": object(), "rating": "low"},
        }
    )
    assert raw_exploit.exploitability.startswith("Rating: low")
    surface_only = packet_from_claim(
        {"id": "cl_surface", "type": "bug_class", "value_json": json.dumps({"surface": "webkit svg"})}
    )
    assert surface_only.title == "bug class in webkit svg"


def test_RA_SUB_007_render_minimal_packet_uses_placeholders():
    packet = SubmissionPacket(
        packet_id="pkt_test",
        claim_id="cl_min",
        claim_type="bug_class",
        title="",
        component="",
        surface="",
        root_cause="",
        repro_steps=(),
        crash_signature="",
        exploitability="",
        impact="",
        chain_summary="",
        escalation_summary="",
        bounty_tier="unknown",
        bounty_rationale="",
        confidence=0.0,
        created=0,
        run_id=None,
        dedup_key="",
    )
    markdown = render_report_markdown(packet)
    assert "Untitled promoted finding" in markdown
    assert "1. Not established." in markdown
    assert "No artifact metadata available." in markdown
    assert "- None." in markdown
    assert "`unknown`" in markdown


def test_RA_SUB_007_render_redacts_packet_and_evidence_fields():
    packet = valid_packet(
        title="Contact attacker@example.com",
        root_cause="password=hunter2 on iPhone 15 Pro",
        impact="leak /Users/alice/document",
        evidence=(
            EvidenceRef(
                artifact_id="attacker@example.com",
                kind="crash",
                role="evidence",
                sha256="0" * 64,
                byte_size=1,
                ttl_class="run",
                created=1,
            ),
        ),
    )
    markdown = render_report_markdown(packet)
    rendered = markdown + packet_json(packet)
    for leaked in ("attacker@example.com", "hunter2", "iPhone 15 Pro", "/Users/alice"):
        assert leaked not in rendered
    assert "[REDACTED_EMAIL]" in rendered
    assert "[REDACTED_SECRET]" in rendered


def test_RA_SUB_008_service_generates_and_stores_reports_deterministically():
    async def body():
        ledger = await Ledger.open(":memory:")
        try:
            await ledger.create_claim(
                claim_input(
                    "cl_submit",
                    "submit-key",
                    {
                        "title": "Ledger-backed UAF",
                        "bug_class": "uaf",
                        "component": "WebContent",
                        "surface": "webkit",
                        "root_cause": "Use after free in WebCore.",
                        "repro_steps": ["open", "trigger"],
                        "impact": "renderer compromise",
                        "bounty_tier": "high",
                    },
                    data=b"ledger-evidence",
                )
            )
            await ledger.create_claim(
                claim_input("cl_limbo", "limbo-key", {"bug_class": "other"}, data=b"ledger-evidence")
            )
            await promote(ledger, "cl_submit")
            service = SubmitReportService(ledger)
            result = await service.generate()
            assert result.stored is True
            assert result.report_count == 1
            submission = result.submissions[0]
            assert submission.packet.claim_id == "cl_submit"
            assert submission.report_artifact_id and submission.report_artifact_id.startswith("art_")
            assert submission.packet_artifact_id and submission.packet_artifact_id.startswith("art_")
            assert "Ledger-backed UAF" in submission.markdown
            assert ledger.artifact_count() == 3

            again = await service.generate()
            assert again.submissions[0].report_sha256 == submission.report_sha256
            assert again.submissions[0].packet_sha256 == submission.packet_sha256
            assert ledger.artifact_count() == 3

            unstored = await service.generate(store=False)
            assert unstored.submissions[0].report_artifact_id is None
            assert unstored.submissions[0].packet_artifact_id is None
            assert unstored.packets[0].claim_id == "cl_submit"
        finally:
            await ledger.close()

    run(body())


class FakeLedger:
    def __init__(self, rows):
        self.rows = rows
        self.puts = []

    def claims_by_state(self, state, *, limit=100):
        return self.rows[:limit]

    def claim_artifacts(self, claim_id):
        raise RuntimeError("injected artifact read failure")

    async def put_artifact(self, kind, data, *, ttl_class="run"):
        self.puts.append((kind, data, ttl_class))
        return f"art_fake_{len(self.puts)}"


def test_RA_SUB_008_service_validates_limits_and_survives_artifact_read_failure():
    with pytest.raises(ValueError):
        SubmitReportService(object(), max_claims=0)  # type: ignore[arg-type]

    rows = [
        {"id": "cl_fail", "type": "bug_class", "value_json": "{}", "confidence": 0.5, "created": 1},
        {"type": "bug_class", "value_json": "{}", "confidence": 0.5, "created": 2},
    ]
    ledger = FakeLedger(rows)
    service = SubmitReportService(ledger)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        service.packets(limit=0)
    packets = service.packets(limit=2)
    assert len(packets) == 2
    assert any("artifact metadata read failed: RuntimeError" in warning for warning in packets[0].warnings)
    assert "claim id missing; artifact metadata not read" in packets[1].warnings

    async def body():
        result = await service.generate(store=True)
        assert result.report_count == 2
        assert len(ledger.puts) == 4
        assert all(item.packet_artifact_id is not None for item in result.submissions)

    run(body())
