"""Adversarial hardening tests for the groom planner and primitive ladder."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

import pytest

from ra.errors import DialectDefect, DuplicateDedup, FormatFail
from ra.groom import (
    RUNG_ASSERTIONS,
    AllocatorModel,
    AllocatorModelSet,
    AttemptEvidence,
    CrashCase,
    FoundryDialectGate,
    GroomCandidate,
    GroomPlan,
    GroomPlanner,
    HeapDiff,
    HeapDiffExpectation,
    HeapDiffResult,
    HeapObject,
    HeapSnapshot,
    LadderRung,
    LadderRunner,
    LedgerFoundryDefectSink,
    TriageResult,
    adjacent_size_classes,
    is_valid_size_class,
    load_allocator_models,
    size_class_for_kb,
    validate_heap_diff,
)
from ra.groom.ledgerio import create_claim_once, finalize_claim, transition_if_needed
from ra.ledger import ClaimState, Ledger


def _dialect(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "format": "heif",
        "pre_seed": [{"box": "meta", "pad_to_class": "kalloc_1024", "count": 2}],
        "victim_pad": "align_to_class",
        "victim_class": "kalloc_2048",
        "post": {"free": "ipco_before_victim"},
        "validator": "heap_diff.class_stable",
    }
    value.update(overrides)
    return value


def _candidate(candidate_id: str = "groom_adv", size_class: str = "kalloc_2048") -> GroomCandidate:
    return GroomCandidate(
        candidate_id=candidate_id,
        depth=1,
        score=1.0,
        dialect=_dialect(victim_class=size_class),
        size_class=size_class,
        provenance={"libpas_size_classes": "https://example.com/libpas"},
        rationale="adversarial test candidate",
    )


def _models_payload() -> dict[str, Any]:
    return {
        "format": "heif",
        "models": {
            "libpas_size_classes": {
                "provenance": "https://example.com/libpas",
                "classes_kb": [16, 32],
            },
            "gigacage": {
                "provenance": "https://example.com/cage",
                "cages": ["primitive"],
            },
            "isoheap": {
                "provenance": "https://example.com/isoheap",
                "values": ["per_type"],
            },
            "structure_id": {
                "provenance": "https://example.com/structure",
                "values": ["transition"],
            },
        },
    }


def test_allocator_models_reject_adversarial_files(tmp_path: Path) -> None:
    path = tmp_path / "models.json"

    def write(payload: Any) -> None:
        path.write_text(json.dumps(payload), encoding="utf-8")

    missing_isoheap = _models_payload()
    del missing_isoheap["models"]["isoheap"]
    write(missing_isoheap)
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    unsorted = _models_payload()
    unsorted["models"]["libpas_size_classes"]["classes_kb"] = [32, 16]
    write(unsorted)
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    duplicate_classes = _models_payload()
    duplicate_classes["models"]["libpas_size_classes"]["classes_kb"] = [16, 16]
    write(duplicate_classes)
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    empty_cages = _models_payload()
    empty_cages["models"]["gigacage"]["cages"] = []
    write(empty_cages)
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    empty_isoheap_values = _models_payload()
    empty_isoheap_values["models"]["isoheap"]["values"] = []
    write(empty_isoheap_values)
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    classes_on_cage = _models_payload()
    classes_on_cage["models"]["gigacage"]["classes_kb"] = [16]
    write(classes_on_cage)
    with pytest.raises(FormatFail):
        load_allocator_models(path)


def test_model_dto_validation_and_serialization_edges() -> None:
    case = CrashCase(id="case-adv", target="media", payload=b"payload", metadata={"size_kb": 16}, created_ms=1)
    assert case.to_dict()["payload_bytes"] == 7
    assert CrashCase.from_mapping({"id": "m", "payload": "text", "metadata": [], "created_ms": 0}).payload == b"text"
    assert CrashCase.from_mapping({"id": "m", "payload": b"bytes"}).payload == b"bytes"
    assert CrashCase.from_mapping({"id": "m", "payload": 123}).payload == b""
    for kwargs in (
        {"id": ""},
        {"id": "x", "target": 1},
        {"id": "x", "payload": bytearray(b"x")},
        {"id": "x", "metadata": []},
        {"id": "x", "created_ms": -1},
    ):
        with pytest.raises(ValueError):
            CrashCase(**kwargs)

    triage = TriageResult(bug_class="heap", primitive_hint="oob_read", confidence=0.5, rationale="r", artifacts=(b"a",))
    assert triage.to_dict()["artifact_count"] == 1
    for kwargs in (
        {"bug_class": ""},
        {"bug_class": "heap", "primitive_hint": ""},
        {"bug_class": "heap", "confidence": float("nan")},
        {"bug_class": "heap", "confidence": 2},
        {"bug_class": "heap", "rationale": 1},
        {"bug_class": "heap", "artifacts": b"x"},
        {"bug_class": "heap", "artifacts": 1},
        {"bug_class": "heap", "artifacts": (1,)},
    ):
        with pytest.raises(ValueError):
            TriageResult(**kwargs)

    with pytest.raises(ValueError):
        HeapObject("kalloc_16", state="")
    for bad_objects in (b"x", 1, (object(),)):
        with pytest.raises(ValueError):
            HeapSnapshot(label="snap", objects=bad_objects)  # type: ignore[arg-type]
    victim = HeapObject("kalloc_16", role="victim")
    assert HeapDiff(added=(victim,)).to_dict()["added"] == [victim.to_dict()]
    assert HeapDiffExpectation(removed=(victim,)).to_dict()["removed"] == [victim.to_dict()]
    assert HeapDiffResult(passed=False, validator="heap_diff.class_stable").to_dict()["diff"] is None

    base_candidate = {
        "candidate_id": "c",
        "depth": 0,
        "score": 1.0,
        "dialect": _dialect(),
        "size_class": "kalloc_16",
    }
    GroomCandidate(**base_candidate).to_dict()
    for kwargs in (
        {"candidate_id": ""},
        {"score": float("nan")},
        {"dialect": []},
        {"size_class": "bad"},
        {"cage": 1},
        {"provenance": []},
        {"provenance": {"a": 1}},
        {"rationale": 1},
    ):
        with pytest.raises(ValueError):
            GroomCandidate(**{**base_candidate, **kwargs})

    base_plan = {"plan_id": "p", "crash_id": "case", "candidates": (_candidate(),)}
    GroomPlan(**base_plan).to_dict()
    for kwargs in (
        {"crash_id": ""},
        {"candidates": b"x"},
        {"candidates": 1},
        {"candidates": (object(),)},
        {"candidates": tuple(_candidate(f"c{i}") for i in range(65))},
        {"stats": []},
        {"stats": {"x": True}},
        {"created_ms": -1},
    ):
        with pytest.raises(ValueError):
            GroomPlan(**{**base_plan, **kwargs})

    evidence_kwargs = {
        "rung": LadderRung.INFO_LEAK,
        "passed": True,
        "assertion": RUNG_ASSERTIONS[LadderRung.INFO_LEAK],
    }
    AttemptEvidence(**evidence_kwargs).to_dict()
    for kwargs in (
        {"assertion": 1},
        {"assertion_results": []},
        {"assertion_results": {"x": 1}},
        {"heap_before": object()},
        {"heap_after": object()},
        {"heap_expectation": object()},
        {"artifact_payload": "x"},
        {"details": []},
    ):
        with pytest.raises(ValueError):
            AttemptEvidence(**{**evidence_kwargs, **kwargs})


def test_allocator_model_loader_and_helper_edges(tmp_path: Path) -> None:
    models = load_allocator_models()
    assert models.to_dict()["format"] == "heif"
    assert AllocatorModel(name="m", provenance="p", classes_kb=(1,), cages=("c",), values=("v",)).to_dict()["name"] == "m"
    with pytest.raises(FormatFail):
        models.get("missing")
    assert models.is_known_isoheap("per_type")
    assert models.is_known_structure_id("transition")
    assert models.provenance_for("kalloc_999") == {"libpas_size_classes": models.libpas().provenance}
    with pytest.raises(FormatFail):
        adjacent_size_classes("kalloc_999", models)

    path = tmp_path / "models.json"
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"] = {}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["libpas_size_classes"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["libpas_size_classes"]["classes_kb"] = {}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["libpas_size_classes"]["classes_kb"] = []
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["gigacage"]["cages"] = {}
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["gigacage"]["cages"] = [""]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["gigacage"]["cages"] = ["primitive", "primitive"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)
    payload = _models_payload()
    payload["models"]["structure_id"]["values"] = ["transition", "transition"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FormatFail):
        load_allocator_models(path)

    empty = AllocatorModelSet(
        format="heif",
        models=(AllocatorModel(name="libpas_size_classes", provenance="p", classes_kb=()),),
    )
    with pytest.raises(FormatFail):
        size_class_for_kb(1, empty)


def test_heap_diff_custom_models_and_serialization_edges(tmp_path: Path) -> None:
    path = tmp_path / "models.json"
    path.write_text(json.dumps(_models_payload()), encoding="utf-8")
    models = load_allocator_models(path)
    dialect = _dialect(victim_class="kalloc_32", pre_seed=[{"box": "meta"}])
    before = HeapSnapshot(label="before")
    after = HeapSnapshot(label="after", objects=(HeapObject("kalloc_32", role="victim"),))
    result = validate_heap_diff(dialect, before, after, allocator_models=models)
    assert result.passed
    assert result.to_dict()["diff"]["added"] == [after.objects[0].to_dict()]


def test_foundry_gate_rejects_unknown_pad_size_class() -> None:
    gate = FoundryDialectGate(load_allocator_models())
    with pytest.raises(DialectDefect):
        gate.validate(_dialect(pre_seed=[{"box": "meta", "pad_to_class": "kalloc_999", "count": 1}]))


def test_size_class_and_heap_object_invariants() -> None:
    models = load_allocator_models()
    for kb in models.libpas().classes_kb:
        assert size_class_for_kb(kb, models) == f"kalloc_{kb}"
    for bad in ("kalloc_0", "kalloc_00", "kalloc_016", "kalloc_", "kalloc_x", " kalloc_16", "kalloc_16 "):
        assert not is_valid_size_class(bad)
        with pytest.raises(ValueError):
            HeapObject(bad)
    for bad_kb in (0, -1, True, 1.5, "20", 5000):
        with pytest.raises(FormatFail):
            size_class_for_kb(bad_kb, models)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HeapObject("kalloc_16", cage=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HeapObject("kalloc_16", role="")


def test_groom_dtos_reject_malformed_values() -> None:
    with pytest.raises(ValueError):
        CrashCase(id="")
    with pytest.raises(ValueError):
        CrashCase(id="crash", payload="not-bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        CrashCase(id="crash", metadata=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        TriageResult(bug_class="", confidence=0.5)
    with pytest.raises(ValueError):
        TriageResult(bug_class="uaf", confidence=1.1)
    with pytest.raises(ValueError):
        TriageResult(bug_class="uaf", confidence=float("nan"))
    with pytest.raises(ValueError):
        TriageResult(bug_class="uaf", artifacts=b"bad")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        GroomCandidate(candidate_id="c", depth=4, score=0.0, dialect={}, size_class="kalloc_16")
    with pytest.raises(ValueError):
        GroomCandidate(candidate_id="c", depth=0, score=0.0, dialect={}, size_class="kalloc_0")
    with pytest.raises(ValueError):
        GroomCandidate(candidate_id="c", depth=0, score=0.0, dialect=[], size_class="kalloc_16")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        GroomPlan(plan_id="", crash_id="crash", candidates=())
    too_many = tuple(
        GroomCandidate(candidate_id=f"groom_{index}", depth=0, score=0.0, dialect={}, size_class="kalloc_16")
        for index in range(65)
    )
    with pytest.raises(ValueError):
        GroomPlan(plan_id="gplan_too_many", crash_id="crash", candidates=too_many)
    with pytest.raises(ValueError):
        AttemptEvidence(rung="not_a_rung", passed=True)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AttemptEvidence(rung=LadderRung.INFO_LEAK, passed=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AttemptEvidence(rung=LadderRung.INFO_LEAK, passed=True, consecutive_passes=-1)
    with pytest.raises(ValueError):
        AttemptEvidence(
            rung=LadderRung.INFO_LEAK,
            passed=True,
            assertion_results={"info_leak.stable": 1},  # type: ignore[dict-item]
        )
    with pytest.raises(ValueError):
        HeapSnapshot(label="", objects=())
    with pytest.raises(ValueError):
        HeapSnapshot(label="bad", objects=(HeapObject("kalloc_16"), "not-a-heap-object"))  # type: ignore[arg-type]


def test_heap_diff_dialect_mutations_raise_dialect_defect() -> None:
    before = HeapSnapshot.from_objects("before", ())
    after = HeapSnapshot.from_objects("after", (HeapObject("kalloc_2048", role="victim"),))
    bad_dialects: list[Any] = [
        {},
        {"validator": "heap_diff.class_stable"},
        _dialect(victim_class="kalloc_999"),
        _dialect(victim_class="kalloc_0"),
        _dialect(pre_seed="not-a-list"),
        _dialect(pre_seed=[42]),
        _dialect(pre_seed=[{"pad_to_class": "kalloc_999"}]),
        _dialect(pre_seed=[{"pad_to_class": 16}]),
        "not-a-mapping",
    ]
    for dialect in bad_dialects:
        with pytest.raises(DialectDefect):
            validate_heap_diff(dialect, before, after)
    with pytest.raises(FormatFail):
        validate_heap_diff(_dialect(), object(), after)  # type: ignore[arg-type]


def test_heap_diff_allocator_model_mutations_fail_closed() -> None:
    before = HeapSnapshot.from_objects("before", ())

    def validate(obj: HeapObject) -> Any:
        after = HeapSnapshot.from_objects("after", (obj,))
        return validate_heap_diff(_dialect(), before, after)

    bad_cage = validate(HeapObject("kalloc_2048", role="victim", cage="not_a_cage"))
    assert not bad_cage.passed
    assert any("Gigacage" in reason for reason in bad_cage.reasons)

    bad_isoheap = validate(HeapObject("kalloc_2048", role="victim", isoheap="bogus"))
    assert not bad_isoheap.passed
    assert any("IsoHeap" in reason for reason in bad_isoheap.reasons)

    bad_structure = validate(HeapObject("kalloc_2048", role="victim", structure_id="bogus"))
    assert not bad_structure.passed
    assert any("StructureID" in reason for reason in bad_structure.reasons)

    known = validate(
        HeapObject(
            "kalloc_2048",
            role="victim",
            cage="primitive",
            isoheap="per_type",
            structure_id="transition",
        )
    )
    assert known.passed


class _FailingAttemptPort:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def attempt(self, *, rung: LadderRung, candidate: GroomCandidate, case: CrashCase) -> Any:
        self.calls.append(candidate.candidate_id)
        return {"not": "AttemptEvidence"}


class _RaisingAdvisor:
    async def advise_rung(self, *, case: CrashCase, triage: TriageResult, rung: LadderRung) -> Any:
        raise RuntimeError("advisor boom")

    async def advise_groom(self, *, case: CrashCase, triage: TriageResult) -> Any:
        raise RuntimeError("advisor boom")


class _ScoringAdvisor:
    async def advise_rung(self, *, case: CrashCase, triage: TriageResult, rung: LadderRung) -> Any:
        return None

    async def advise_groom(self, *, case: CrashCase, triage: TriageResult) -> Any:
        return {
            "size_class": "kalloc_1024",
            "prefer_cage": True,
            "prefer_isoheap": True,
            "prefer_structure_transition": True,
        }


class _BadShapeAdvisor:
    async def advise_rung(self, *, case: CrashCase, triage: TriageResult, rung: LadderRung) -> Any:
        return 123

    async def advise_groom(self, *, case: CrashCase, triage: TriageResult) -> Any:
        return "not-a-mapping"


class _BadTriage:
    async def classify(self, case: CrashCase) -> Any:
        return object()


def _passing_evidence(rung: LadderRung, candidate: GroomCandidate) -> AttemptEvidence:
    assertion = RUNG_ASSERTIONS[rung]
    victim = HeapObject(candidate.size_class, role="victim")
    return AttemptEvidence(
        rung=rung,
        passed=True,
        consecutive_passes=3,
        assertion=assertion,
        assertion_results={assertion: True},
        heap_before=HeapSnapshot(label="before"),
        heap_after=HeapSnapshot(label="after", objects=(victim,)),
        artifact_payload=f"artifact-{rung.value}".encode(),
    )


class _PassingPort:
    async def attempt(self, *, rung: LadderRung, candidate: GroomCandidate, case: CrashCase) -> Any:
        return _passing_evidence(rung, candidate)


class _AcceptGate:
    def validate(self, dialect: Any) -> None:
        return None


class _UnknownAdvisor:
    async def advise_rung(self, *, case: CrashCase, triage: TriageResult, rung: LadderRung) -> Any:
        return "missing_candidate"

    async def advise_groom(self, *, case: CrashCase, triage: TriageResult) -> Any:
        return None


class _SequencePort:
    async def attempt(self, *, rung: LadderRung, candidate: GroomCandidate, case: CrashCase) -> Any:
        assertion = RUNG_ASSERTIONS[rung]
        if rung == LadderRung.INFO_LEAK:
            return AttemptEvidence(
                rung=rung,
                passed=True,
                assertion=assertion,
                assertion_results={assertion: True},
                heap_before=HeapSnapshot(label="before"),
                heap_expectation=HeapDiffExpectation(),
            )
        if rung == LadderRung.OOB_READ:
            victim = HeapObject(candidate.size_class, role="victim")
            return AttemptEvidence(
                rung=rung,
                passed=True,
                assertion=assertion,
                assertion_results={assertion: True},
                heap_before=HeapSnapshot(label="before"),
                heap_after=HeapSnapshot(label="after", objects=(victim,)),
            )
        return AttemptEvidence(rung=rung, passed=False)


class GroomAdversarialAsyncTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ledger = await Ledger.open(Path(self._tmp.name) / "ledger.sqlite")
        await self.ledger.create_run("macos", run_id="run_1")
        self.models = load_allocator_models()

    async def asyncTearDown(self) -> None:
        await self.ledger.close()
        self._tmp.cleanup()

    def case(self, crash_id: str = "crash_adv", **metadata: Any) -> CrashCase:
        return CrashCase(
            id=crash_id,
            target="jsc",
            ring_node="macos_15_0",
            payload=b"crash-bytes",
            bug_class="heap_overflow",
            primitive_hint="oob_read",
            format="heif",
            run_id="run_1",
            metadata=metadata,
        )

    async def test_invalid_inputs_are_rejected_before_ledger_write(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models)
        with self.assertRaises(ValueError):
            await planner.plan(object())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            await planner.plan(self.case(), triage=object())  # type: ignore[arg-type]
        bad_triage_planner = GroomPlanner(self.ledger, models=self.models, triage=_BadTriage())
        with self.assertRaises(ValueError):
            await bad_triage_planner.plan(self.case("crash_bad_triage"))
        ladder = LadderRunner(self.ledger, allocator_models=self.models)
        empty_plan = GroomPlan(plan_id="gplan_empty", crash_id="crash_adv", candidates=())
        with self.assertRaises(ValueError):
            await ladder.run(self.case(), empty_plan, triage=object())  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            await ladder.run(object(), None)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            await ladder.run(self.case(), object())  # type: ignore[arg-type]
        bad_triage_ladder = LadderRunner(self.ledger, triage=_BadTriage(), allocator_models=self.models)
        with self.assertRaises(ValueError):
            await bad_triage_ladder.run(self.case("crash_bad_triage_ladder"), None)
        self.assertEqual(self.ledger.claims_by_type("groom"), [])
        self.assertEqual(self.ledger.claims_by_type("rung"), [])

    async def test_planner_caps_memoization_and_determinism(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models)
        outcomes = []
        for index, size_kb in enumerate([1, 17, 1500, 5000, 0, -1, True, "20", None]):
            outcome = await planner.plan(self.case(f"crash_prop_{index}", size_kb=size_kb))
            outcomes.append(outcome)
            self.assertLessEqual(len(outcome.plan.candidates), 64)
            self.assertTrue(all(candidate.depth <= 3 for candidate in outcome.plan.candidates))
            self.assertLessEqual(outcome.plan.stats["max_depth"], 3)
            self.assertGreater(outcome.plan.stats["memo_hits"], 0)
            self.assertTrue(all(candidate.size_class != "kalloc_999" for candidate in outcome.plan.candidates))
        first = self.case("crash_repeat")
        replay_a = await planner.plan(first)
        replay_b = await planner.plan(first)
        self.assertEqual(replay_a.plan.plan_id, replay_b.plan.plan_id)
        self.assertEqual(replay_a.claim_id, replay_b.claim_id)

    async def test_advisor_failures_fail_closed(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models, advisor=_RaisingAdvisor())
        plan_outcome = await planner.plan(self.case("crash_advisor"))
        self.assertEqual(plan_outcome.status, "planned")
        port = _FailingAttemptPort()
        scripted = LadderRunner(
            self.ledger,
            attempt_port=port,
            advisor=_RaisingAdvisor(),
            allocator_models=self.models,
        )
        scripted_outcome = await scripted.run(
            self.case("crash_advisor"), plan_outcome.plan, triage=plan_outcome.triage
        )
        self.assertEqual(scripted_outcome.status, "exhausted")
        self.assertEqual(scripted_outcome.error_code, "LADDER_EXHAUSTED")
        self.assertTrue(all(result.reason == "invalid_evidence" for result in scripted_outcome.results))
        self.assertEqual(len(port.calls), 3)
        self.assertTrue(set(port.calls) <= {candidate.candidate_id for candidate in plan_outcome.plan.candidates})
        self.assertIsNotNone(scripted_outcome.claim_id)
        claim = self.ledger.get_claim(str(scripted_outcome.claim_id))
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertEqual(claim["state"], "demoted")

    async def test_advisor_shape_and_scoring_fail_closed(self) -> None:
        planner = GroomPlanner(self.ledger, models=self.models, advisor=_ScoringAdvisor())
        outcome = await planner.plan(self.case("crash_scored", size_kb=1))
        self.assertEqual(outcome.status, "planned")
        self.assertTrue(any(candidate.size_class == "kalloc_1024" for candidate in outcome.plan.candidates))
        self.assertTrue(
            any(
                candidate.cage and candidate.isoheap and candidate.structure_id
                for candidate in outcome.plan.candidates
            )
        )
        bad_shape = GroomPlanner(self.ledger, models=self.models, advisor=_BadShapeAdvisor())
        bad_outcome = await bad_shape.plan(self.case("crash_bad_advice"))
        self.assertEqual(bad_outcome.status, "planned")

    async def test_minimal_allocator_models_generate_no_unknown_neighbors(self) -> None:
        minimal = AllocatorModelSet(
            format="heif",
            models=(AllocatorModel(name="libpas_size_classes", provenance="p", classes_kb=(16, 32)),),
        )
        planner = GroomPlanner(self.ledger, models=minimal)
        outcome = await planner.plan(self.case("crash_minimal"))
        self.assertEqual(outcome.status, "planned")
        self.assertTrue(outcome.plan.candidates)
        self.assertTrue(all(candidate.size_class in {"kalloc_16", "kalloc_32"} for candidate in outcome.plan.candidates))
        self.assertTrue(
            all(not candidate.cage and not candidate.isoheap and not candidate.structure_id for candidate in outcome.plan.candidates)
        )

    async def test_ladder_promotion_persists_triage_and_evidence_artifacts(self) -> None:
        candidate = _candidate("groom_pass", size_class="kalloc_2048")
        plan = GroomPlan(plan_id="gplan_pass", crash_id="crash_pass", candidates=(candidate,), stats={"generated": 1})
        triage = TriageResult(
            bug_class="heap_overflow",
            primitive_hint="oob_read",
            confidence=0.9,
            artifacts=(b"triage-artifact",),
        )
        ladder = LadderRunner(self.ledger, attempt_port=_PassingPort(), allocator_models=self.models)
        outcome = await ladder.run(self.case("crash_pass"), plan, triage=triage)
        self.assertEqual(outcome.status, "promoted")
        self.assertEqual(outcome.error_code, None)
        self.assertTrue(all(result.promoted for result in outcome.results))
        self.assertIsNotNone(outcome.claim_id)
        assert outcome.claim_id is not None
        self.assertGreater(self.ledger.claim_artifact_count(outcome.claim_id), 3)

    async def test_ladder_evidence_and_heap_diff_failure_injection(self) -> None:
        candidate = GroomCandidate(
            candidate_id="groom_bad_heap_dialect",
            depth=0,
            score=0.0,
            dialect=_dialect(victim_class="kalloc_999"),
            size_class="kalloc_2048",
        )
        plan = GroomPlan(
            plan_id="gplan_bad_heap_dialect",
            crash_id="crash_bad_heap_dialect",
            candidates=(candidate,),
            stats={"generated": 1},
        )
        ladder = LadderRunner(
            self.ledger,
            attempt_port=_SequencePort(),
            gate=_AcceptGate(),
            advisor=_UnknownAdvisor(),
            allocator_models=self.models,
        )
        outcome = await ladder.run(self.case("crash_bad_heap_dialect"), plan)
        self.assertEqual(outcome.status, "exhausted")
        self.assertEqual(outcome.error_code, "LADDER_EXHAUSTED")
        reasons = {result.rung: result.reason for result in outcome.results}
        self.assertEqual(reasons[LadderRung.INFO_LEAK], "heap_evidence_missing")
        self.assertEqual(reasons[LadderRung.OOB_READ], "heap_diff_error:DialectDefect")
        self.assertEqual(reasons[LadderRung.REL_RW], "attempt_failed")

    async def test_ledgerio_duplicate_race_and_terminal_edges(self) -> None:
        class _DupLedger:
            def __init__(self, replay: dict[str, str] | None) -> None:
                self._replay = replay
                self.calls = 0

            def claim_by_dedup(self, dedup: str) -> dict[str, str] | None:
                self.calls += 1
                return None if self.calls == 1 else self._replay

            async def create_claim(self, claim: Any) -> str:
                raise DuplicateDedup("duplicate dedup")

        replay_id = await create_claim_once(
            _DupLedger({"id": "claim_replay"}),  # type: ignore[arg-type]
            claim_id="claim_dup",
            claim_type="groom",
            value={"ok": True},
            confidence=0.5,
            dedup="dup-key",
            artifacts=(("artifact", b"bytes"),),
        )
        self.assertEqual(replay_id, "claim_replay")
        with self.assertRaises(DuplicateDedup):
            await create_claim_once(
                _DupLedger(None),  # type: ignore[arg-type]
                claim_id="claim_dup_missing",
                claim_type="groom",
                value={"ok": True},
                confidence=0.5,
                dedup="dup-key-missing",
                artifacts=(),
            )

        class _StateLedger:
            def __init__(self, row: dict[str, str] | None) -> None:
                self._row = row

            def get_claim(self, claim_id: str) -> dict[str, str] | None:
                return self._row

            async def transition_claim(self, claim_id: str, to_state: ClaimState) -> None:
                return None

        await transition_if_needed(_StateLedger(None), "missing", ClaimState.LIMBO, ClaimState.BOUND)  # type: ignore[arg-type]
        await transition_if_needed(_StateLedger({"state": "bound"}), "bound", ClaimState.LIMBO, ClaimState.BOUND)  # type: ignore[arg-type]
        self.assertEqual(await finalize_claim(_StateLedger(None), "missing", promoted=True), "missing")  # type: ignore[arg-type]
        self.assertEqual(await finalize_claim(_StateLedger({"state": "bound"}), "bound", promoted=True), "bound")  # type: ignore[arg-type]

    async def test_foundry_defect_round_trip(self) -> None:
        models = self.models
        gate = FoundryDialectGate(models)
        good = _candidate("groom_good")
        gate.validate(good.dialect)
        bad = _candidate(
            "groom_bad_class",
            size_class="kalloc_999",
        )
        with self.assertRaises(DialectDefect):
            gate.validate(bad.dialect)
        sink = LedgerFoundryDefectSink(self.ledger)
        await sink.report_dialect_defect(candidate=bad, case=self.case("crash_defect"), error="unknown size class")
        rows = self.ledger.work_orders_for_unit("groom:groom_bad_class")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action"], "widen_dialect")
        self.assertEqual(rows[0]["state"], "dialect_defect")
        self.assertIn("groom_bad_class", str(rows[0]["payload_json"]))
        self.assertIn("unknown size class", str(rows[0]["payload_json"]))


if __name__ == "__main__":
    unittest.main()
