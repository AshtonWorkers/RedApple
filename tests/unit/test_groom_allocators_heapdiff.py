"""RA-GRM allocator model and heap-diff validator tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from ra.errors import DialectDefect, FormatFail
from ra.groom import (
    HeapDiffExpectation,
    HeapObject,
    HeapSnapshot,
    adjacent_size_classes,
    diff_heap_states,
    is_valid_size_class,
    load_allocator_models,
    size_class_for_kb,
    validate_heap_diff,
)


def test_RA_GRM_001_allocator_models_have_provenance() -> None:
    models = load_allocator_models()
    assert models.format == "heif"
    names = {model.name for model in models.models}
    assert {"libpas_size_classes", "gigacage", "isoheap", "structure_id"} <= names
    libpas = models.libpas()
    assert libpas.classes_kb == (16, 32, 64, 128, 256, 512, 1024, 2048, 4096)
    assert libpas.provenance.startswith("https://github.com/apple-oss-distributions/libpas")
    assert "kalloc_1024" in libpas.size_classes()
    assert models.is_known_size_class("kalloc_2048")
    assert not models.is_known_size_class("kalloc_999")
    assert size_class_for_kb(1, models) == "kalloc_16"
    assert size_class_for_kb(17, models) == "kalloc_32"
    assert size_class_for_kb(5000, models) == "kalloc_4096"
    assert adjacent_size_classes("kalloc_1024", models) == ("kalloc_512", "kalloc_2048")
    assert adjacent_size_classes("kalloc_16", models) == ("kalloc_16", "kalloc_32")
    assert adjacent_size_classes("kalloc_4096", models) == ("kalloc_2048", "kalloc_4096")


def test_RA_GRM_001_rejects_invalid_model_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "models.json"
        path.write_text(json.dumps({"format": "other", "models": {}}), encoding="utf-8")
        with pytest.raises(FormatFail):
            load_allocator_models(path)
        path.write_text(json.dumps({"format": "heif", "models": {"x": {}}}), encoding="utf-8")
        with pytest.raises(FormatFail):
            load_allocator_models(path)
        path.write_text(
            json.dumps(
                {
                    "format": "heif",
                    "models": {
                        "libpas_size_classes": {
                            "provenance": "https://example.com",
                            "classes_kb": [0],
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(FormatFail):
            load_allocator_models(path)
        path.write_text("not json", encoding="utf-8")
        with pytest.raises(FormatFail):
            load_allocator_models(path)


def test_heap_object_and_snapshot_helpers() -> None:
    with pytest.raises(ValueError):
        HeapObject(size_class="bad")
    assert is_valid_size_class("kalloc_128")
    assert not is_valid_size_class("kalloc_x")
    before = HeapSnapshot.from_objects(
        "before",
        (
            HeapObject("kalloc_2048", role="victim"),
            HeapObject("kalloc_1024", role="seed", cage="primitive"),
        ),
    )
    after = HeapSnapshot.from_objects(
        "after",
        (
            HeapObject("kalloc_2048", role="victim", state="freed"),
            HeapObject("kalloc_1024", role="seed", cage="primitive"),
        ),
    )
    assert before.digest() != after.digest()
    assert before.to_dict()["objects"][0]["size_class"] == "kalloc_1024"
    diff = diff_heap_states(before, after)
    assert [obj.role for obj in diff.removed] == ["victim"]
    assert [obj.state for obj in diff.added] == ["freed"]
    assert not diff.is_empty


def test_RA_GRM_002_heap_diff_class_stable_pass_and_expectation() -> None:
    dialect = {
        "format": "heif",
        "pre_seed": [{"box": "meta", "pad_to_class": "kalloc_1024", "count": 2}],
        "victim_pad": "align_to_class",
        "victim_class": "kalloc_2048",
        "post": {"free": "ipco_before_victim"},
        "validator": "heap_diff.class_stable",
    }
    before = HeapSnapshot.from_objects("before", (HeapObject("kalloc_1024", role="seed"),))
    victim = HeapObject("kalloc_2048", role="victim")
    after = HeapSnapshot.from_objects("after", (*before.objects, victim))
    expectation = HeapDiffExpectation(added=(victim,))
    result = validate_heap_diff(dialect, before, after, expectation=expectation)
    assert result.passed
    assert result.validator == "heap_diff.class_stable"
    assert result.diff is not None and result.diff.added == (victim,)


def test_RA_GRM_002_heap_diff_rejects_escape_empty_and_bad_validator() -> None:
    dialect = {
        "victim_class": "kalloc_2048",
        "pre_seed": [{"pad_to_class": "kalloc_1024"}],
        "validator": "heap_diff.class_stable",
    }
    before = HeapSnapshot.from_objects("before", ())
    escaped = HeapObject("kalloc_512", role="escape")
    after = HeapSnapshot.from_objects("after", (escaped,))
    failed = validate_heap_diff(dialect, before, after)
    assert not failed.passed
    assert failed.reasons
    empty = validate_heap_diff(dialect, before, before)
    assert not empty.passed
    assert "heap state did not change" in empty.reasons[0]
    with pytest.raises(DialectDefect):
        validate_heap_diff({"validator": "heap_diff.other"}, before, after)
    with pytest.raises(FormatFail):
        validate_heap_diff({"validator": "heap_diff.class_stable"}, before, after)
    mismatched = HeapDiffExpectation(removed=(escaped,))
    result = validate_heap_diff(dialect, before, after, expectation=mismatched)
    assert not result.passed
    assert any("expected before/after delta" in reason for reason in result.reasons)
