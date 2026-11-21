"""Shared helpers for foundry unit tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ra.foundry import AcceptanceMeasurements, HarnessSpec

VALID_DIALECT: dict[str, Any] = {
    "format": "heif",
    "pre_seed": [{"box": "meta", "pad_to_class": "kalloc_1024"}, {"box": "iprp", "count": 8}],
    "victim_pad": "align_to_class",
    "victim_class": "kalloc_2048",
    "post": {"free": "ipco_before_victim"},
    "validator": "heap_diff.class_stable",
}

GOOD_COVERAGE = (
    "COVERAGE:\n"
    "COVERED_FUNC: hits: 10 edges: 3/4 parser_malloc(unsigned long) harness.cc:10\n"
    "UNCOVERED_FUNC: hits: 0 edges: 0/2 parser_free harness.cc:20\n"
)
BAD_COVERAGE = (
    "COVERAGE:\n"
    "COVERED_FUNC: hits: 10 edges: 2/2 LLVMFuzzerTestOneInput harness.cc:20\n"
)


def measurements(**overrides: Any) -> AcceptanceMeasurements:
    values: dict[str, Any] = {
        "compiled": True,
        "edges_per_sec": 1000.0,
        "surface_median_edges_per_sec": 1000.0,
        "coverage_map": GOOD_COVERAGE,
        "dry_run_seconds": 600.0,
        "covered_edges": 600,
        "total_edges": 1000,
        "baseline_covered_edges": 0,
        "new_covered_edges": 600,
        "throughput_metric": "coverage_edges_per_sec",
    }
    values.update(overrides)
    return AcceptanceMeasurements(**values)


def write_harness(
    root: Path,
    *,
    harness_id: str = "test_heif",
    fmt: str = "heif",
    dialect: Any | None = None,
    manifest: dict[str, Any] | None = None,
    source: str = "harness.cc",
    source_text: str = "int LLVMFuzzerTestOneInput() { return 0; }\n",
) -> HarnessSpec:
    directory = root / harness_id
    directory.mkdir(parents=True, exist_ok=True)
    (directory / source).write_text(source_text, encoding="utf-8")
    dialect_name = "heif.dialect.json"
    (directory / dialect_name).write_text(
        json.dumps(VALID_DIALECT if dialect is None else dialect),
        encoding="utf-8",
    )
    manifest_name: str | None = None
    if manifest is not None:
        manifest_name = "harness.json"
        (directory / manifest_name).write_text(json.dumps(manifest), encoding="utf-8")
    return HarnessSpec(
        id=harness_id,
        format=fmt,
        directory=directory,
        source=source,
        dialect=dialect_name,
        manifest=manifest_name,
    )
