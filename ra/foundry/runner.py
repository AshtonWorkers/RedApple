"""Compile harnesses and measure libFuzzer dry runs for RA-FND."""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .acceptance import coverage_edge_counts
from .errors import FoundryError
from .models import AcceptanceMeasurements, HarnessSpec


@dataclass(frozen=True)
class CompileResult:
    """Outcome of one harness compile."""

    ok: bool
    returncode: int
    output: str
    binary_path: Path


@dataclass(frozen=True)
class DryRunResult:
    """Outcome of one libFuzzer dry run."""

    completed: bool
    returncode: int
    seconds: float
    covered_edges: int
    total_edges: int
    baseline_covered_edges: int
    new_covered_edges: int
    edges_per_sec: float
    output: str


def _run_process(
    command: list[str], *, timeout_seconds: float, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise FoundryError(f"command timed out after {timeout_seconds}s: {command[0]}") from exc
    except OSError as exc:
        raise FoundryError(f"failed to execute {command[0]}: {exc}") from exc


def resolve_clangxx(clangxx: str | None = None, manifest: dict[str, Any] | None = None) -> str:
    """Resolve the C++ compiler for harness builds."""
    if clangxx:
        return clangxx
    if manifest is not None:
        value = manifest.get("clangxx")
        if isinstance(value, str) and value:
            return value
    for env_name in ("REDAPPLE_CLANGXX", "CXX"):
        value = os.environ.get(env_name)
        if value:
            return value
    return "clang++"


def compile_harness(
    spec: HarnessSpec,
    workdir: Path,
    *,
    clangxx: str | None = None,
    extra_args: tuple[str, ...] = (),
    timeout_seconds: float = 600.0,
) -> CompileResult:
    """Compile ``spec.source`` as a libFuzzer harness."""
    source_path = spec.source_path
    if not source_path.exists():
        raise FoundryError(f"harness source does not exist: {source_path}")
    workdir.mkdir(parents=True, exist_ok=True)
    compiler = resolve_clangxx(clangxx)
    output_path = workdir / f"{spec.id}_fuzzer"
    command = [
        compiler,
        "-std=c++17",
        "-O1",
        "-g",
        "-fsanitize=fuzzer,address,undefined",
        "-fno-omit-frame-pointer",
        *extra_args,
        str(source_path),
        "-o",
        str(output_path),
    ]
    completed = _run_process(command, timeout_seconds=timeout_seconds, cwd=workdir)
    output = completed.stdout + completed.stderr
    return CompileResult(
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        output=output,
        binary_path=output_path,
    )


def run_dry_run(
    binary: Path,
    corpus_dir: Path,
    seconds: float,
    *,
    timeout_seconds: float | None = None,
    baseline_covered_edges: int = 0,
) -> DryRunResult:
    """Run libFuzzer and compute new covered edges per second."""
    if seconds <= 0:
        raise FoundryError("dry_run_seconds must be positive")
    corpus_dir.mkdir(parents=True, exist_ok=True)
    timeout = timeout_seconds if timeout_seconds is not None else seconds + 120.0
    command = [
        str(binary),
        f"-max_total_time={seconds}",
        "-print_coverage=1",
        "-print_final_stats=1",
        str(corpus_dir),
    ]
    start = time.monotonic()
    try:
        completed = _run_process(command, timeout_seconds=timeout, cwd=corpus_dir.parent)
    except FoundryError as exc:
        elapsed = time.monotonic() - start
        return DryRunResult(
            completed=False,
            returncode=-1,
            seconds=elapsed,
            covered_edges=0,
            total_edges=0,
            baseline_covered_edges=baseline_covered_edges,
            new_covered_edges=0,
            edges_per_sec=0.0,
            output=str(exc),
        )
    elapsed = time.monotonic() - start
    output = completed.stdout + completed.stderr
    covered_edges, total_edges = coverage_edge_counts(output)
    new_covered_edges = max(0, covered_edges - baseline_covered_edges)
    edges_per_sec = new_covered_edges / elapsed if elapsed > 0 else 0.0
    return DryRunResult(
        completed=completed.returncode == 0,
        returncode=completed.returncode,
        seconds=elapsed,
        covered_edges=covered_edges,
        total_edges=total_edges,
        baseline_covered_edges=baseline_covered_edges,
        new_covered_edges=new_covered_edges,
        edges_per_sec=edges_per_sec,
        output=output,
    )


def run_seed_coverage(binary: Path, corpus_dir: Path, *, timeout_seconds: float = 120.0) -> int:
    """Return covered edge count for a ``-runs=0`` seed-only coverage probe."""
    corpus_dir.mkdir(parents=True, exist_ok=True)
    completed = _run_process(
        [str(binary), "-runs=0", "-print_coverage=1", str(corpus_dir)],
        timeout_seconds=timeout_seconds,
        cwd=corpus_dir.parent,
    )
    if completed.returncode != 0:
        raise FoundryError(
            "seed coverage probe failed: " + (completed.stdout + completed.stderr)[-2000:]
        )
    covered_edges, _ = coverage_edge_counts(completed.stdout + completed.stderr)
    return covered_edges


def load_manifest(path: Path) -> dict[str, Any]:
    """Load a harness manifest JSON object."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FoundryError(f"invalid harness manifest JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise FoundryError(f"manifest must be a JSON object: {path}")
    return payload


def _manifest_float(manifest: dict[str, Any], key: str, default: float) -> float:
    value = manifest.get(key, default)
    if isinstance(value, bool):
        raise FoundryError(f"manifest field {key!r} must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise FoundryError(f"manifest field {key!r} must be a number") from exc


def _manifest_str_list(manifest: dict[str, Any], key: str) -> tuple[str, ...]:
    value = manifest.get(key, [])
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise FoundryError(f"manifest field {key!r} must be a list of strings")
    return tuple(value)


def harness_spec_from_manifest(manifest_path: Path) -> HarnessSpec:
    """Build a :class:`HarnessSpec` from ``harness.json``."""
    manifest = load_manifest(manifest_path)
    harness_id = manifest.get("id") or manifest.get("harness_id")
    if harness_id is None:
        raise FoundryError(f"harness manifest missing id: {manifest_path}")
    try:
        return HarnessSpec(
            id=str(harness_id),
            format=str(manifest["format"]),
            directory=manifest_path.parent,
            source=str(manifest["source"]),
            dialect=str(manifest["dialect"]),
            manifest=manifest_path.name,
        )
    except (KeyError, ValueError) as exc:
        raise FoundryError(f"invalid harness manifest {manifest_path}: {exc}") from exc


def measure_harness(
    spec: HarnessSpec,
    manifest: dict[str, Any],
    workdir: Path,
    corpus_dir: Path,
    surface_median_edges_per_sec: float | None = None,
    *,
    clangxx: str | None = None,
    dry_run_seconds: float | None = None,
    run_baseline: bool = True,
) -> AcceptanceMeasurements:
    """Compile ``spec`` and run a dry run, returning RA-FND-001 measurements."""
    compiler = resolve_clangxx(clangxx, manifest)
    compile_args = _manifest_str_list(manifest, "compile_args")
    build_dir = workdir / "build"
    compile_start = time.monotonic()
    compile_result = compile_harness(
        spec,
        build_dir,
        clangxx=compiler,
        extra_args=compile_args,
    )
    compile_seconds = time.monotonic() - compile_start
    if not compile_result.ok:
        return AcceptanceMeasurements(
            compiled=False,
            edges_per_sec=0.0,
            surface_median_edges_per_sec=(
                surface_median_edges_per_sec
                if surface_median_edges_per_sec is not None
                else _manifest_float(manifest, "surface_median_edges_per_sec", 0.0)
            ),
            coverage_map=compile_result.output,
            parser_malloc_symbol=str(manifest.get("parser_malloc_symbol", "parser_malloc")),
            compile_seconds=compile_seconds,
            dry_run_seconds=0.0,
            dry_run_completed=False,
            throughput_metric="coverage_edges_per_sec",
        )

    seconds = (
        dry_run_seconds
        if dry_run_seconds is not None
        else _manifest_float(manifest, "dry_run_seconds", 600.0)
    )
    baseline_edges = 0
    baseline_enabled = run_baseline and bool(manifest.get("baseline_coverage", True))
    if baseline_enabled:
        baseline_edges = run_seed_coverage(compile_result.binary_path, corpus_dir)
    dry_run = run_dry_run(
        compile_result.binary_path,
        corpus_dir,
        seconds,
        baseline_covered_edges=baseline_edges,
    )
    median = (
        surface_median_edges_per_sec
        if surface_median_edges_per_sec is not None
        else _manifest_float(manifest, "surface_median_edges_per_sec", 0.0)
    )
    return AcceptanceMeasurements(
        compiled=True,
        edges_per_sec=dry_run.edges_per_sec,
        surface_median_edges_per_sec=median,
        coverage_map=dry_run.output,
        parser_malloc_symbol=str(manifest.get("parser_malloc_symbol", "parser_malloc")),
        dry_run_seconds=dry_run.seconds,
        compile_seconds=compile_seconds,
        dry_run_completed=dry_run.completed,
        covered_edges=dry_run.covered_edges,
        total_edges=dry_run.total_edges,
        baseline_covered_edges=dry_run.baseline_covered_edges,
        new_covered_edges=dry_run.new_covered_edges,
        throughput_metric="coverage_edges_per_sec",
    )
