"""Compile harnesses and collect mechanical dry-run measurements.

This is the thin I/O edge of RA-FND-001: it runs the compiler and libFuzzer,
then hands pure measurements to the acceptance gate.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .errors import FoundryError
from .models import AcceptanceMeasurements, HarnessSpec

_EXEC_PER_SEC_RE = re.compile(r"stat::average_exec_per_sec:\s*([0-9]+(?:\.[0-9]+)?)")


@dataclass(frozen=True)
class CompileResult:
    """Outcome of one harness compile."""

    compiled: bool
    seconds: float
    command: Tuple[str, ...]
    output: str


@dataclass(frozen=True)
class DryRunResult:
    """Outcome of one libFuzzer dry run."""

    completed: bool
    returncode: int
    seconds: float
    edges_per_sec: float
    output: str


def load_manifest(path: Path) -> Dict[str, Any]:
    """Load a harness manifest JSON object."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise FoundryError(f"{path}: harness manifest must be a JSON object")
    return data


def harness_spec_from_manifest(directory: Path) -> HarnessSpec:
    """Build a :class:`HarnessSpec` from ``harness.json`` in ``directory``."""
    manifest_path = directory / "harness.json"
    manifest = load_manifest(manifest_path)
    for key in ("id", "format", "source", "dialect"):
        if key not in manifest:
            raise FoundryError(f"{manifest_path}: missing required key {key!r}")
    return HarnessSpec(
        id=str(manifest["id"]),
        format=str(manifest["format"]),
        directory=directory,
        source=str(manifest["source"]),
        dialect=str(manifest["dialect"]),
        manifest=manifest_path.name,
    )


def resolve_clangxx(manifest: Dict[str, Any], override: Optional[str] = None) -> str:
    """Resolve the C++ compiler, preferring explicit runner overrides."""
    return (
        override
        or os.environ.get("RA_FOUNDRY_CLANGXX")
        or str(manifest.get("clangxx") or "clang++")
    )


def compile_harness(
    spec: HarnessSpec,
    manifest: Dict[str, Any],
    workdir: Path,
    clangxx: Optional[str] = None,
    timeout_seconds: float = 300.0,
) -> CompileResult:
    """Compile one harness source into ``workdir``."""
    spec_directory = spec.directory.resolve()
    workdir = Path(workdir).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    output_name = str(manifest.get("output") or f"{spec.id}_fuzzer")
    output_path = workdir / output_name
    source_path = (spec_directory / spec.source).resolve()
    compile_args = [str(arg) for arg in manifest.get("compile_args", [])]
    command = (
        resolve_clangxx(manifest, clangxx),
        *compile_args,
        str(source_path),
        "-o",
        str(output_path),
    )

    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(spec_directory),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CompileResult(
            compiled=False,
            seconds=time.monotonic() - started,
            command=command,
            output=str(exc),
        )

    return CompileResult(
        compiled=completed.returncode == 0 and output_path.exists(),
        seconds=time.monotonic() - started,
        command=command,
        output=completed.stdout,
    )


def parse_average_exec_per_sec(output: str) -> float:
    """Parse libFuzzer's ``stat::average_exec_per_sec`` value."""
    match = _EXEC_PER_SEC_RE.search(output)
    if match is None:
        return 0.0
    return float(match.group(1))


def run_dry_run(
    binary: Path,
    corpus_dir: Path,
    seconds: float,
    timeout_seconds: Optional[float] = None,
) -> DryRunResult:
    """Run libFuzzer for ``seconds`` and capture the coverage map output."""
    command = [
        str(binary),
        f"-max_total_time={seconds}",
        "-print_coverage=1",
        "-print_final_stats=1",
        str(corpus_dir),
    ]
    timeout = timeout_seconds if timeout_seconds is not None else seconds + 120.0
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout
        returncode = completed.returncode
        completed_ok = returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        output = str(exc)
        returncode = -1
        completed_ok = False

    elapsed = time.monotonic() - started
    return DryRunResult(
        completed=completed_ok,
        returncode=returncode,
        seconds=elapsed,
        edges_per_sec=parse_average_exec_per_sec(output),
        output=output,
    )


def measure_harness(
    spec: HarnessSpec,
    manifest: Dict[str, Any],
    workdir: Path,
    corpus_dir: Path,
    surface_median_edges_per_sec: float,
    clangxx: Optional[str] = None,
    dry_run_seconds: Optional[float] = None,
) -> AcceptanceMeasurements:
    """Compile and dry-run a harness, returning RA-FND-001 measurements."""
    workdir = Path(workdir).resolve()
    corpus_dir = Path(corpus_dir).resolve()
    seconds = float(
        dry_run_seconds
        if dry_run_seconds is not None
        else manifest.get("dry_run_seconds", 600.0)
    )
    compile_result = compile_harness(spec, manifest, workdir, clangxx=clangxx)
    parser_malloc_symbol = str(manifest.get("parser_malloc_symbol") or "parser_malloc")
    if not compile_result.compiled:
        return AcceptanceMeasurements(
            compiled=False,
            edges_per_sec=0.0,
            surface_median_edges_per_sec=surface_median_edges_per_sec,
            coverage_map="",
            parser_malloc_symbol=parser_malloc_symbol,
            dry_run_seconds=0.0,
            compile_seconds=compile_result.seconds,
            dry_run_completed=False,
        )

    binary = workdir / str(manifest.get("output") or f"{spec.id}_fuzzer")
    dry_run = run_dry_run(binary, corpus_dir, seconds)
    return AcceptanceMeasurements(
        compiled=True,
        edges_per_sec=dry_run.edges_per_sec,
        surface_median_edges_per_sec=surface_median_edges_per_sec,
        coverage_map=dry_run.output,
        parser_malloc_symbol=parser_malloc_symbol,
        dry_run_seconds=seconds,
        compile_seconds=compile_result.seconds,
        dry_run_completed=dry_run.completed,
    )
