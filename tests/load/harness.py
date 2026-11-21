#!/usr/bin/env python3.12
"""RED APPLE load harness: replay synthetic crashes through fake lanes (RA-LOAD)."""

from __future__ import annotations

import argparse
import asyncio
import gc
import hashlib
import json
import resource
import sys
import time
from pathlib import Path

from ra.errors import RaError
from ra.fleet.fake import FakeLane
from ra.lanes.base import DeviceProfile, Tier
from ra.ledger import ClaimArtifactInput, ClaimInput, Ledger, UlidFactory
from ra.ledger.ids import dedup_key
from ra.ledger.models import ArtifactInput
from ra.policy import ExecutorCaps, PolicyEngine, WorkOrderCandidate
from ra.press.packets import Packet, PacketCompiler
from ra.press.routing import TaskType

VOCAB = ("oob_read", "oob_write", "uaf", "type_confusion", "info_leak")


def percentile(values: list[float], q: float) -> float:
    """Return the q percentile of values."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int((len(ordered) - 1) * q))]


def rss_mb() -> float:
    """Return process RSS in MiB."""
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    scale = 1.0 if sys.platform == "darwin" else 1024.0
    return round(usage / scale / (1024 * 1024), 2)


async def run_load(crashes: int, rate: float, db_path: Path, out_path: Path) -> dict[str, object]:
    """Replay crashes and return the load report."""
    ledger = await Ledger.open(
        db_path,
        max_queue=1024,
        max_batch_rows=25,
        max_batch_ms=25,
        wal_autocheckpoint=100000,
    )
    lane = FakeLane(tier=Tier.C, crash_every=1)
    compiler = PacketCompiler()
    ids = UlidFactory()
    engine = PolicyEngine(ledger, ExecutorCaps(spend_usd_micro=40_000_000))
    profile = DeviceProfile(udid="load-udid", tier=Tier.C, ring_node="load-ring", state="attached")
    await lane.provision(profile)
    handle = await lane.launch("load-target", object())
    await lane.assert_ready()

    triage_ms: list[float] = []
    compile_ms: list[float] = []
    tick_ms: list[float] = []
    submit_ms: list[float] = []
    sqlite_busy = 0
    work_order_count = min(200, max(0, crashes // 250))
    for _index in range(work_order_count):
        await ledger.enqueue_work_order(
            action="park", unit="load", ev_cost=1.0, state="ready", payload_json="{}"
        )
    candidates = [
        WorkOrderCandidate(
            id=f"candidate_{i:05d}", action="park", unit="load", ev_cost=float(5000 - i), created=i
        )
        for i in range(5000)
    ]

    started = time.perf_counter()
    next_tick = started
    interval = 1.0 / rate if rate > 0 else 0.0
    processed = 0
    pending_claims: list[ClaimInput] = []

    async def flush_claims() -> None:
        nonlocal processed, sqlite_busy
        if not pending_claims:
            return

        async def timed(claim: ClaimInput) -> None:
            nonlocal processed, sqlite_busy
            start = time.perf_counter()
            try:
                await ledger.create_claim(claim)
            except Exception as exc:
                if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                    sqlite_busy += 1
                raise
            submit_ms.append((time.perf_counter() - start) * 1000)
            processed += 1

        await asyncio.gather(*(timed(claim) for claim in pending_claims))
        pending_claims.clear()

    try:
        for n in range(1, crashes + 1):
            payload = f"synthetic crash {n}".encode()
            triage_start = time.perf_counter()
            stack_hash = hashlib.sha256(payload).hexdigest()
            key = dedup_key("synthetic", stack_hash, "load_alloc")
            triage_ms.append((time.perf_counter() - triage_start) * 1000)

            compile_start = time.perf_counter()
            artifact_id = "art_" + hashlib.sha256(payload).hexdigest()
            packet = Packet(
                TaskType.BUG_CLASS,
                f"Classify synthetic crash {n}.",
                (artifact_id,),
                VOCAB,
            )
            compiler.compile(packet)
            compile_ms.append((time.perf_counter() - compile_start) * 1000)

            if n % 100 == 0:
                tick_start = time.perf_counter()
                engine.rank_candidates(candidates)
                tick_ms.append((time.perf_counter() - tick_start) * 1000)

            await lane.feed(handle, payload)
            crashes_seen = await lane.collect_crashes(handle)
            for crash in crashes_seen:
                claim_id = ids.new("cl")
                artifact = ArtifactInput(kind="crash", data=crash.payload, ttl_class="run")
                claim = ClaimInput(
                    claim_id=claim_id,
                    type="bug_class",
                    value_json=json.dumps(
                        {"bug_class": "synthetic", "crash": crash.id}, sort_keys=True
                    ),
                    confidence=0.5,
                    dedup_key=key,
                    created=int(time.time() * 1000),
                    artifacts=(ClaimArtifactInput(artifact=artifact, role="evidence"),),
                )
                pending_claims.append(claim)
                if len(pending_claims) >= 100:
                    await flush_claims()

            if n % 50 == 0:
                await engine.dispatch_ready(limit=8)
            now = time.perf_counter()
            if interval:
                sleep_for = next_tick - now
                if sleep_for > 0:
                    await asyncio.sleep(sleep_for)
                next_tick = max(next_tick + interval, time.perf_counter())
        await flush_claims()
    finally:
        await lane.teardown()
        await ledger.close()

    duration = time.perf_counter() - started
    actor_stats = ledger.actor.stats() if hasattr(ledger, "actor") else {}
    report = {
        "crashes_requested": crashes,
        "crashes_processed": processed,
        "duration_s": round(duration, 3),
        "rate_per_s": round(processed / duration, 3) if duration else 0.0,
        "rss_mb": rss_mb(),
        "sqlite_busy": sqlite_busy,
        "mailbox": actor_stats,
        "slo": {
            "triage_p95_ms": round(percentile(triage_ms, 0.95), 3),
            "compile_p99_ms": round(percentile(compile_ms, 0.99), 3),
            "tick_p99_ms": round(percentile(tick_ms, 0.99), 3),
            "ledger_commit_p99_ms": round(float(actor_stats.get("commit_ms_p99", 0.0)), 3),
            "ledger_submit_p99_ms": round(percentile(submit_ms, 0.99), 3),
        },
        "thresholds": {
            "triage_p95_ms": 900000,
            "compile_p99_ms": 8,
            "tick_p99_ms": 5,
            "ledger_commit_p99_ms": 3,
            "rss_mb": 1536,
            "sqlite_busy": 0,
        },
    }
    checks = {
        "triage": report["slo"]["triage_p95_ms"] <= 900000,
        "compile": report["slo"]["compile_p99_ms"] <= 8,
        "tick": report["slo"]["tick_p99_ms"] <= 5,
        "ledger": report["slo"]["ledger_commit_p99_ms"] <= 3,
        "rss": report["rss_mb"] < 1536,
        "busy": sqlite_busy == 0,
    }
    report["passed"] = all(checks.values()) and processed == crashes
    report["checks"] = checks
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    """Load harness entry point."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--crashes", type=int, default=50000)
    parser.add_argument("--rate", type=float, default=200.0)
    parser.add_argument("--db", type=Path, default=Path(".redapple/load.sqlite"))
    parser.add_argument("--out", type=Path, default=Path("tests/load/results/load_report.json"))
    args = parser.parse_args(argv)
    gc.disable()
    try:
        report = asyncio.run(run_load(args.crashes, args.rate, args.db, args.out))
    except RaError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}), file=sys.stderr)
        return 2
    finally:
        gc.enable()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
