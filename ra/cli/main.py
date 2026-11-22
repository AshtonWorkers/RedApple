"""`ra` CLI with exactly run, attach, replay, golden, doctor, retain."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import re
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..config import load_config, validate_budget_usd
from ..errors import FormatFail, RaError
from ..ledger import Ledger
from ..obs.health import health_payload
from ..obs.retention import RetentionPolicy, sweep
from ..press.golden import GoldenCase, check_golden, load_golden
from ..press.routing import route_for

COMMANDS = ("run", "attach", "replay", "golden", "doctor", "retain")
DEFAULT_DB = Path(".redapple/ledger.sqlite")
DEFAULT_QUEUE = Path(".redapple/press-queue.jsonl")
_UNTIL_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(prog="ra", description="RED APPLE M0 core")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="arm and drain a hardware-free run")
    run.add_argument("--mode", choices=("macos", "ios"), required=True)
    run.add_argument("--budget-usd", type=int, default=None)
    run.add_argument("--until", default=None)
    run.add_argument("--config", default=None)
    run.add_argument("--db", type=Path, default=DEFAULT_DB)

    attach = sub.add_parser("attach", help="record a device attachment")
    attach.add_argument("--udid", required=True)
    attach.add_argument("--tier", choices=("A", "B", "C"), required=True)
    attach.add_argument("--build", default=None)
    attach.add_argument("--ring-node", default=None)
    attach.add_argument("--config", default=None)
    attach.add_argument("--db", type=Path, default=DEFAULT_DB)

    replay = sub.add_parser("replay", help="validate offline PRESS packet queue")
    replay.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    replay.add_argument("--type", default=None)
    replay.add_argument("--check", action="store_true")
    replay.add_argument("--clear", action="store_true")
    replay.add_argument("--config", default=None)

    golden = sub.add_parser("golden", help="run the golden-set gate")
    golden.add_argument("--type", required=True)
    golden.add_argument("--file", type=Path, default=None)
    golden.add_argument("--baseline", type=Path, default=None)
    golden.add_argument("--check", action="store_true")
    golden.add_argument("--config", default=None)

    doctor = sub.add_parser("doctor", help="report station and layout health")
    doctor.add_argument("--layout", action="store_true")
    doctor.add_argument("--config", default=None)
    doctor.add_argument("--db", type=Path, default=DEFAULT_DB)

    retain = sub.add_parser("retain", help="run one retention sweep")
    retain.add_argument("--sweep", action="store_true")
    retain.add_argument("--batch-size", type=int, default=500)
    retain.add_argument("--min-set", type=int, default=0)
    retain.add_argument("--config", default=None)
    retain.add_argument("--db", type=Path, default=DEFAULT_DB)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_dispatch(args))
    except RaError as exc:
        print(json.dumps({"error": exc.code, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    except (sqlite3.Error, OSError, KeyError, TypeError, ValueError) as exc:
        print(
            json.dumps({"error": "FORMAT_FAIL", "message": str(exc)}, sort_keys=True),
            file=sys.stderr,
        )
        return 2


async def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "run":
        return await _cmd_run(args)
    if args.command == "attach":
        return await _cmd_attach(args)
    if args.command == "replay":
        return _cmd_replay(args)
    if args.command == "golden":
        return _cmd_golden(args)
    if args.command == "doctor":
        return await _cmd_doctor(args)
    if args.command == "retain":
        return await _cmd_retain(args)
    raise FormatFail(f"unknown command {args.command}")


async def _cmd_run(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    if args.until is not None and not _UNTIL_RE.fullmatch(args.until):
        raise FormatFail("--until must be HH:MM")
    budget = config.budget_payload()
    if args.budget_usd is not None:
        budget["spend_usd_micro"] = validate_budget_usd(args.budget_usd, config)
    ledger = await Ledger.open(args.db)
    try:
        run_id = await ledger.create_run(args.mode, budget=budget, state="running")
        await ledger.end_run(run_id, "drained")
    finally:
        await ledger.close()
    print(json.dumps({"run_id": run_id, "mode": args.mode, "state": "drained"}, sort_keys=True))
    return 0


async def _cmd_attach(args: argparse.Namespace) -> int:
    load_config(args.config)
    ledger = await Ledger.open(args.db)
    try:
        if args.ring_node is not None and ledger.ring_node(args.ring_node) is None:
            raise FormatFail(f"unknown ring node {args.ring_node}")
        payload = {
            "udid": args.udid,
            "build": args.build,
            "tier": args.tier,
            "state": "attached" if args.build else "needs_hand",
            "thermal": "nominal",
            "crashes": 0,
            "exclusion_window": None,
            "ring_node": args.ring_node,
        }
        await ledger.upsert_device_profile(payload)
    finally:
        await ledger.close()
    print(
        json.dumps(
            {"udid": args.udid, "tier": args.tier, "state": payload["state"]}, sort_keys=True
        )
    )
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    load_config(args.config)
    from ..press.client import ReplayQueue

    valid_types = {item.value for item in route_for_task_types()}
    if args.type is not None and args.type not in valid_types:
        raise FormatFail("--type must be a PRESS task type")
    queue = ReplayQueue(args.queue)
    records = queue.read_all()
    valid = 0
    invalid: list[int] = []
    for index, record in enumerate(records, 1):
        try:
            task_type = record.get("task_type")
            sha = record.get("sha")
            packet = record.get("packet")
            if task_type not in valid_types:
                raise FormatFail("bad task_type")
            if not isinstance(sha, str) or len(sha) != 64:
                raise FormatFail("bad sha")
            if not isinstance(packet, dict):
                raise FormatFail("bad packet")
            valid += 1
        except (FormatFail, KeyError, TypeError):
            invalid.append(index)
    if args.check and invalid:
        raise FormatFail(f"replay queue has {len(invalid)} invalid records")
    if args.clear and not invalid:
        queue.clear()
    print(
        json.dumps(
            {"replayed": valid, "queued": len(records), "invalid": len(invalid)}, sort_keys=True
        )
    )
    return 0


def route_for_task_types() -> tuple[Any, ...]:
    """Return PRESS task types for replay validation."""
    from ..press.routing import TaskType

    return tuple(TaskType)


def _load_baseline(path: Path) -> float:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        score = float(payload["score"])
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise FormatFail(f"invalid golden baseline {path}: {exc}") from exc
    if not math.isfinite(score):
        raise FormatFail(f"invalid golden baseline {path}: score must be finite")
    return score


def _cmd_golden(args: argparse.Namespace) -> int:
    load_config(args.config)
    path = args.file or Path("tests/golden") / f"{args.type}.jsonl"
    try:
        cases = load_golden(path, args.type)
    except (OSError, ValueError) as exc:
        raise FormatFail(f"cannot load golden set {path}: {exc}") from exc
    baseline = _load_baseline(args.baseline) if args.baseline is not None else None
    report = check_golden(cases, _offline_responder, baseline=baseline)
    payload = {
        "task_type": report.task_type.value,
        "rows": report.rows,
        "score": report.score,
        "baseline": report.baseline,
        "passed": report.passed,
        "route_large_model": report.route_large_model,
        "drop": report.drop,
    }
    print(json.dumps(payload, sort_keys=True))
    return 0 if (report.passed or not args.check) else 1


def _offline_responder(case: GoldenCase) -> dict[str, Any]:
    grammar = route_for(case.task_type).grammar
    if grammar == "enum":
        return {"answer": "insufficient_evidence"}
    if grammar == "numeric":
        return {"value": 0}
    if grammar == "code":
        return {"code": "# offline replay\n"}
    if grammar == "ranked":
        return {"ranking": []}
    if grammar == "path":
        return {"path": [], "cost": 0}
    return {"text": "insufficient_evidence"}


async def _cmd_doctor(args: argparse.Namespace) -> int:
    config_error = None
    config_summary = None
    try:
        config = load_config(args.config)
        config_summary = {
            "external_mount": config.station.external_mount,
            "max_vm_images": config.station.max_vm_images,
            "spend_usd": config.budget.spend_usd,
            "model": config.model.primary,
            "local_only": config.model.local_only,
        }
    except RaError as exc:
        config_error = {"code": exc.code, "message": str(exc)}
    layout_errors = layout_check()
    db_status = {"path": str(args.db), "exists": args.db.exists()}
    if args.db.exists():
        ledger = await Ledger.open(args.db)
        try:
            db_status["integrity"] = ledger.integrity_check()
            db_status["counts"] = ledger.counts()
            ring_nodes = ledger.ring_nodes()
            db_status["ring"] = {
                "nodes": len(ring_nodes),
                "epoch": max((int(row["epoch"]) for row in ring_nodes), default=0),
                "bad": sum(1 for row in ring_nodes if row["state"] == "bad"),
            }
            payload = health_payload(
                ledger, extra={"config": "ok" if config_error is None else "error"}
            )
            db_status["health"] = payload
        finally:
            await ledger.close()
    mount_value = config_summary.get("external_mount") if config_summary else None
    mount = mount_value if isinstance(mount_value, str) else None
    mount_status = (
        {"path": mount, "exists": bool(mount and Path(mount).exists())}
        if mount
        else {"path": None, "exists": False}
    )
    report = {
        "config": config_summary,
        "config_error": config_error,
        "layout": {"errors": layout_errors, "ok": not layout_errors},
        "db": db_status,
        "station": {
            "external_mount": mount_status,
            "worker_formula": worker_formula(),
            "disk_free_gb": disk_free_gb(mount) if mount else None,
        },
    }
    print(json.dumps(report, sort_keys=True))
    if args.layout and layout_errors:
        return 1
    return 0


async def _cmd_retain(args: argparse.Namespace) -> int:
    load_config(args.config)
    if not args.sweep:
        raise FormatFail("retain requires --sweep")
    ledger = await Ledger.open(args.db)
    try:
        result = await sweep(
            ledger, RetentionPolicy(batch_size=args.batch_size, min_set=args.min_set)
        )
    finally:
        await ledger.close()
    print(json.dumps(result, sort_keys=True))
    return 0


def layout_check(root: Path | None = None) -> list[str]:
    """Check required layout and the lanes-import boundary."""
    base = root or Path(__file__).resolve().parents[2]
    errors: list[str] = []
    required = [
        "ra/ledger",
        "ra/press",
        "ra/policy",
        "ra/fleet",
        "ra/foundry",
        "ra/triage",
        "ra/ladder",
        "ra/groom",
        "ra/joins",
        "ra/chain",
        "ra/dup",
        "ra/obs",
        "ra/cli",
        "ra/config",
        "ra/lanes",
        "ra/lanes/macos",
        "ra/lanes/ios",
        "grammars",
        "schemas",
        "migrations",
        "models",
        "tests/unit",
        "tests/golden",
        "tests/fixtures",
        "tests/injection",
        "tests/load",
    ]
    for rel in required:
        if not (base / rel).exists():
            errors.append(f"missing {rel}")
    lanes_import = re.compile(r"(?:from\s+(?:ra\.lanes|\.\.lanes|\.lanes)|import\s+ra\.lanes)")
    ra_dir = base / "ra"
    if ra_dir.exists():
        for path in ra_dir.rglob("*.py"):
            rel_path = path.relative_to(ra_dir)
            if "fleet" in rel_path.parts or "lanes" in rel_path.parts:
                continue
            text = path.read_text(encoding="utf-8")
            if lanes_import.search(text):
                errors.append(f"lanes import outside fleet: {path.relative_to(base)}")
    return errors


def worker_formula(ram_gb: float | None = None, cores: int | None = None) -> dict[str, Any]:
    """RA-STN-003 worker count formula."""
    cpu = cores if cores is not None else (os.cpu_count() or 1)
    ram = ram_gb if ram_gb is not None else _detect_ram_gb()
    if ram is None:
        return {"cores": cpu, "ram_gb": None, "workers": None}
    workers = min(cpu - 2, int((ram - 14) / 0.6))
    return {"cores": cpu, "ram_gb": ram, "workers": max(0, workers)}


def _detect_ram_gb() -> float | None:
    if sys.platform == "darwin":
        try:
            import subprocess

            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True, timeout=2)
            return round(int(out.strip()) / (1024**3), 2)
        except Exception:
            return None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kib = int(line.split()[1])
                return round(kib * 1024 / (1024**3), 2)
    except (OSError, ValueError, IndexError):
        return None
    return None


def disk_free_gb(path: str) -> float | None:
    """Free disk in GiB for a path."""
    try:
        return round(os.statvfs(path).f_bavail * os.statvfs(path).f_frsize / (1024**3), 2)
    except OSError:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
