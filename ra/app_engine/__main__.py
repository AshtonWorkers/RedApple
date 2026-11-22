"""CLI entrypoint used by the native RedApple app."""

from __future__ import annotations

import argparse
import asyncio
import json
import signal
import sys

from . import workspace as ws
from .engine import config_from_env, loop_engine, run_engine, stop_engine


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ra.app_engine")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--time-budget", type=float, default=None)
    run.add_argument("--json", action="store_true")
    loop = sub.add_parser("loop")
    loop.add_argument("--time-budget", type=float, default=None)
    loop.add_argument("--json", action="store_true")
    stop = sub.add_parser("stop")
    stop.add_argument("--json", action="store_true")
    status = sub.add_parser("status")
    status.add_argument("--json", action="store_true")
    return parser


async def _run(args: argparse.Namespace) -> int:
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop_event.set())
    config = config_from_env(time_budget_s=args.time_budget)
    if args.command == "loop":
        code = await loop_engine(config, stop_event)
    else:
        code = await run_engine(config, stop_event)
    if args.json:
        status = ws.load_json(ws.status_path(config.home), {})
        print(json.dumps(status, indent=2, ensure_ascii=False))
    return code


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"run", "loop"}:
        return asyncio.run(_run(args))
    if args.command == "stop":
        stopped = asyncio.run(stop_engine())
        if args.json:
            status = ws.load_json(ws.status_path(), {})
            print(json.dumps(status, indent=2, ensure_ascii=False))
        else:
            print(json.dumps({"stopped": stopped}, indent=2))
        return 0 if stopped else 1
    status = ws.load_json(ws.status_path(), {})
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
