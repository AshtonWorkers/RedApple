"""Command line for compiling a dyld-cache surface graph."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any, Dict, List, Optional

from .compile import compile_surface
from .dyld import DyldCache
from .store import SQLiteEntryPointStore


async def _run(args: argparse.Namespace) -> Dict[str, Any]:
    store = SQLiteEntryPointStore(args.db)
    async with await DyldCache.open(args.cache) as cache:
        result = await compile_surface(
            cache,
            ring_node=args.ring_node,
            store=store,
            image_limit=args.limit,
        )
    rows = await store.read_ring_node(args.ring_node)
    return {
        "cache": result.cache_path,
        "ring_node": result.ring_node,
        "images_scanned": result.images_scanned,
        "strings_scanned": result.strings_scanned,
        "sandbox_profiles": len(result.profiles),
        "xpc_shapes": result.xpc_shapes,
        "service_candidates": result.service_candidates,
        "entry_points": len(rows),
        "sha256": result.sha256,
        "top": [
            {
                "name": r["name"],
                "weight": r["weight"],
                "privilege_delta": r["privilege_delta"],
                "parser_complexity": r["parser_complexity"],
                "reach_from": json.loads(r["reach_from_json"])[:3],
            }
            for r in rows[: args.top]
        ],
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ra.srf")
    parser.add_argument("--cache", required=True, help="dyld shared cache file or directory")
    parser.add_argument("--db", default="entry_points.sqlite3", help="SQLite output path")
    parser.add_argument("--ring-node", default="macos-dyld-cache")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="scan only the first N images (reduced proof input)",
    )
    parser.add_argument("--top", type=int, default=20)
    args = parser.parse_args(argv)
    summary = asyncio.run(_run(args))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
