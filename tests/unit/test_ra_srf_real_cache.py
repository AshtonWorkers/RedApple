"""Opt-in real dyld-cache proof.

This test is intentionally guarded: it is skipped on Linux CI and on macOS
unless `RA_SRF_REAL_CACHE` points at a real dyld shared cache (for example
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`).

macOS verification still owed for RA-SRF:
- run `python -m ra.srf --cache <real-cache> --db /tmp/ra_srf.sqlite --top 20`
- confirm `images_scanned`, `strings_scanned`, `service_candidates`, and
  `entry_points` are non-zero and the JSON summary is deterministic across two runs
- spot-check `reach_from_json` contains both `image:` and `sandbox-profile:` rows
- verify the SQLite `entry_point` table can be replaced by ring node without
  cross-ring leakage
"""

import asyncio
import os
import sys

import pytest

from ra.srf.compile import compile_surface
from ra.srf.dyld import DyldCache
from ra.srf.store import SQLiteEntryPointStore

pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="real dyld cache proof is macOS-only"
)


def test_RA_SRF_real_dyld_cache_proof(tmp_path):
    cache_path = os.environ.get("RA_SRF_REAL_CACHE")
    if not cache_path:
        pytest.skip("set RA_SRF_REAL_CACHE to a real dyld shared cache path")
    limit_raw = os.environ.get("RA_SRF_REAL_CACHE_LIMIT", "")
    image_limit = int(limit_raw) if limit_raw else None

    async def exercise():
        store = SQLiteEntryPointStore(tmp_path / "real.sqlite")
        async with await DyldCache.open(cache_path) as cache:
            return await compile_surface(
                cache,
                ring_node="real-cache-proof",
                store=store,
                image_limit=image_limit,
            )

    result = asyncio.run(exercise())
    assert result.images_scanned > 0
    assert result.strings_scanned > 0
    assert result.service_candidates > 0
    assert len(result.sha256) == 64
