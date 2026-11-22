"""Lane-backed race backend.

Lives in fleet because only fleet modules may import ``ra.lanes``. Executes
each deterministic race schedule against a provisioned lane: launch, feed the
scheduled interleaving with jitter delays, collect crashes before reset
(RA-LAN-007), and convert lane CrashRefs into race CrashRefs.
"""

from __future__ import annotations

import asyncio
import json
import math
import time

from ..errors import FormatFail
from ..lanes.base import CrashRef, FeedStatus, HarnessRef, Lane, LaneError
from ..race.models import RaceCrash, RaceRunResult, RaceSchedule, RaceStep, canonical_json
from ..race.store import RaceCas  # noqa: F401  (re-export for adapter typing)


def race_crash_from_lane(ref: CrashRef, *, lane: str) -> RaceCrash:
    """Convert a lane CrashRef into a race CrashRef with JSON-safe metadata."""
    metadata = json.loads(json.dumps(dict(ref.metadata), default=str))
    metadata["lane"] = lane
    return RaceCrash(
        id=ref.id,
        kind=ref.kind,
        context=ref.context,
        handle_id=ref.handle_id,
        path=ref.path,
        digest=ref.digest,
        payload=ref.payload,
        metadata=metadata,
    )


def step_payload(schedule: RaceSchedule, step: RaceStep) -> bytes:
    """Deterministic feed bytes for one scheduled step.

    The payload is a pure function of the schedule digest and step, so replay
    feeds byte-identical input (RA-RACE-004). Corpus bytes are never parsed on
    the host (I10); this is schedule metadata, not corpus content.
    """
    return canonical_json(
        {
            "delay_us": step.delay_us,
            "format": "ra.race.step.v1",
            "op": step.op,
            "schedule": schedule.digest,
            "worker": step.worker,
        }
    )


class LaneRaceBackend:
    """Race backend executing schedules on a provisioned lane.

    The lane must already be provisioned and ready; provisioning is owned by
    the fleet layer. ``deterministic`` is false because hardware interleavings
    are not perfectly reproducible; the harness measures that as flakiness.
    """

    name = "lane"
    deterministic = False

    def __init__(
        self,
        lane: Lane,
        *,
        harness: HarnessRef,
        delay_scale: float = 1.0,
        max_steps: int = 4096,
    ) -> None:
        if isinstance(delay_scale, bool) or not isinstance(delay_scale, (int, float)):
            raise FormatFail("lane race backend delay_scale must be a number")
        scaled = float(delay_scale)
        if not math.isfinite(scaled) or scaled < 0:
            raise FormatFail("lane race backend delay_scale must be finite and >= 0")
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise FormatFail("lane race backend max_steps must be a positive int")
        self._lane = lane
        self._harness = harness
        self._delay_scale = scaled
        self._max_steps = max_steps

    async def run_schedule(self, schedule: RaceSchedule) -> RaceRunResult:
        if len(schedule.steps) > self._max_steps:
            raise FormatFail("race schedule exceeds lane backend max_steps")
        started = time.monotonic()
        handle = await self._lane.launch(schedule.target.name, self._harness)
        crashes: list[RaceCrash] = []
        errors: list[str] = []
        steps_done = 0
        collected = False

        async def collect() -> None:
            nonlocal collected
            refs = await self._lane.collect_crashes(handle)
            crashes.extend(race_crash_from_lane(ref, lane=self._lane.name) for ref in refs)
            collected = True

        try:
            for step in schedule.steps:
                if step.delay_us and self._delay_scale:
                    await asyncio.sleep(step.delay_us / 1_000_000 * self._delay_scale)
                result = await self._lane.feed(handle, step_payload(schedule, step))
                steps_done += 1
                if result.status is not FeedStatus.ACCEPTED:
                    break
            await collect()
        except LaneError as exc:
            errors.append(exc.code.value)
            if exc.crash_ref is not None:
                crashes.append(race_crash_from_lane(exc.crash_ref, lane=self._lane.name))
            if not collected:
                try:
                    await collect()
                except LaneError as collect_exc:
                    errors.append(collect_exc.code.value)
        finally:
            if collected:
                try:
                    await self._lane.reset(handle)
                except LaneError as reset_exc:
                    errors.append(reset_exc.code.value)

        duration_ms = int((time.monotonic() - started) * 1000)
        return RaceRunResult(
            schedule_digest=schedule.digest,
            crashes=tuple(crashes),
            steps_executed=steps_done,
            duration_ms=duration_ms,
            errors=tuple(errors),
        )
