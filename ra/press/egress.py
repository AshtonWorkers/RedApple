"""PRESS egress governor: token bucket, concurrency, and retry backoff."""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

Clock = Callable[[], float]
Sleep = Callable[[float], None]


class EgressGovernor:
    """Thread-safe token bucket plus bounded-concurrency egress limiter."""

    def __init__(
        self,
        *,
        rate_per_s: float = 20.0,
        max_concurrent: int = 8,
        max_retries: int = 3,
        backoff_cap_s: float = 60.0,
        clock: Clock | None = None,
        sleep: Sleep | None = None,
        rng: random.Random | None = None,
    ) -> None:
        if rate_per_s <= 0:
            raise ValueError("rate_per_s must be positive")
        if max_concurrent < 1:
            raise ValueError("max_concurrent must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if backoff_cap_s < 0:
            raise ValueError("backoff_cap_s must be non-negative")
        self.rate_per_s = float(rate_per_s)
        self.max_concurrent = int(max_concurrent)
        self.max_retries = int(max_retries)
        self.backoff_cap_s = float(backoff_cap_s)
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep
        self._rng = rng or random.Random()
        self._capacity = max(1.0, self.rate_per_s)
        self._tokens = self._capacity
        self._last = self._clock()
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        """Number of permits currently held."""
        return self._in_flight

    @contextmanager
    def permit(self) -> Iterator[None]:
        """Acquire one rate token and one concurrency slot."""
        self._semaphore.acquire()
        self._in_flight += 1
        try:
            self._acquire_token()
            yield
        finally:
            self._in_flight -= 1
            self._semaphore.release()

    def backoff_delay(self, attempt: int) -> float:
        """Full-jitter exponential backoff capped at ``backoff_cap_s``."""
        if attempt < 0:
            raise ValueError("attempt must be non-negative")
        cap = min(self.backoff_cap_s, 2.0 ** (attempt + 1))
        return self._rng.uniform(0.0, cap)

    def backoff_wait(self, attempt: int) -> float:
        """Sleep for one full-jitter backoff and return the delay used."""
        delay = self.backoff_delay(attempt)
        self._sleep(delay)
        return delay

    def _acquire_token(self) -> None:
        while True:
            with self._lock:
                now = self._clock()
                elapsed = max(0.0, now - self._last)
                self._tokens = min(self._capacity, self._tokens + elapsed * self.rate_per_s)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait = (1.0 - self._tokens) / self.rate_per_s
            self._sleep(wait)
