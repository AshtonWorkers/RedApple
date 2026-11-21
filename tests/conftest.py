import asyncio
from collections.abc import Coroutine
from typing import Any


def run(coro: Coroutine[Any, Any, Any]) -> Any:
    """Run an async test body."""
    return asyncio.run(coro)
