"""JSON Foundry store tests."""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from ra.foundry import FoundryState, JsonFoundryStore


class StoreTest(unittest.TestCase):
    def test_save_load_list_roundtrip(self) -> None:
        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                store = JsonFoundryStore(Path(tmp))
                self.assertIsNone(await store.load("missing"))
                self.assertEqual(await store.list_ids(), [])
                state = FoundryState(harness_id="b", format="heif")
                other = FoundryState(harness_id="a", format="bin")
                await store.save(state)
                await store.save(other)
                self.assertEqual(await store.list_ids(), ["a", "b"])
                loaded = await store.load("b")
                self.assertIsNotNone(loaded)
                self.assertEqual(loaded.harness_id, "b")
                loaded.state = "accepted"
                await store.save(loaded)
                again = await store.load("b")
                self.assertEqual(again.state, "accepted")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
