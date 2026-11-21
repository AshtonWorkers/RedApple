"""Content-addressed store tests."""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from ra.foundry import CasCorrupt, ContentAddressedStore, pack_harness_files, unpack_harness_files


class CasTest(unittest.TestCase):
    def test_pack_unpack_roundtrip_and_determinism(self) -> None:
        files = {"b.txt": b"two", "a.txt": b"one", "dir/c.txt": b"three"}
        first = pack_harness_files(files)
        second = pack_harness_files(dict(reversed(list(files.items()))))
        self.assertEqual(first, second)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out"
            unpack_harness_files(first, target)
            self.assertEqual((target / "a.txt").read_bytes(), b"one")
            self.assertEqual((target / "b.txt").read_bytes(), b"two")
            self.assertEqual((target / "dir" / "c.txt").read_bytes(), b"three")

    def test_unpack_rejects_unsafe_names(self) -> None:
        for name in ("../evil", "/tmp/evil", "a/../../evil", "..\\evil", ""):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                bundle = pack_harness_files({name: b"payload"})
                with self.assertRaises(CasCorrupt):
                    unpack_harness_files(bundle, Path(tmp) / "out")

    def test_unpack_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside.txt"
            target = root / "extract"
            target.mkdir()
            (target / "link").symlink_to(outside)
            bundle = pack_harness_files({"link": b"payload"})
            with self.assertRaises(CasCorrupt):
                unpack_harness_files(bundle, target)
            self.assertFalse(outside.exists())

    def test_unpack_skips_non_file_members(self) -> None:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            directory = tarfile.TarInfo("dir")
            directory.type = tarfile.DIRTYPE
            archive.addfile(directory)
            payload = b"x"
            member = tarfile.TarInfo("dir/x.txt")
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out"
            unpack_harness_files(buffer.getvalue(), target)
            self.assertEqual((target / "dir" / "x.txt").read_bytes(), b"x")

    def test_store_put_get_integrity(self) -> None:
        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                store = ContentAddressedStore(Path(tmp))
                digest = await store.put(b"hello")
                self.assertEqual(await store.put(b"hello"), digest)
                self.assertEqual(len(digest), 64)
                self.assertEqual(await store.get(digest), b"hello")
                with self.assertRaises(CasCorrupt):
                    await store.get("0" * 64)
                path = store._path_for(digest)
                path.write_bytes(b"corrupt")
                with self.assertRaises(CasCorrupt):
                    await store.get(digest)

        asyncio.run(run())

    def test_put_json_kinds(self) -> None:
        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                store = ContentAddressedStore(Path(tmp) / "cas")
                plain = await store.put_json({"x": 1})
                self.assertNotIn("kind", json.loads((await store.get(plain)).decode()))
                custom = await store.put_json({"kind": "custom", "x": 1}, kind="ignored")
                payload = json.loads((await store.get(custom)).decode())
                self.assertEqual(payload["kind"], "custom")

        asyncio.run(run())

    def test_put_and_extract_harness(self) -> None:
        async def run() -> None:
            with tempfile.TemporaryDirectory() as tmp:
                store = ContentAddressedStore(Path(tmp) / "cas")
                digest = await store.put_harness({"x.txt": b"x", "y/z.txt": b"z"})
                target = Path(tmp) / "restore"
                await store.extract_harness(digest, target)
                self.assertEqual((target / "x.txt").read_bytes(), b"x")
                self.assertEqual((target / "y" / "z.txt").read_bytes(), b"z")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
