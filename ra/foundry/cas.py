"""Content-addressed storage for Foundry artifacts (RA-FND-004, I2).

Pure helpers pack/unpack harness bundles; the store methods are async I/O.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import tarfile
import uuid
from pathlib import Path
from typing import Dict, Mapping

from .errors import CasCorrupt


def sha256_hex(data: bytes) -> str:
    """Return the lowercase sha256 hex digest for bytes (I2)."""
    return hashlib.sha256(data).hexdigest()


def pack_harness_files(files: Mapping[str, bytes]) -> bytes:
    """Pack harness files into a deterministic tar bundle."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _safe_member_name(name: str) -> bool:
    if name.startswith("/") or name.startswith("\\"):
        return False
    parts = Path(name).parts
    return ".." not in parts and "" not in parts


def unpack_harness_files(bundle: bytes, target: Path) -> None:
    """Extract a harness bundle, rejecting unsafe paths and symlink escapes."""
    target.mkdir(parents=True, exist_ok=True)
    root = target.resolve()
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if not _safe_member_name(member.name):
                raise CasCorrupt(f"unsafe path in harness bundle: {member.name}")
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            destination = (root / member.name).resolve()
            try:
                destination.relative_to(root)
            except ValueError:
                raise CasCorrupt(f"unsafe path in harness bundle: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(extracted.read())


class ContentAddressedStore:
    """SHA-256 addressed object store."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256[2:4] / sha256

    def _put_sync(self, data: bytes) -> str:
        digest = sha256_hex(data)
        path = self._path_for(digest)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
            tmp.write_bytes(data)
            tmp.replace(path)
        return digest

    def _get_sync(self, sha256: str) -> bytes:
        path = self._path_for(sha256)
        if not path.exists():
            raise CasCorrupt(f"missing CAS object {sha256}")
        data = path.read_bytes()
        if sha256_hex(data) != sha256:
            raise CasCorrupt(f"CAS object {sha256} failed integrity check")
        return data

    async def put(self, data: bytes) -> str:
        """Store bytes and return their content address."""
        return await asyncio.to_thread(self._put_sync, data)

    async def get(self, sha256: str) -> bytes:
        """Read bytes by content address, verifying integrity."""
        return await asyncio.to_thread(self._get_sync, sha256)

    async def put_harness(self, files: Mapping[str, bytes]) -> str:
        """Store a harness bundle and return its content address."""
        return await self.put(pack_harness_files(files))

    async def extract_harness(self, sha256: str, target: Path) -> None:
        """Restore a harness bundle into ``target``."""
        bundle = await self.get(sha256)
        await asyncio.to_thread(unpack_harness_files, bundle, Path(target))
