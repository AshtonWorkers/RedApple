"""macOS gate and harness helpers for ImageIO/HEIF discovery.

Linux CI imports this module safely: no lane or ImageIO work happens unless the
caller is on macOS and injects a provisioned lane.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ..errors import RaError
from .images import IMAGE_FORMATS
from .models import DiscoveryHarnessRef


class MacOSUnavailable(RaError):
    """Raised when a macOS-only discovery path is used off macOS."""

    code = "MACOS_UNAVAILABLE"
    retryable = False


def macos_available(*, platform: str | None = None) -> bool:
    """Return whether the target platform can run ImageIO/HEIF discovery."""
    current = platform if platform is not None else sys.platform
    return current.startswith("darwin")


def require_macos(feature: str = "ImageIO/HEIF discovery", *, platform: str | None = None) -> None:
    """Raise :class:`MacOSUnavailable` unless running on macOS."""
    if not macos_available(platform=platform):
        raise MacOSUnavailable(f"{feature} requires macOS; current platform is {sys.platform}")


def imageio_heif_feed_source(repo_root: Path | None = None) -> Path:
    """Return the stdin feed driver source for the HEIF/ImageIO harness."""
    root = repo_root or Path(__file__).resolve().parents[2]
    return root / "harnesses" / "imageio_heif" / "feed.cc"


def imageio_heif_feed_manifest(repo_root: Path | None = None) -> Path:
    """Return the feed-harness manifest path."""
    root = repo_root or Path(__file__).resolve().parents[2]
    return root / "harnesses" / "imageio_heif" / "feed_harness.json"


def imageio_heif_harness_ref(feed_binary: Path, *, name: str = "imageio_heif_feed") -> DiscoveryHarnessRef:
    """Build the harness reference a macOS lane should launch for stdin feeds."""
    argv = [str(feed_binary)]
    return DiscoveryHarnessRef(
        name=name,
        kind="command",
        argv=argv,
        env={},
        metadata={
            "surface": "imageio.heif",
            "format": "heif",
            "image_formats": list(IMAGE_FORMATS),
            "feed_argv": argv,
            "build_webkit": False,
            "saturated_return_codes": [75],
        },
    )


def macos_verification_checklist() -> list[str]:
    """Return the real macOS/device checks this component cannot run on Linux CI."""
    return [
        "compile harnesses/imageio_heif/feed.cc with LLVMFuzzerTestOneInput.cc on macOS",
        "run a tart macOS VM lane end-to-end with imageio_heif_harness_ref",
        "confirm ImageIO crash reports appear as CrashRef(kind='macos_vm_crash')",
        "verify thermal pause/drain and collect-before-reset on the real lane",
        "measure sustained throughput and crash dedup against the live ledger",
        "feed PNG/JPEG/GIF/BMP/TIFF/WebP seeds and confirm ImageIO decode attempts",
    ]
