"""Stdlib Apple security-release HTML parser.

Ported from PR #1's fetcher with strict types and no filesystem/network I/O.
Network access lives in :mod:`ra.advisory.service` behind an injectable
downloader.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from .models import CveCredit, DiffFrom, ReleaseEntry, ReleaseRecord

APPLE_INDEX_URL = "https://support.apple.com/en-us/100100"
_OS_VERSION_RE = re.compile(
    r"\b(iOS|iPadOS|macOS|tvOS|watchOS|visionOS|Safari)\b.*?(\d+(?:\.\d+)*)"
)
_BUILD_RE = re.compile(r"\b[Bb]uild\s+(\d{2}[A-Z]\d+[a-z]?)\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_ADVISORY_ID_RE = re.compile(r"/\d{6}/?$")
_DATE_FORMATS = ("%d %b %Y", "%B %d, %Y", "%d %B %Y")


@dataclass
class _Cell:
    text: str = ""
    links: list[str] = field(default_factory=list)


@dataclass
class _Block:
    tag: str
    text: str = ""


class _Document(HTMLParser):
    """Minimal table/block extractor matching PR #1's parser behavior."""

    def __init__(self, html: str) -> None:
        if not isinstance(html, str):
            raise ValueError("advisory HTML must be str")
        super().__init__(convert_charrefs=True)
        self.rows: list[list[_Cell]] = []
        self.blocks: list[tuple[str, str]] = []
        self.row: list[_Cell] | None = None
        self.cell: _Cell | None = None
        self.block: _Block | None = None
        self.feed(html)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name: value for name, value in attrs if value is not None}
        if tag == "tr":
            self.row = []
        if tag in {"td", "th"}:
            self.cell = _Cell()
        if tag == "a" and self.cell is not None:
            href = attr_map.get("href")
            if href is not None:
                self.cell.links.append(href)
        if tag in {"h1", "h2", "h3", "p"}:
            self.block = _Block(tag)
        if tag == "br":
            self.handle_data(" ")

    def handle_data(self, data: str) -> None:
        if self.cell is not None:
            self.cell.text += data
        if self.block is not None:
            self.block.text += data

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self.cell is not None:
            self.cell.text = " ".join(self.cell.text.split())
            if self.row is not None:
                self.row.append(self.cell)
            self.cell = None
        if tag == "tr" and self.row is not None:
            self.rows.append(self.row)
            self.row = None
        if self.block is not None and tag == self.block.tag:
            self.blocks.append((self.block.tag, " ".join(self.block.text.split())))
            self.block = None


@dataclass(frozen=True)
class ReleaseMetadata:
    """Metadata scraped from one advisory page."""

    advisory_title: str | None
    builds: tuple[str, ...]


def _parse_date(text: str) -> str | None:
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _safe_advisory_url(href: str) -> str | None:
    url = urljoin(APPLE_INDEX_URL, href)
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "support.apple.com":
        return None
    if _ADVISORY_ID_RE.search(parsed.path) is None:
        return None
    return url


def parse_index(html: str) -> list[ReleaseRecord]:
    """Parse the Apple security-release index into release records."""
    releases: list[ReleaseRecord] = []
    for row in _Document(html).rows:
        if len(row) != 3:
            continue
        date = _parse_date(row[2].text)
        if date is None:
            continue
        links: list[str] = []
        for href in row[0].links:
            url = _safe_advisory_url(href)
            if url is not None:
                links.append(url)
        releases.append(
            ReleaseRecord(
                name=row[0].text.split("This update")[0].strip(),
                available_for=row[1].text,
                date=date,
                url=links[0] if links else None,
            )
        )
    if not releases:
        raise ValueError("No release rows recognized; Apple index markup may have changed")
    return sorted(releases, key=lambda release: release.date, reverse=True)


@dataclass
class _EntryBuilder:
    component: str
    available_for: str = ""
    impact: str = ""
    description: str = ""
    cves: list[CveCredit] = field(default_factory=list)

    def finish(self) -> ReleaseEntry | None:
        if not self.component.strip():
            return None
        if not self.impact and not self.cves:
            return None
        cves: list[CveCredit] = []
        seen: set[str] = set()
        for cve in self.cves:
            if cve.id in seen:
                continue
            seen.add(cve.id)
            cves.append(cve)
        return ReleaseEntry(
            component=self.component,
            available_for=self.available_for,
            impact=self.impact,
            description=self.description,
            cves=tuple(cves),
        )


def parse_advisory(html: str) -> list[ReleaseEntry]:
    """Parse one advisory page into affected-component entries."""
    entries: list[ReleaseEntry] = []
    current: _EntryBuilder | None = None
    for tag, text in _Document(html).blocks:
        if tag in {"h2", "h3"}:
            if current is not None:
                finished = current.finish()
                if finished is not None:
                    entries.append(finished)
            current = _EntryBuilder(component=text)
            continue
        if current is None:
            continue
        for label, field_name in (
            ("Available for:", "available_for"),
            ("Impact:", "impact"),
            ("Description:", "description"),
        ):
            if text.startswith(label):
                setattr(current, field_name, text[len(label) :].strip())
        if not text.startswith("CVE-"):
            continue
        matches = list(_CVE_RE.finditer(text))
        for index, match in enumerate(matches):
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            credit = text[match.end() : end].strip(": ;,")
            current.cves.append(CveCredit(id=match.group(), credit=credit))
    if current is not None:
        finished = current.finish()
        if finished is not None:
            entries.append(finished)
    return entries


def release_metadata(html: str) -> ReleaseMetadata:
    """Extract advisory title and explicit build strings from one advisory."""
    blocks = _Document(html).blocks
    text = " ".join(block_text for _, block_text in blocks)
    title = next((block_text for tag, block_text in blocks if tag == "h1"), None)
    return ReleaseMetadata(
        advisory_title=title,
        builds=tuple(sorted(set(_BUILD_RE.findall(text)))),
    )


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def enrich_versions(releases: list[ReleaseRecord] | tuple[ReleaseRecord, ...]) -> list[ReleaseRecord]:
    """Fill ``os``/``version`` and same-major ``diff_from`` hints deterministically."""
    parsed: list[tuple[ReleaseRecord, str | None, str | None]] = []
    for release in releases:
        match = _OS_VERSION_RE.search(release.name)
        parsed.append(
            (
                release,
                match.group(1) if match else None,
                match.group(2) if match else None,
            )
        )

    out: list[ReleaseRecord] = []
    for release, os_name, version in parsed:
        diff_from: DiffFrom | None = None
        if os_name is not None and version is not None:
            current = _version_tuple(version)
            candidates: list[tuple[ReleaseRecord, str]] = []
            for other, other_os, other_version in parsed:
                if other_os != os_name or other_version is None:
                    continue
                if other_version.split(".")[0] != version.split(".")[0]:
                    continue
                if _version_tuple(other_version) >= current:
                    continue
                if other.date > release.date:
                    continue
                candidates.append((other, other_version))
            if candidates:
                previous, previous_version = max(
                    candidates, key=lambda item: _version_tuple(item[1])
                )
                diff_from = DiffFrom(
                    name=previous.name,
                    version=previous_version,
                    url=previous.url,
                    date=previous.date,
                )
        out.append(replace(release, os=os_name, version=version, diff_from=diff_from))
    return out
