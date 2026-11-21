"""SBPL sandbox-profile parsing for RA-SRF-001.

This parser is intentionally small and total: it accepts the SBPL surface we can
derive from cache strings (and embedded profile text when present) and extracts
deterministic mach-lookup grants plus operation names for privilege scoring.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Optional

SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,120}$")

HIGH_RISK_OPS = frozenset(
    {
        "network-outbound",
        "network-inbound",
        "network-bind",
        "process-exec",
        "process-fork",
        "file-write*",
        "file-write-data",
        "file-write-create",
        "iokit-open",
        "mach-priv*",
        "sysctl-write",
        "nvram-*",
        "keychain-*",
        "user-preference-read",
        "user-preference-write",
        "mach-lookup",
        "xpc-message-send",
        "system-*",
        "device-*",
    }
)

XPC_MESSAGE_OPS = frozenset({"xpc-message-send", "xpc-message-receive"})


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    source: str
    operations: tuple[str, ...]
    mach_lookup_allow: tuple[str, ...]
    mach_lookup_deny: tuple[str, ...]
    xpc_message_ops: tuple[str, ...]
    high_risk_ops: tuple[str, ...]
    sha256: str

    @property
    def privilege_score(self) -> int:
        return min(5, len(self.high_risk_ops))


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == ";":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue
        if ch == '"':
            j = i + 1
            buf: list[str] = []
            while j < n:
                c = text[j]
                if c == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if c == '"':
                    break
                buf.append(c)
                j += 1
            tokens.append("".join(buf))
            i = j + 1
            continue
        if ch == "#":
            if i + 1 < n and text[i + 1] == '"':
                j = i + 2
                regex_buf: list[str] = []
                while j < n and text[j] != '"':
                    regex_buf.append(text[j])
                    j += 1
                tokens.append("#" + "".join(regex_buf))
                i = j + 1 if j < n else j
                continue
            j = i + 1
            while j < n and not text[j].isspace() and text[j] not in "()":
                j += 1
            tokens.append(text[i:j])
            i = j
            continue
        j = i
        while j < n and not text[j].isspace() and text[j] not in "()":
            j += 1
        tokens.append(text[i:j])
        i = j
    return tokens


def _parse(tokens: list[str]) -> list[object]:
    pos = 0

    def parse_one() -> object:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of SBPL")
        tok = tokens[pos]
        pos += 1
        if tok == "(":
            out: list[object] = []
            while pos < len(tokens) and tokens[pos] != ")":
                out.append(parse_one())
            if pos >= len(tokens):
                raise ValueError("unterminated SBPL form")
            pos += 1
            return out
        if tok == ")":
            raise ValueError("unexpected ) in SBPL")
        return tok

    forms: list[object] = []
    while pos < len(tokens):
        forms.append(parse_one())
    return forms


def _walk(forms: list[object]) -> Iterable[list[object]]:
    stack = list(forms)
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            yield node
            stack.extend(node)


def _strings(node: object) -> Iterable[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _is_allow_deny(form: list[object]) -> bool:
    return len(form) >= 2 and form[0] in {"allow", "deny"}


def _operation_of(form: list[object]) -> Optional[str]:
    if len(form) < 2 or not isinstance(form[1], str):
        return None
    return form[1]


def looks_like_sbpl(text: str) -> bool:
    stripped = text.lstrip()
    head = stripped[:4096]
    return stripped.startswith("(") and ("(version" in head or "(deny" in head or "(allow" in head)


def parse_sbpl_profile(
    text: str, *, source: str, name: Optional[str] = None
) -> Optional[SandboxProfile]:
    """Parse one SBPL profile document. Returns None when it is not SBPL."""
    if not looks_like_sbpl(text):
        return None
    forms = _parse(_tokenize(text))
    operations: set[str] = set()
    allow_lookup: set[str] = set()
    deny_lookup: set[str] = set()
    xpc_ops: set[str] = set()
    high_risk: set[str] = set()

    for form in _walk(forms):
        if not isinstance(form, list) or not _is_allow_deny(form):
            continue
        op = _operation_of(form)
        if not op:
            continue
        operations.add(op)
        if op in XPC_MESSAGE_OPS:
            xpc_ops.add(op)
        if op in HIGH_RISK_OPS or op.endswith("*"):
            high_risk.add(op)
        if op == "mach-lookup":
            names = _lookup_names(form)
            if form[0] == "allow":
                allow_lookup.update(names)
            else:
                deny_lookup.update(names)

    if not operations or operations == {"default"}:
        return None
    profile_name = name or source.rsplit("/", 1)[-1] or "embedded"
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return SandboxProfile(
        name=profile_name,
        source=source,
        operations=tuple(sorted(operations)),
        mach_lookup_allow=tuple(
            sorted(
                n
                for n in allow_lookup
                if n.startswith("regex:") or SERVICE_NAME_RE.match(n)
            )
        ),
        mach_lookup_deny=tuple(sorted(n for n in deny_lookup if SERVICE_NAME_RE.match(n))),
        xpc_message_ops=tuple(sorted(xpc_ops)),
        high_risk_ops=tuple(sorted(high_risk)),
        sha256=sha,
    )


def _lookup_names(form: list[object]) -> set[str]:
    names: set[str] = set()

    def add_regex(value: str) -> None:
        pattern = value.strip()
        if pattern.startswith("#"):
            pattern = pattern[1:]
        if len(pattern) >= 2 and pattern.startswith('"') and pattern.endswith('"'):
            pattern = pattern[1:-1]
        if pattern:
            names.add(f"regex:{pattern}")

    def walk(node: object) -> None:
        if not isinstance(node, list):
            return
        if node and isinstance(node[0], str):
            key = node[0]
            if key in {"global-name", "local-name"}:
                for value in node[1:]:
                    if isinstance(value, str) and SERVICE_NAME_RE.match(value):
                        names.add(value)
                return
            if key in {"global-name-regex", "local-name-regex"}:
                for value in node[1:]:
                    if isinstance(value, str):
                        add_regex(value)
                return
        for child in node:
            walk(child)

    for item in form[2:]:
        walk(item)
    return names


def profile_grants_service(profile: SandboxProfile, service: str) -> bool:
    if service in profile.mach_lookup_allow:
        return True
    for allowed in profile.mach_lookup_allow:
        if allowed.startswith("regex:"):
            pattern = allowed[len("regex:") :]
            try:
                if re.search(pattern, service):
                    return True
            except re.error:
                continue
    return False


def profiles_from_strings(strings: Iterable[str], *, source: str) -> tuple[SandboxProfile, ...]:
    out: list[SandboxProfile] = []
    for idx, s in enumerate(strings):
        if not looks_like_sbpl(s):
            continue
        profile = parse_sbpl_profile(s, source=f"{source}#str{idx}")
        if profile is not None:
            out.append(profile)
    return tuple(out)
