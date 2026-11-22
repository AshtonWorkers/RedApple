"""Guards against adversarial SBPL profiles and regular expressions.

Surface expansion trusts SBPL ``global-name-regex`` / ``local-name-regex``
grants only after they pass a conservative static check. The check rejects
nested/ambiguous quantifiers, backreferences, lookarounds, and oversized or
unbalanced expressions before ``re`` ever sees them.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_REGEX_PATTERN_LENGTH = 256
MAX_REGEX_GROUPS = 16
MAX_REGEX_QUANTIFIERS = 24
MAX_REGEX_ALTERNATIONS = 12
MAX_SBPL_PROFILE_CHARS = 262_144
MAX_SBPL_DEPTH = 96

_REGEX_FLAGS = frozenset("aiLmsux-")


@dataclass
class _GroupState:
    has_quantifier: bool = False
    has_alternation: bool = False


def _consume_quantifier(pattern: str, start: int) -> int | None:
    """Return the index after a quantifier at ``start``, or None."""
    n = len(pattern)
    i = start
    if i >= n:
        return None
    ch = pattern[i]
    if ch in "*+?":
        i += 1
    elif ch == "{":
        j = i + 1
        if j >= n or not pattern[j].isdigit():
            return None
        while j < n and pattern[j].isdigit():
            j += 1
        if j < n and pattern[j] == "}":
            j += 1
        elif j < n and pattern[j] == ",":
            j += 1
            if j < n and pattern[j] == "}":
                j += 1
            else:
                if j >= n or not pattern[j].isdigit():
                    return None
                while j < n and pattern[j].isdigit():
                    j += 1
                if j >= n or pattern[j] != "}":
                    return None
                j += 1
        else:
            return None
        i = j
    else:
        return None
    if i < n and pattern[i] in "?+":
        i += 1
    return i


def _consume_group_open(pattern: str, start: int) -> tuple[int, bool] | None:
    """Return ``(next_index, pushed_group)`` for ``(`` at ``start``."""
    n = len(pattern)
    if pattern.startswith("(?:", start) or pattern.startswith("(?>", start):
        return start + 3, True
    if pattern.startswith("(?P<", start):
        end = pattern.find(">", start + 4)
        if end <= start + 4:
            return None
        return end + 1, True
    if pattern.startswith(("(?P=", "(?=", "(?!", "(?<=", "(?<!")):
        return None
    if pattern.startswith("(?", start):
        k = start + 2
        while k < n:
            ch = pattern[k]
            if ch == ":":
                return k + 1, True
            if ch == ")":
                return k + 1, False
            if ch not in _REGEX_FLAGS:
                return None
            k += 1
        return None
    return start + 1, True


def regex_pattern_is_safe(pattern: str) -> bool:
    """Conservatively accept regex grants that cannot backtrack catastrophically."""
    if not pattern or len(pattern) > MAX_REGEX_PATTERN_LENGTH:
        return False
    groups: list[_GroupState] = []
    group_count = 0
    quantifiers = 0
    alternations = 0
    in_class = False
    i = 0
    n = len(pattern)

    while i < n:
        ch = pattern[i]
        if in_class:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "\\":
            if i + 1 >= n:
                return False
            if pattern[i + 1] in "123456789":
                return False
            i += 2
            continue
        if ch == "[":
            in_class = True
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            continue
        if ch == "(":
            opened = _consume_group_open(pattern, i)
            if opened is None:
                return False
            i, pushed = opened
            if pushed:
                group_count += 1
                if group_count > MAX_REGEX_GROUPS:
                    return False
                groups.append(_GroupState())
            continue
        if ch == ")":
            if not groups:
                return False
            state = groups.pop()
            quant_end = _consume_quantifier(pattern, i + 1)
            if quant_end is not None:
                if state.has_quantifier or state.has_alternation:
                    return False
                quantifiers += 1
                if quantifiers > MAX_REGEX_QUANTIFIERS:
                    return False
                i = quant_end
            else:
                i += 1
            if groups:
                parent = groups[-1]
                parent.has_quantifier = parent.has_quantifier or state.has_quantifier
                parent.has_alternation = parent.has_alternation or state.has_alternation
                if quant_end is not None:
                    parent.has_quantifier = True
            continue
        if ch == "|":
            alternations += 1
            if alternations > MAX_REGEX_ALTERNATIONS:
                return False
            if groups:
                groups[-1].has_alternation = True
            i += 1
            continue
        quant_end = _consume_quantifier(pattern, i)
        if quant_end is not None:
            quantifiers += 1
            if quantifiers > MAX_REGEX_QUANTIFIERS:
                return False
            if groups:
                groups[-1].has_quantifier = True
            i = quant_end
            continue
        i += 1

    return not (in_class or groups)


def _sbpl_scan(text: str) -> tuple[int, int, tuple[str, ...]]:
    """Return ``(max_depth, final_depth, string_literals)`` for SBPL-ish text."""
    literals: list[str] = []
    buf: list[str] = []
    depth = 0
    max_depth = 0
    state = "normal"
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if state == "comment":
            if ch == "\n":
                state = "normal"
            i += 1
            continue
        if state == "string":
            if ch == "\\" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                literals.append("".join(buf))
                buf = []
                state = "normal"
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if state == "regex":
            if ch == '"':
                literals.append("".join(buf))
                buf = []
                state = "normal"
                i += 1
                continue
            buf.append(ch)
            i += 1
            continue
        if ch == ";":
            state = "comment"
            i += 1
            continue
        if ch == '"':
            state = "string"
            buf = []
            i += 1
            continue
        if ch == "#" and i + 1 < n and text[i + 1] == '"':
            state = "regex"
            buf = []
            i += 2
            continue
        if ch == "(":
            depth += 1
            max_depth = max(max_depth, depth)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth < 0:
                return max_depth, -1, tuple(literals)
            i += 1
            continue
        i += 1
    if buf and state in {"string", "regex"}:
        literals.append("".join(buf))
    return max_depth, depth, tuple(literals)


def sbpl_profile_is_safe(text: str) -> bool:
    """Return False for SBPL text that is malformed or regex-unsafe."""
    max_depth, final_depth, literals = _sbpl_scan(text)
    if final_depth != 0 or max_depth > MAX_SBPL_DEPTH:
        return False
    if "global-name-regex" not in text and "local-name-regex" not in text:
        return True
    return all(regex_pattern_is_safe(literal) for literal in literals)
