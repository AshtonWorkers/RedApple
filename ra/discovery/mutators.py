"""Grammar-aware JavaScript mutation operators for JSC discovery.

The operators are deliberately dependency-free: they use token/literal masks so
strings and comments are not rewritten as code, while still producing the kind
of edge-case JS that stresses JSC's parser, DFG/FTL tiers, GC, and builtins.
"""

from __future__ import annotations

import bisect
import json
import random
import re
from collections.abc import Callable, Sequence
from enum import StrEnum

SPICY: tuple[str, ...] = (
    "gc()",
    "edenGC()",
    "fullGC()",
    "new ArrayBuffer(0x1000)",
    "new Float64Array(0x100)",
    "new Uint8Array(1000).fill(0x41)",
    "[].length = 0xffffffff",
    "new Array(0xffffff)",
    "Array.prototype.sort.call({length: 1e7})",
    "Object.defineProperty(a, 'length', {value: -1})",
    "a.__proto__ = b",
    "Reflect.apply(f, null, a)",
    "a.concat(a, a, a)",
    "new Proxy(a, {get(){ return a; }})",
    "a.splice(0, -1, ...a)",
    "function f(){ return f.apply(null, arguments); }",
    "transferArrayBuffer(ab)",
    "a.fill(1.1).sort()",
    "valueOf: function(){ a.length = 0; return 1; }",
    "with(a){}",
    "eval('a'.repeat(1e4))",
    "a[Symbol.species] = Array",
    "new Uint8Array(ab, -1)",
    "ab.resize(0)",
    "structuredClone(a)",
    "Atomics.store(new Int32Array(new SharedArrayBuffer(16)), 0, 1)",
)

TOKENS: tuple[str, ...] = (
    "a",
    "b",
    "f",
    "ab",
    "0",
    "-1",
    "0x7fffffff",
    "1.1",
    "null",
    "undefined",
    "{}",
    "[]",
    "()=>{}",
    "...a",
    "new.target",
    "this",
    "arguments",
)

WRAPPERS: tuple[str, ...] = (
    "for (let i=0;i<1000;i++){{\n{}\n}}",
    "try{{\n{}\n}}catch(e){{}}",
    "function g(){{\n{}\n}} for(let i=0;i<100;i++) g();",
    "(function(){{\n{}\n}})();",
    "for (let i=0;i<50000;i++){{\ntry{{\n{}\n}}catch(e){{}}\n}}",
)

EDGE_NUMBERS: tuple[str, ...] = (
    "0",
    "-0",
    "1",
    "-1",
    "2",
    "0x7fffffff",
    "0x80000000",
    "0xffffffff",
    "2147483647",
    "2147483648",
    "4294967295",
    "4294967296",
    "Number.MAX_SAFE_INTEGER",
    "Number.MIN_SAFE_INTEGER",
    "Number.MAX_VALUE",
    "Number.MIN_VALUE",
    "Number.NaN",
    "Number.POSITIVE_INFINITY",
    "1e-323",
    "1e308",
    "1.1",
    "2n",
    "1024n",
)

EDGE_STRINGS: tuple[str, ...] = (
    "",
    "A",
    "AAAA",
    "0",
    "-1",
    "length",
    "constructor",
    "__proto__",
    "prototype",
    "Symbol.species",
    "\\u0000",
    "\\ud800",
    "A" * 64,
    "A" * 1024,
)

IDENTIFIERS: tuple[str, ...] = (
    "a",
    "b",
    "c",
    "tmp",
    "obj",
    "arr",
    "buf",
    "fn",
    "cb",
    "x",
    "y",
    "z",
    "ev",
    "p",
    "q",
)

JS_BUILTIN_SNIPPETS: tuple[str, ...] = (
    "Array.prototype.sort.call(a);",
    "Array.prototype.reverse.call(a);",
    "a.copyWithin(0, -1);",
    "a.fill(1.1, -1);",
    "a.splice(0, 1, 2.2, 3.3);",
    "a.concat(a, a, a);",
    "Array.prototype.slice.call(a, -1);",
    "Array.prototype.indexOf.call(a, 1.1);",
    "Array.prototype.lastIndexOf.call(a, 1.1);",
    "Array.prototype.includes.call(a, 1.1);",
    "new Uint8Array(ab).set(a);",
    "new Float64Array(ab).fill(NaN);",
    "Object.defineProperty(a, 'length', {value: -1});",
    "Object.defineProperty(a, Symbol.species, {value: Array});",
    "Reflect.apply(f, null, a);",
    "a.__proto__ = b;",
    "a[Symbol.species] = Array;",
    "a.length = 0xffffffff;",
    "a.length = -1;",
    "Array.prototype.sort.call({length: 1e7});",
)

GC_SNIPPETS: tuple[str, ...] = (
    "gc();",
    "edenGC();",
    "fullGC();",
    "gc({type:'minor'});",
    "gc({type:'major'});",
    "drainMicrotasks();",
)

_OPERATOR_ALTERNATIVES: dict[str, tuple[str, ...]] = {
    "+": ("-", "*", "/", "%", "|", "^", "&"),
    "-": ("+", "*", "/", "%", "|", "^", "&"),
    "*": ("+", "-", "/", "%", "**"),
    "/": ("+", "-", "*", "%"),
    "%": ("+", "-", "*", "/"),
    "<": (">", "<=", ">=", "==", "==="),
    ">": ("<", "<=", ">=", "==", "==="),
    "<=": (">=", "<", ">", "==", "==="),
    ">=": ("<=", ">", "<", "==", "==="),
    "==": ("===", "!=", "!==", "<", ">"),
    "===": ("==", "!==", "!=", "<", ">"),
    "!=": ("!==", "==", "===", "<", ">"),
    "!==": ("!=", "==", "===", "<", ">"),
    "&&": ("||", "&", "|", "??"),
    "||": ("&&", "|", "&", "??"),
    "&": ("|", "^", "&&", "||"),
    "|": ("&", "^", "&&", "||"),
    "^": ("&", "|", "&&", "||"),
    "??": ("||", "&&", "|", "&"),
    "**": ("*", "/", "%", "+"),
    "<<": (">>", ">>>", "+", "-"),
    ">>": ("<<", ">>>", "+", "-"),
    ">>>": ("<<", ">>", "+", "-"),
}

GRAMMAR_SOURCE_LIMIT = 250_000
DEFAULT_MINIMIZATION_ATTEMPTS = 32
MUTATION_KIND_NAMES: tuple[str, ...] = (
    "legacy_line",
    "identifier",
    "number",
    "string",
    "operator",
    "builtin_call",
    "gc_stress",
    "jit_warmup",
    "wrapper",
)


class MutationKind(StrEnum):
    """Named mutation strategy used for deterministic scheduling."""

    LEGACY_LINE = "legacy_line"
    IDENTIFIER = "identifier"
    NUMBER = "number"
    STRING = "string"
    OPERATOR = "operator"
    BUILTIN_CALL = "builtin_call"
    GC_STRESS = "gc_stress"
    JIT_WARMUP = "jit_warmup"
    WRAPPER = "wrapper"


_MUTATION_WEIGHTS: tuple[tuple[MutationKind, int], ...] = (
    (MutationKind.LEGACY_LINE, 24),
    (MutationKind.IDENTIFIER, 13),
    (MutationKind.NUMBER, 13),
    (MutationKind.STRING, 8),
    (MutationKind.OPERATOR, 11),
    (MutationKind.BUILTIN_CALL, 11),
    (MutationKind.GC_STRESS, 5),
    (MutationKind.JIT_WARMUP, 9),
    (MutationKind.WRAPPER, 6),
)

_LITERAL_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`",
    re.S,
)
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_STRING_RE = re.compile(r"\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`", re.S)
_IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_NUMBER_RE = re.compile(
    r"(?<![\w$.])(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[nN]?)(?![\w$])"
)
_OPERATOR_RE = re.compile(
    r"===|!==|>>>|<<=|>>=|&&|\|\||\*\*|==|!=|<=|>=|=>|\+\+|--|<<|>>|\+=|-=|\*=|/=|%=|&=|\|=|\^=|"
    r"[-+*/%<>=!&|^]"
)
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)")
_ARROW_RE = re.compile(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>")

_RESERVED_WORDS = frozenset(
    {
        "await",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "undefined",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "let",
        "static",
        "get",
        "set",
        "of",
        "async",
    }
)

MutationFn = Callable[[str, random.Random], str]


def legacy_mutate(source: str, rng: random.Random) -> str:
    """PR #3 line-oriented mutation operator mix."""
    lines = source.splitlines() or [""]
    op = rng.random()
    if op < 0.3:  # splice a spicy fragment
        lines.insert(rng.randrange(len(lines) + 1), rng.choice(SPICY) + ";")
    elif op < 0.5:  # duplicate a line
        i = rng.randrange(len(lines))
        lines.insert(i, lines[i])
    elif op < 0.65:  # drop a line
        if len(lines) > 1:
            lines.pop(rng.randrange(len(lines)))
    elif op < 0.8:  # token substitution
        i = rng.randrange(len(lines))
        lines[i] = lines[i] + " " + rng.choice(TOKENS) + ";"
    else:  # wrap in aggressive construct
        body = "\n".join(lines)
        return rng.choice(WRAPPERS).format(body)
    return "\n".join(lines)


def _literal_spans(source: str) -> tuple[list[tuple[int, int]], list[int]]:
    spans = [match.span() for match in _LITERAL_RE.finditer(source)]
    return spans, [start for start, _end in spans]


def _in_spans(pos: int, spans: list[tuple[int, int]], starts: list[int]) -> bool:
    index = bisect.bisect_right(starts, pos) - 1
    return index >= 0 and spans[index][0] <= pos < spans[index][1]


def _comment_spans(source: str) -> tuple[list[tuple[int, int]], list[int]]:
    spans = [match.span() for match in _COMMENT_RE.finditer(source)]
    return spans, [start for start, _end in spans]


def _code_match(
    source: str,
    pattern: re.Pattern[str],
    rng: random.Random,
    spans: list[tuple[int, int]],
    starts: list[int],
) -> re.Match[str] | None:
    matches = [m for m in pattern.finditer(source) if not _in_spans(m.start(), spans, starts)]
    if not matches:
        return None
    return rng.choice(matches)


def _replace(source: str, match: re.Match[str], replacement: str) -> str:
    return f"{source[: match.start()]}{replacement}{source[match.end() :]}"


def _insert_at_line(source: str, snippet: str, rng: random.Random) -> str:
    lines = source.splitlines()
    if not lines:
        return f"{snippet}\n"
    index = rng.randrange(len(lines) + 1)
    lines.insert(index, snippet)
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def mutate_identifier(source: str, rng: random.Random) -> str:
    """Rename one non-reserved, non-property identifier."""
    spans, starts = _literal_spans(source)
    candidates: list[re.Match[str]] = []
    for match in _IDENT_RE.finditer(source):
        if _in_spans(match.start(), spans, starts):
            continue
        word = match.group(0)
        if word in _RESERVED_WORDS:
            continue
        if match.start() > 0 and source[match.start() - 1] == ".":
            continue
        candidates.append(match)
    if not candidates:
        return source
    match = rng.choice(candidates)
    replacement = rng.choice(IDENTIFIERS)
    if replacement == match.group(0):
        replacement = "__ra_mut"
    return _replace(source, match, replacement)


def mutate_number(source: str, rng: random.Random) -> str:
    """Replace one numeric literal with a JSC edge value."""
    spans, starts = _literal_spans(source)
    match = _code_match(source, _NUMBER_RE, rng, spans, starts)
    if match is None:
        return source
    choices = [value for value in EDGE_NUMBERS if value != match.group(0)] or list(EDGE_NUMBERS)
    return _replace(source, match, rng.choice(choices))


def mutate_string(source: str, rng: random.Random) -> str:
    """Replace one string/template literal with an edge string."""
    comment_spans, comment_starts = _comment_spans(source)
    matches = [
        match
        for match in _STRING_RE.finditer(source)
        if not _in_spans(match.start(), comment_spans, comment_starts)
    ]
    if not matches:
        return f"var __ra_string = {json.dumps(rng.choice(EDGE_STRINGS))};\n{source}"
    match = rng.choice(matches)
    replacement = json.dumps(rng.choice(EDGE_STRINGS))
    return _replace(source, match, replacement)


def mutate_operator(source: str, rng: random.Random) -> str:
    """Swap one JavaScript operator for a neighboring edge operator."""
    spans, starts = _literal_spans(source)
    match = _code_match(source, _OPERATOR_RE, rng, spans, starts)
    if match is None:
        return source
    op = match.group(0)
    alternatives = _OPERATOR_ALTERNATIVES.get(op)
    if not alternatives:
        return source
    choices = [value for value in alternatives if value != op] or list(alternatives)
    return _replace(source, match, rng.choice(choices))


def mutate_builtin_call(source: str, rng: random.Random) -> str:
    """Insert one builtin/edge API call at a random line boundary."""
    return _insert_at_line(source, rng.choice(JS_BUILTIN_SNIPPETS), rng)


def mutate_gc_stress(source: str, rng: random.Random) -> str:
    """Insert GC/heap-pressure calls to expose lifetime bugs."""
    return _insert_at_line(source, rng.choice(GC_SNIPPETS), rng)


def mutate_jit_warmup(source: str, rng: random.Random) -> str:
    """Wrap a discovered function in a deterministic JIT warm-up loop."""
    spans, starts = _literal_spans(source)
    names = [match.group(1) for match in _FUNCTION_RE.finditer(source) if not _in_spans(match.start(), spans, starts)]
    if not names:
        names = [match.group(1) for match in _ARROW_RE.finditer(source) if not _in_spans(match.start(), spans, starts)]
    name = rng.choice(names) if names else "__ra_target"
    warmup = (
        "function __ra_target(a, b) { var s = 0; for (var i = 0; i < (a && a.length) || 8; i++) "
        "s += (a && a[i]) || b; return s; }\n"
        f"for (let __ra_warm = 0; __ra_warm < 50000; __ra_warm++) {{\n"
        f"  try {{ {name}(1.1, 2.2, [1, 2, 3], ab); }} catch (e) {{}}\n"
        "}\n"
    )
    if name == "__ra_target":
        return warmup + source
    return f"{source}\n{warmup}"


def mutate_wrapper(source: str, rng: random.Random) -> str:
    """Wrap the whole program in an aggressive execution context."""
    body = "\n".join(source.splitlines())
    return rng.choice(WRAPPERS).format(body)


_MUTATORS: tuple[tuple[MutationKind, MutationFn, int], ...] = (
    (MutationKind.LEGACY_LINE, legacy_mutate, 24),
    (MutationKind.IDENTIFIER, mutate_identifier, 13),
    (MutationKind.NUMBER, mutate_number, 13),
    (MutationKind.STRING, mutate_string, 8),
    (MutationKind.OPERATOR, mutate_operator, 11),
    (MutationKind.BUILTIN_CALL, mutate_builtin_call, 11),
    (MutationKind.GC_STRESS, mutate_gc_stress, 5),
    (MutationKind.JIT_WARMUP, mutate_jit_warmup, 9),
    (MutationKind.WRAPPER, mutate_wrapper, 6),
)

_MUTATOR_BY_NAME: dict[str, MutationFn] = {kind.value: fn for kind, fn, _weight in _MUTATORS}
_MUTATION_WEIGHTS_BY_NAME: dict[str, int] = {kind.value: weight for kind, _fn, weight in _MUTATORS}


def _selected_mutators(kinds: Sequence[str] | None) -> tuple[tuple[str, MutationFn, int], ...]:
    if kinds is None:
        return tuple((kind.value, fn, weight) for kind, fn, weight in _MUTATORS)
    wanted = set(kinds)
    unknown = sorted(wanted - set(MUTATION_KIND_NAMES))
    if unknown:
        raise ValueError(f"unknown mutation kinds: {', '.join(unknown)}")
    selected = tuple(
        (kind.value, fn, weight)
        for kind, fn, weight in _MUTATORS
        if kind.value in wanted
    )
    if not selected:
        raise ValueError("mutation kinds selected no operators")
    return selected


def _weighted_mutator(
    mutators: tuple[tuple[str, MutationFn, int], ...], rng: random.Random
) -> MutationFn:
    total = sum(weight for _name, _fn, weight in mutators)
    pick = rng.random() * total
    upto = 0.0
    for _name, fn, weight in mutators:
        upto += weight
        if pick < upto:
            return fn
    return mutators[-1][1]


def mutate_program(
    source: str,
    rng: random.Random,
    *,
    kinds: Sequence[str] | None = None,
    max_attempts: int = 8,
) -> str:
    """Apply one weighted mutation strategy, falling back to legacy line ops.

    Large inputs use only the line-oriented operator so grammar scans stay
    bounded; malformed inputs simply miss grammar matches and fall through.
    """
    if not isinstance(source, str):
        raise TypeError("source must be str")
    mutators = _selected_mutators(kinds)
    if len(source) > GRAMMAR_SOURCE_LIMIT:
        return legacy_mutate(source, rng)
    for _attempt in range(max(1, max_attempts)):
        candidate = _weighted_mutator(mutators, rng)(source, rng)
        if candidate != source:
            return candidate
    return legacy_mutate(source, rng)


def mutate(source: str, rng: random.Random) -> str:
    """Backward-compatible PR #3 mutation entry point."""
    return legacy_mutate(source, rng)
