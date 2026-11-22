"""Deterministic bounty-tier estimation for submission packets."""

from __future__ import annotations

from .models import BOUNTY_TIERS

_CRITICAL_TERMS = (
    "kernel",
    "xnu",
    "iokit",
    "sandbox escape",
    "sandbox-escape",
    "zero-click",
    "zero click",
    "remote code execution",
    " arbitrary code execution",
    "tcc",
    "keychain",
    "secure enclave",
    "baseband",
    "privilege escalation",
)
_HIGH_TERMS = (
    "use-after-free",
    "uaf",
    "type confusion",
    "type_confusion",
    "out-of-bounds write",
    "oob_write",
    "arbitrary write",
    "arbitrary read",
    "webkit",
    "javascriptcore",
    "jsc",
    "webcontent",
    "xpc",
    "mach service",
    "sandbox",
)
_MEDIUM_TERMS = (
    "out-of-bounds read",
    "oob_read",
    "info_leak",
    "information leak",
    "uninitialized",
    "null-deref",
    "null deref",
    "denial of service",
    "dos",
)
_STRONG_BUG_CLASSES = {
    "uaf",
    "type confusion",
    "oob write",
    "integer overflow",
    "double free",
    "uninitialized memory",
}
_MEDIUM_BUG_CLASSES = {"oob read", "info leak"}


def _norm(value: str) -> str:
    return " ".join(value.lower().replace("_", " ").replace("-", " ").split())


def _has_term(text: str, terms: tuple[str, ...]) -> bool:
    haystack = f" {_norm(text)} "
    for term in terms:
        needle = f" {_norm(term)} "
        if needle in haystack:
            return True
    return False


def estimate_bounty_tier(
    *,
    explicit_tier: str,
    bug_class: str,
    surface: str,
    component: str,
    exploitability: str,
    impact: str,
    chain_summary: str,
    escalation_summary: str,
) -> tuple[str, str]:
    """Estimate a bounty tier and return ``(tier, rationale)``."""
    candidate = _norm(explicit_tier)
    candidate = candidate.replace(" ", "_")
    if candidate in BOUNTY_TIERS and candidate != "unknown":
        return candidate, "Tier supplied by the promoted claim."

    joined = "\n".join(
        [bug_class, surface, component, exploitability, impact, chain_summary, escalation_summary]
    )
    if not bug_class and impact.strip() in {"", "Impact not established from the promoted claim."}:
        return "unknown", "Insufficient promoted-claim evidence for a bounty-tier estimate."

    score = 0
    reasons: list[str] = []
    bug = _norm(bug_class)
    if bug in _STRONG_BUG_CLASSES:
        score += 3
        reasons.append(f"bug class {bug_class}")
    elif bug in _MEDIUM_BUG_CLASSES:
        score += 2
        reasons.append(f"bug class {bug_class}")

    if _has_term(joined, _CRITICAL_TERMS):
        score += 3
        reasons.append("critical surface or impact terms")
    elif _has_term(joined, _HIGH_TERMS):
        score += 2
        reasons.append("high-value memory-corruption terms")
    elif _has_term(joined, _MEDIUM_TERMS):
        score += 1
        reasons.append("memory-safety terms")

    exploit = _norm(exploitability)
    if "rating: critical" in exploit or "rating: high" in exploit:
        score += 2
        reasons.append("high exploitability rating")
    elif "rating: medium" in exploit:
        score += 1
        reasons.append("medium exploitability rating")
    if any(token in exploit for token in ("arbitrary", "control", "sandbox escape", "privilege")):
        score += 1
        reasons.append("strong primitive language")

    chain_text = chain_summary.strip()
    chain_placeholder = chain_text in {"", "No chain evidence was present in the promoted claim."}
    if not chain_placeholder and _has_term(chain_summary, ("chain", "chained", "multi-stage", "escalat")):
        score += 1
        reasons.append("chain or escalation evidence")

    if score >= 7:
        tier = "critical"
    elif score >= 4:
        tier = "high"
    elif score >= 2:
        tier = "medium"
    else:
        tier = "low"
    rationale = "; ".join(reasons) if reasons else "limited promoted-claim evidence"
    return tier, rationale[:1000]


__all__ = ["estimate_bounty_tier"]
