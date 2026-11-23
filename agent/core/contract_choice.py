"""Which contract of a multi-contract file the pipeline should verify."""

from __future__ import annotations

import re
from collections import Counter

from core.solidity_source import mask_comments_and_strings, matching_brace
from core.vulnerability_catalog import get_catalog_entry


# Words that mark a contract as test harness, exploit code, a mock or an already-fixed copy that a
# tutorial ships beside the vulnerable one. Compared by whole words of the CamelCase name, so a real
# contract such as "Attestation" is not taken for a "test".
_HARNESS_WORDS = {
    "test", "tests", "attack", "attacker", "exploit", "exploiter", "hack", "hacker", "poc",
    "fixed", "remediated", "mock",
}


def is_harness_contract(name: str) -> bool:
    words = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", name)
    return any(word.lower() in _HARNESS_WORDS for word in words)


def _contract_of(element: dict) -> str:
    """Name of the contract an element of a Slither detector belongs to."""
    node = element
    while isinstance(node, dict):
        if node.get("type") == "contract":
            return node.get("name", "")
        node = node.get("type_specific_fields", {}).get("parent")
    return ""


def contract_with_most_critical_findings(slither_raw: dict) -> str:
    """The contract holding the most findings that can be formalized or confirmed statically.

    A file such as a tutorial often holds the vulnerable contract, a fixed copy and the exploit
    ("Attack"); picking by position verifies the wrong one, and counting every contract picks the
    test harness, whose exploit code has the most flagged calls. Returns "" when no such finding names
    a contract, so the caller keeps its own choice.
    """
    counts: Counter[str] = Counter()
    for detector in slither_raw.get("results", {}).get("detectors", []):
        entry = get_catalog_entry(detector.get("check", ""))
        if not (entry.get("formalizable") or entry.get("static_confirmed")):
            continue
        names = {_contract_of(e) for e in detector.get("elements", []) if isinstance(e, dict)} - {""}
        names = {name for name in names if not is_harness_contract(name)}
        counts.update(names)
    if not counts:
        return ""
    best = max(counts.values())
    leaders = [name for name, count in counts.items() if count == best]
    return leaders[0] if len(leaders) == 1 else ""


def blank_harness_contracts(source: str) -> str:
    """``source`` with the body of every harness contract replaced by spaces, keeping line breaks.

    The normalizer's text-based fallbacks know nothing about contracts, so without this they report
    the exploit's own calls. Line numbers of what remains are unchanged.
    """
    masked = mask_comments_and_strings(source)
    out = list(source)
    for match in re.finditer(r"\b(?:abstract\s+)?contract\s+(\w+)[^{;]*\{", masked):
        if not is_harness_contract(match.group(1)):
            continue
        brace = match.end() - 1
        end = matching_brace(masked, brace)
        for i in range(brace + 1, end):
            if out[i] != "\n":
                out[i] = " "
    return "".join(out)
