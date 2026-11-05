"""Which contract of a multi-contract file the pipeline should verify."""

from __future__ import annotations

import re
from collections import Counter

from core.vulnerability_catalog import get_catalog_entry


# Harness and exploit code (ContractTest, EtherStoreAttack, ExploitContract) and the already-fixed
# copy a tutorial ships beside the vulnerable one are never what should be verified.
_NOT_THE_TARGET = re.compile(r"attack|exploit|hack|test|fixed|remediat", re.IGNORECASE)


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
        names = {name for name in names if not _NOT_THE_TARGET.search(name)}
        counts.update(names)
    if not counts:
        return ""
    best = max(counts.values())
    leaders = [name for name, count in counts.items() if count == best]
    return leaders[0] if len(leaders) == 1 else ""
