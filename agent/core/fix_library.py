"""Persistent JSON store of successful fix patterns for few-shot prompting."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

LIBRARY_PATH = Path(__file__).resolve().parents[2] / "runs" / "fix_library.json"

_EMPTY_LIBRARY: dict = {"version": 1, "patterns": []}


def load_library() -> dict:
    """Load the fix library JSON, return empty structure if missing or corrupt."""
    if not LIBRARY_PATH.exists():
        return {"version": 1, "patterns": []}
    try:
        with LIBRARY_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict) or "patterns" not in data:
            return {"version": 1, "patterns": []}
        return data
    except Exception:
        return {"version": 1, "patterns": []}


def save_pattern(
    vuln_type: str,
    repair_strategy: str,
    function_signature: str,
    fix_snippet: str,
    contract_name: str,
    run_id: str,
) -> None:
    """Append a new successful fix pattern to the library, avoiding exact duplicates."""
    if not vuln_type or not fix_snippet:
        return

    library = load_library()
    patterns: list[dict] = library.setdefault("patterns", [])

    # Avoid saving the exact same snippet for the same type twice
    for existing in patterns:
        if (
            existing.get("vuln_type") == vuln_type
            and existing.get("fix_snippet") == fix_snippet
        ):
            return

    patterns.append(
        {
            "vuln_type": vuln_type,
            "repair_strategy": repair_strategy,
            "function_signature": function_signature,
            "fix_snippet": fix_snippet,
            "contract_name": contract_name,
            "run_id": run_id,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
        }
    )

    LIBRARY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LIBRARY_PATH.open("w", encoding="utf-8") as fh:
        json.dump(library, fh, indent=2, ensure_ascii=False)


def get_examples_for_prompt(vuln_types: list[str], max_per_type: int = 2) -> str:
    """Return a formatted string with few-shot examples for the given vuln types.

    Returns empty string if no relevant examples exist.
    """
    if not vuln_types:
        return ""

    library = load_library()
    patterns: list[dict] = library.get("patterns", [])
    if not patterns:
        return ""

    requested = {t for t in vuln_types if t}
    by_type: dict[str, list[dict]] = {}
    for pat in patterns:
        t = pat.get("vuln_type", "")
        if t in requested:
            by_type.setdefault(t, []).append(pat)

    if not by_type:
        return ""

    lines = ["SUCCESSFUL FIX PATTERNS FROM PREVIOUS RUNS:"]
    for vuln_type, examples in by_type.items():
        for pat in examples[-max_per_type:]:
            fn_sig = pat.get("function_signature", "")
            contract = pat.get("contract_name", "")
            snippet = pat.get("fix_snippet", "")
            lines.append(f"[{vuln_type}] Contract {contract}, function {fn_sig}")
            lines.append(f"  Fix applied: {snippet}")

    return "\n".join(lines)
