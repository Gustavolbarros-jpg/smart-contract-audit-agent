"""Token-efficient context and safeguards for LLM diagnosis."""

from __future__ import annotations


def compact_certora_log(log: str, rules: list[str], max_lines: int = 140) -> str:
    """Keep only Certora lines that matter for the selected rules."""
    rule_names = [rule for rule in rules if rule]
    keywords = (
        "Result for",
        "Verified:",
        "Violated:",
        "Failures summary",
        "Results for all",
        "CRITICAL:",
        "ERROR",
        "FAIL",
        "SUCCESS",
        "SANITY",
    )
    selected = []

    for line in log.splitlines():
        if any(keyword in line for keyword in keywords) or any(rule in line for rule in rule_names):
            selected.append(line)

    if not selected:
        selected = log.splitlines()[-max_lines:]

    if len(selected) > max_lines:
        selected = selected[-max_lines:]

    return "\n".join(selected)


def filter_plan_by_ids(plan: dict, vuln_ids: set[str]) -> dict:
    return {
        "selected_rules": [
            item for item in plan.get("selected_rules", [])
            if item.get("id") in vuln_ids
        ],
        "skipped_findings": [
            item for item in plan.get("skipped_findings", [])
            if item.get("id") in vuln_ids
        ],
        "global_assumptions": plan.get("global_assumptions", []),
    }


def sanitize_diagnosis_ids(diagnosis: dict, allowed_ids: set[str]) -> dict:
    """Drop hallucinated or stale vulnerability IDs from LLM diagnosis."""
    filtered = []
    seen = set()
    for failure in diagnosis.get("falhas", []):
        vuln_id = failure.get("id", "")
        if vuln_id not in allowed_ids or vuln_id in seen:
            continue
        seen.add(vuln_id)
        filtered.append(failure)
    return {"falhas": filtered}
