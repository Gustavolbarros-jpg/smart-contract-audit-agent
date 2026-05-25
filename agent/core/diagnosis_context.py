"""Token-efficient context and safeguards for LLM diagnosis."""

from __future__ import annotations


def compact_certora_log(log: str, rules: list[str], max_lines: int = 140) -> str:
    """Keep only Certora lines that matter for the selected rules."""
    rule_names = [rule for rule in rules if rule]
    selected = []

    for line in log.splitlines():
        stripped = line.strip()
        rule_line = any(rule in line for rule in rule_names)
        if (
            not rule_line
            and (
                "envfreeFuncsStaticCheck" in line
                or "SUCCESS" in line
                or "Verified:" in line
            )
        ):
            continue
        if rule_line:
            if (
                stripped.startswith("Result for")
                or stripped.startswith("Violated:")
                or stripped.startswith("Failed on")
                or ("|Violated" in line)
            ):
                selected.append(line)
            continue

        if "Failures summary" in line or "CRITICAL:" in line:
            selected.append(line)
            continue

        if "ERROR" in line and "exitcode 100" not in line:
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


def compact_plan_for_diagnosis(plan: dict) -> dict:
    """Keep only fields needed to explain and repair confirmed findings."""
    selected = []
    fields = (
        "id",
        "type",
        "function",
        "line",
        "rule_names",
        "repair_strategy",
        "target_parameter",
    )
    for item in plan.get("selected_rules", []):
        selected.append({key: item[key] for key in fields if key in item and item[key]})

    skipped = []
    for item in plan.get("skipped_findings", []):
        skipped.append(
            {
                key: item[key]
                for key in ("id", "type", "function", "reason")
                if key in item and item[key]
            }
        )

    return {
        "selected_rules": selected,
        "skipped_findings": skipped,
    }


def compact_confirmed_analyses(analyses: list[dict]) -> list[dict]:
    """Reduce Certora/static analysis rows before sending them to the LLM."""
    compact = []
    fields = ("id", "type", "function", "rule", "status")
    for item in analyses:
        row = {key: item[key] for key in fields if key in item and item[key]}
        evidence = item.get("evidencia", "")
        if evidence and item.get("status") == "confirmed_static":
            row["evidence"] = evidence[:180]
        compact.append(row)
    return compact


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
