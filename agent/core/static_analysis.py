"""Static-confirmed finding support for Slither-only repair flows."""

from __future__ import annotations

from core.vulnerability_catalog import get_catalog_entry


def static_confirmed_findings(normalized_report: dict) -> list[dict]:
    findings = []
    for finding in normalized_report.get("vulnerabilidades", []):
        entry = get_catalog_entry(finding.get("type", ""))
        if entry.get("static_confirmed"):
            findings.append(finding)
    return findings


def static_confirmed_analyses(findings: list[dict]) -> list[dict]:
    return [
        {
            "id": finding.get("id", ""),
            "type": finding.get("type", ""),
            "function": finding.get("function", ""),
            "rule": f"slither:{finding.get('type', '')}",
            "status": "confirmed_static",
            "evidencia": finding.get("description", "Confirmed by Slither."),
        }
        for finding in findings
    ]


def static_plan_entries(findings: list[dict]) -> list[dict]:
    entries = []
    for finding in findings:
        entry = get_catalog_entry(finding.get("type", ""))
        entries.append(
            {
                "id": finding.get("id", ""),
                "type": finding.get("type", ""),
                "function": finding.get("function", ""),
                "line": finding.get("line", ""),
                "rule_names": [f"slither_{finding.get('type', '').replace('-', '_')}"],
                "formal_property": entry.get("property", ""),
                "cvl_strategy": "static_slither_confirmation",
                "required_methods": [],
                "assumptions": [],
                "reason": entry.get("reason", "Confirmed statically by Slither."),
                "evidence": {
                    "elements": finding.get("elements", []),
                    "external_calls": finding.get("external_calls", []),
                    "state_writes_after_calls": finding.get("state_writes_after_calls", []),
                },
                "repair_strategy": entry.get("repair_strategy", ""),
                "target_parameter": finding.get("target_parameter", ""),
            }
        )
    return entries


def append_static_entries_to_plan(plan: dict, findings: list[dict]) -> dict:
    if not findings:
        return plan
    return {
        "selected_rules": plan.get("selected_rules", []) + static_plan_entries(findings),
        "skipped_findings": plan.get("skipped_findings", []),
        "global_assumptions": plan.get("global_assumptions", []),
    }


def _finding_key(finding: dict) -> tuple[str, str]:
    return finding.get("type", ""), finding.get("function", "")


def analyze_static_after_fix(original_findings: list[dict], fixed_report: dict) -> list[dict]:
    fixed_static = static_confirmed_findings(fixed_report)
    fixed_keys = {_finding_key(finding) for finding in fixed_static}
    analyses = []

    for finding in original_findings:
        key = _finding_key(finding)
        persists = key in fixed_keys
        analyses.append(
            {
                "id": finding.get("id", ""),
                "type": finding.get("type", ""),
                "function": finding.get("function", ""),
                "rule": f"slither:{finding.get('type', '')}",
                "status": "confirmed" if persists else "not_confirmed",
                "evidencia": (
                    "Slither still reports this static finding after the fix."
                    if persists
                    else "Slither no longer reports this static finding after the fix."
                ),
            }
        )

    return analyses
