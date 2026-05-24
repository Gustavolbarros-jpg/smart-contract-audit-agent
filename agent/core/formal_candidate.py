"""Build Certora-oriented candidates from normalized findings."""

from __future__ import annotations


def build_formal_candidates(normalized_report: dict) -> list[dict]:
    candidates = []
    for finding in normalized_report.get("vulnerabilidades", []):
        if not finding.get("formalizable"):
            continue
        if finding.get("function", "").startswith("constructor"):
            continue
        candidates.append(
            {
                "id": finding["id"],
                "type": finding["type"],
                "description": finding.get("description", ""),
                "function": finding.get("function", ""),
                "line": finding.get("line", ""),
                "impact": finding.get("impact", ""),
                "confidence": finding.get("confidence", ""),
                "property": finding.get("propriedade_formal", ""),
                "rule_template": finding.get("padrao_cvl", ""),
                "repair_strategy": finding.get("repair_strategy", ""),
                "target_parameter": finding.get("target_parameter", ""),
                "evidence": {
                    "elements": finding.get("elements", []),
                    "external_calls": finding.get("external_calls", []),
                    "state_writes_after_calls": finding.get("state_writes_after_calls", []),
                },
            }
        )
    return candidates
