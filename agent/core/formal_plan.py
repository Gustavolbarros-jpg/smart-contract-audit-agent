"""Helpers for the LLM-driven formalization planning step."""

from __future__ import annotations

import re


FORCED_FORMAL_TYPES = {"missing-zero-check", "tx-origin", "suicidal"}


def _truncate(value: str, limit: int = 700) -> str:
    if not value:
        return ""
    value = value.strip()
    return value if len(value) <= limit else value[: limit - 3].rstrip() + "..."


def _compact_evidence(evidence: dict) -> dict:
    return {
        "elements": evidence.get("elements", [])[:8],
        "external_calls": evidence.get("external_calls", [])[:5],
        "state_writes_after_calls": evidence.get("state_writes_after_calls", [])[:5],
    }


def build_planner_input(candidates: list[dict]) -> list[dict]:
    """Keep the LLM input small while preserving the evidence it needs."""
    compact = []
    for candidate in candidates:
        compact.append(
            {
                "id": candidate.get("id", ""),
                "type": candidate.get("type", ""),
                "function": candidate.get("function", ""),
                "line": candidate.get("line", ""),
                "impact": candidate.get("impact", ""),
                "confidence": candidate.get("confidence", ""),
                "description": _truncate(candidate.get("description", "")),
                "property": candidate.get("property", ""),
                "rule_template": candidate.get("rule_template", ""),
                "repair_strategy": candidate.get("repair_strategy", ""),
                "target_parameter": candidate.get("target_parameter", ""),
                "evidence": _compact_evidence(candidate.get("evidence", {})),
            }
        )
    return compact


def _safe_identifier(raw: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", raw or "").strip("_")
    name = re.sub(r"_+", "_", name)
    if not name:
        name = "rule"
    if name[0].isdigit():
        name = f"rule_{name}"
    return name


def _default_rule_name(candidate: dict) -> str:
    template = candidate.get("rule_template") or candidate.get("type") or "finding"
    function = candidate.get("function") or "contract"
    function = function.split("(")[0].split(".")[-1]
    return _safe_identifier(f"{template}_{function}")


def _unique_rule_names(rule_names: list[str], candidate: dict, used: set[str]) -> list[str]:
    cleaned = [_safe_identifier(name) for name in rule_names if name]
    if not cleaned:
        cleaned = [_default_rule_name(candidate)]

    unique = []
    for name in cleaned:
        candidate_name = name
        suffix = 2
        while candidate_name in used:
            candidate_name = f"{name}_{suffix}"
            suffix += 1
        used.add(candidate_name)
        unique.append(candidate_name)
    return unique


def _selected_entry(item: dict, candidate: dict, used_rules: set[str]) -> dict:
    return {
        "id": candidate.get("id", ""),
        "type": candidate.get("type", ""),
        "function": candidate.get("function", ""),
        "line": candidate.get("line", ""),
        "rule_names": _unique_rule_names(item.get("rule_names", []), candidate, used_rules),
        "formal_property": item.get("formal_property") or candidate.get("property", ""),
        "cvl_strategy": item.get("cvl_strategy") or candidate.get("rule_template", ""),
        "required_methods": item.get("required_methods", []),
        "assumptions": item.get("assumptions", []),
        "reason": item.get("reason", ""),
        "evidence": candidate.get("evidence", {}),
        "repair_strategy": candidate.get("repair_strategy", ""),
        "target_parameter": candidate.get("target_parameter", ""),
    }


def _forced_item(candidate: dict) -> dict:
    return {
        "id": candidate.get("id", ""),
        "rule_names": [_default_rule_name(candidate)],
        "formal_property": candidate.get("property", ""),
        "cvl_strategy": candidate.get("rule_template", ""),
        "required_methods": [candidate.get("function", "").split("(")[0]]
        if candidate.get("function") and candidate.get("function") != "modifier/function"
        else [],
        "assumptions": [],
        "reason": "Selected by deterministic formalization policy.",
    }


def sanitize_formal_plan(plan: dict, candidates: list[dict]) -> dict:
    """Validate the LLM plan against deterministic candidates and keep exact IDs."""
    candidate_by_id = {candidate.get("id"): candidate for candidate in candidates}
    selected = []
    used_rules: set[str] = set()
    selected_ids: set[str] = set()

    for item in plan.get("selected_rules", []):
        vuln_id = item.get("id", "")
        candidate = candidate_by_id.get(vuln_id)
        if not candidate or vuln_id in selected_ids:
            continue

        selected_ids.add(vuln_id)
        selected.append(_selected_entry(item, candidate, used_rules))

    for candidate in candidates:
        vuln_id = candidate.get("id", "")
        if vuln_id in selected_ids:
            continue
        if candidate.get("type", "") not in FORCED_FORMAL_TYPES:
            continue
        selected_ids.add(vuln_id)
        selected.append(_selected_entry(_forced_item(candidate), candidate, used_rules))

    skipped = []
    skipped_ids = set()
    for item in plan.get("skipped_findings", []):
        vuln_id = item.get("id", "")
        if vuln_id in candidate_by_id and vuln_id not in selected_ids and vuln_id not in skipped_ids:
            skipped_ids.add(vuln_id)
            skipped.append(
                {
                    "id": vuln_id,
                    "type": candidate_by_id[vuln_id].get("type", ""),
                    "reason": item.get("reason", "Skipped by formal planner."),
                }
            )

    for vuln_id, candidate in candidate_by_id.items():
        if vuln_id not in selected_ids and vuln_id not in skipped_ids:
            skipped.append(
                {
                    "id": vuln_id,
                    "type": candidate.get("type", ""),
                    "reason": "Not selected by formal planner.",
                }
            )

    return {
        "selected_rules": selected,
        "skipped_findings": skipped,
        "global_assumptions": plan.get("global_assumptions", []),
    }


def build_spec_plan_input(plan: dict) -> dict:
    """Remove bulky evidence before asking the LLM to generate CVL."""
    return {
        "selected_rules": [
            {
                "id": item.get("id", ""),
                "type": item.get("type", ""),
                "function": item.get("function", ""),
                "line": item.get("line", ""),
                "rule_names": item.get("rule_names", []),
                "formal_property": item.get("formal_property", ""),
                "cvl_strategy": item.get("cvl_strategy", ""),
                "required_methods": item.get("required_methods", []),
                "assumptions": item.get("assumptions", []),
                "repair_strategy": item.get("repair_strategy", ""),
                "target_parameter": item.get("target_parameter", ""),
            }
            for item in plan.get("selected_rules", [])
        ],
        "skipped_findings": plan.get("skipped_findings", []),
        "global_assumptions": plan.get("global_assumptions", []),
    }
