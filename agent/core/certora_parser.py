"""Deterministic Certora log parsing.

The parser extracts rule outcomes directly from Certora logs so the LLM does
not need to decide whether a rule passed or failed.
"""

from __future__ import annotations

import re
from collections import defaultdict


IGNORED_RULE_FRAGMENTS = ("rule_not_vacuous", "envfreeFuncsStaticCheck")


def normalize_rule_name(rule: str) -> str:
    return rule.split("-rule_not_vacuous")[0].split("-sanity")[0].strip()


def _should_ignore(rule: str) -> bool:
    return any(fragment in rule for fragment in IGNORED_RULE_FRAGMENTS)


def extract_rule_vuln_map(spec_text: str) -> dict[str, list[str]]:
    """Map VULN_XXX ids to rule names from comments immediately before rules."""
    mapping: dict[str, list[str]] = defaultdict(list)
    pending_vuln = None

    for line in spec_text.splitlines():
        vuln_match = re.search(r"\b(VULN_\d{3})\b", line)
        if vuln_match:
            pending_vuln = vuln_match.group(1)
            continue

        rule_match = re.match(r"\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)", line)
        if rule_match and pending_vuln:
            mapping[pending_vuln].append(rule_match.group(1))
            pending_vuln = None

    return dict(mapping)


def parse_rule_outcomes(log: str) -> dict[str, dict[str, str]]:
    """Return normalized rule outcomes keyed by rule name."""
    outcomes: dict[str, dict[str, str]] = {}

    for match in re.finditer(r"Verified:\s+([A-Za-z_][A-Za-z0-9_-]*)", log):
        rule = normalize_rule_name(match.group(1))
        if not _should_ignore(rule):
            outcomes[rule] = {"status": "not_confirmed", "evidence": f"Verified: {rule}"}

    for match in re.finditer(r"Violated:\s+([A-Za-z_][A-Za-z0-9_-]*)", log):
        rule = normalize_rule_name(match.group(1))
        if not _should_ignore(rule):
            outcomes[rule] = {"status": "confirmed", "evidence": f"Violated: {rule}"}

    # Result lines are more authoritative than early progress lines.
    result_re = re.compile(
        r"Result for\s+([A-Za-z_][A-Za-z0-9_-]*):\s+"
        r"([A-Za-z_][A-Za-z0-9_-]*):\s+([A-Z_]+|FAIL:[^\n]+)"
    )
    for match in result_re.finditer(log):
        raw_rule = match.group(1)
        rule = normalize_rule_name(raw_rule)
        if _should_ignore(raw_rule):
            continue

        result = match.group(3)
        if result.startswith("SUCCESS"):
            status = "not_confirmed"
        elif result.startswith("FAIL"):
            status = "confirmed"
        elif result.startswith("SANITY_FAIL"):
            status = "inconclusive"
        else:
            status = "inconclusive"

        outcomes[rule] = {
            "status": status,
            "evidence": f"Result for {rule}: {result}",
        }

    return outcomes


def analyze_certora_log(log: str, vulnerabilities: list[dict], spec_text: str) -> dict:
    rule_map = extract_rule_vuln_map(spec_text)
    outcomes = parse_rule_outcomes(log)
    analyses = []

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")
        rules = rule_map.get(vuln_id, [])

        if not rules:
            analyses.append(
                {
                    "id": vuln_id,
                    "type": vuln.get("type", ""),
                    "function": vuln.get("function", ""),
                    "rule": "",
                    "status": "inconclusive",
                    "evidencia": "No CVL rule mapped for this finding.",
                }
            )
            continue

        matched = [(rule, outcomes.get(rule)) for rule in rules if outcomes.get(rule)]
        if not matched:
            analyses.append(
                {
                    "id": vuln_id,
                    "type": vuln.get("type", ""),
                    "function": vuln.get("function", ""),
                    "rule": ",".join(rules),
                    "status": "inconclusive",
                    "evidencia": "Mapped rule not found in Certora log.",
                }
            )
            continue

        if any(outcome["status"] == "confirmed" for _, outcome in matched):
            rule, outcome = next(item for item in matched if item[1]["status"] == "confirmed")
            status = "confirmed"
        elif any(outcome["status"] == "inconclusive" for _, outcome in matched):
            rule, outcome = next(item for item in matched if item[1]["status"] == "inconclusive")
            status = "inconclusive"
        else:
            rule, outcome = matched[0]
            status = "not_confirmed"

        analyses.append(
            {
                "id": vuln_id,
                "type": vuln.get("type", ""),
                "function": vuln.get("function", ""),
                "rule": rule,
                "status": status,
                "evidencia": outcome["evidence"],
            }
        )

    return {"analises": analyses}
