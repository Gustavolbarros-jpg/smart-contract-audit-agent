"""Token-efficient context and safeguards for LLM diagnosis."""

from __future__ import annotations

import re


DETERMINISTIC_REPAIR_HINTS = {
    "missing-zero-check": {
        "motivo": "Address parameter is used without rejecting the zero address.",
        "correcao": "Add require(<parameter> != address(0), \"Zero address\"); at the start of the affected function.",
    },
    "tx-origin": {
        "motivo": "Authorization depends on tx.origin instead of msg.sender.",
        "correcao": "Replace tx.origin with msg.sender in the authorization check.",
    },
    "suicidal": {
        "motivo": "selfdestruct is reachable without a msg.sender-based owner authorization guarantee.",
        "correcao": "Restrict selfdestruct with the existing owner authorization based on msg.sender.",
    },
    "arbitrary-send-eth": {
        "motivo": "Ether transfer can use an arbitrary recipient parameter without the required recipient policy.",
        "correcao": "Restrict the recipient according to the contract policy and reject address(0).",
    },
    "unchecked-lowlevel": {
        "motivo": "Low-level call return value is ignored.",
        "correcao": "Capture the success boolean from the low-level call and require(success, \"call failed\").",
    },
    "unchecked-transfer": {
        "motivo": "ERC20 transfer/transferFrom return value is ignored, so a token that signals failure by returning false is treated as success.",
        "correcao": "Wrap the call in require(...), as in require(token.transfer(to, amount), \"transfer failed\"); keep the existing arguments unchanged.",
    },
    "unchecked-send": {
        "motivo": "The boolean returned by send() is ignored, so a failed transfer goes unnoticed.",
        "correcao": "Capture the boolean and require it, as in bool sent = to.send(amount); require(sent, \"send failed\");",
    },
    "erc2771-multicall-context": {
        "motivo": "ERC2771 forwarded calls can reach delegatecall-based multicall and preserve spoofed calldata context.",
        "correcao": "Reject multicall when msg.sender is the trusted forwarder.",
    },
}


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


def _first_line_number(value: str) -> int | None:
    match = re.search(r"\d+", value or "")
    return int(match.group(0)) if match else None


def deterministic_diagnosis(
    confirmed: list[dict],
    selected_vulnerabilities: list[dict],
    diagnosis_plan: dict,
) -> dict:
    """Build diagnosis for well-known repair strategies without another LLM call."""
    vuln_by_id = {item.get("id"): item for item in selected_vulnerabilities}
    plan_by_id = {
        item.get("id"): item
        for item in diagnosis_plan.get("selected_rules", [])
    }
    failures = []

    for item in confirmed:
        vuln_id = item.get("id", "")
        vuln = vuln_by_id.get(vuln_id, {})
        plan_item = plan_by_id.get(vuln_id, {})
        vuln_type = item.get("type") or vuln.get("type", "")
        hint = DETERMINISTIC_REPAIR_HINTS.get(vuln_type)
        if not hint:
            continue

        target = (
            plan_item.get("target_parameter")
            or vuln.get("target_parameter")
            or ""
        )
        correction = hint["correcao"]
        if target:
            correction = correction.replace("<parameter>", target)

        failures.append(
            {
                "id": vuln_id,
                "rule_que_falhou": item.get("rule", ""),
                "motivo": hint["motivo"],
                "linha": _first_line_number(vuln.get("line", "") or item.get("line", "")),
                "codigo_atual": vuln.get("description", "")[:240],
                "correcao_necessaria": correction,
            }
        )

    return {"falhas": failures}


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
