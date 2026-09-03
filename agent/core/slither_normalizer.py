"""
Deterministic Slither normalization.

This module preserves the complete Slither evidence in run artifacts while
building a compact, stable schema for the rest of the pipeline.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from core.vulnerability_catalog import get_catalog_entry


def _source_lines(element: dict) -> list[int]:
    lines = element.get("source_mapping", {}).get("lines", [])
    return [line for line in lines if isinstance(line, int)]


def _line_range(elements: list[dict]) -> str:
    lines = []
    for element in elements:
        if isinstance(element, dict):
            lines.extend(_source_lines(element))
    if not lines:
        return ""
    return str(min(lines)) if min(lines) == max(lines) else f"{min(lines)}-{max(lines)}"


def _first_line(element: dict) -> str:
    lines = _source_lines(element)
    return str(lines[0]) if lines else ""


def _function_name(detector: dict) -> str:
    for element in detector.get("elements", []):
        if isinstance(element, dict) and element.get("type") == "function":
            return element.get("name", "")

    description = detector.get("description", "")
    match = re.search(r"\.([A-Za-z_][A-Za-z0-9_]*\([^)]*\))", description)
    return match.group(1) if match else ""


def _elements(detector: dict) -> list[dict]:
    normalized = []
    for element in detector.get("elements", []):
        if not isinstance(element, dict):
            continue
        normalized.append(
            {
                "name": element.get("name", ""),
                "type": element.get("type", ""),
                "line": _first_line(element),
            }
        )
    return normalized


def _external_calls(description: str) -> list[str]:
    calls = []
    for line in description.splitlines():
        stripped = line.strip()
        if any(token in stripped for token in [".call{", ".call(", ".transfer(", ".send(", "delegatecall("]):
            calls.append(stripped)
    return calls


def _state_writes(description: str) -> list[str]:
    writes = []
    capture = False
    for line in description.splitlines():
        stripped = line.strip()
        if "State variables written after the call" in stripped:
            capture = True
            continue
        if capture:
            if not stripped or stripped.endswith(":"):
                break
            if stripped.startswith("-"):
                writes.append(stripped)
    return writes


def _target_parameter(detector: dict) -> str:
    check_type = detector.get("check", "")
    if check_type != "missing-zero-check":
        return ""
    for element in detector.get("elements", []):
        if isinstance(element, dict) and element.get("type") == "variable":
            return element.get("name", "")
    return ""


def _parse_function_signature(line: str) -> tuple[str, list[dict]] | None:
    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", line)
    if not match:
        return None

    name, params = match.groups()
    parsed_params = []
    for index, param in enumerate(param.strip() for param in params.split(",") if param.strip()):
        cleaned = re.sub(r"\s+(memory|calldata|storage)\b", "", param)
        cleaned = cleaned.replace("address payable", "address")
        parts = cleaned.split()
        if len(parts) == 1:
            parsed_params.append({"type": parts[0], "name": f"arg{index}"})
        else:
            parsed_params.append({"type": " ".join(parts[:-1]), "name": parts[-1]})

    return name, parsed_params


def _recipient_from_transfer_line(line: str) -> str:
    stripped = line.strip()

    payable_match = re.search(
        r"payable\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\.\s*(?:transfer|send)\s*\(",
        stripped,
    )
    if payable_match:
        return payable_match.group(1)

    direct_match = re.search(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(?:transfer|send)\s*\(",
        stripped,
    )
    if direct_match:
        return direct_match.group(1)

    call_match = re.search(
        r"payable\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\.\s*call\s*\{\s*value\s*:",
        stripped,
    )
    if call_match:
        return call_match.group(1)

    # A parameter already typed `address payable` is called directly, with no
    # payable(...) wrapper — e.g. `to.call{value: amount}("")`. At least as common as
    # the wrapped form above when the recipient comes straight from a function param.
    bare_call_match = re.search(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*call\s*\{\s*value\s*:",
        stripped,
    )
    if bare_call_match:
        return bare_call_match.group(1)

    return ""


def _is_eth_recipient_param(param: dict) -> bool:
    return param.get("type", "").strip() in {"address", "address payable"}


def _find_arbitrary_send_fallbacks(source: str, start_index: int) -> list[dict]:
    findings = []
    idx = start_index
    lines = source.splitlines()
    current = None
    depth = 0

    for line_no, line in enumerate(lines, start=1):
        if current is None:
            parsed = _parse_function_signature(line)
            if not parsed:
                continue
            name, params = parsed
            tail = line.split(")", 1)[-1]
            if not re.search(r"\b(public|external)\b", tail):
                continue
            current = {
                "name": name,
                "params": params,
                "param_names": {param["name"] for param in params},
                "params_by_name": {param["name"]: param for param in params},
                "start_line": line_no,
            }
            depth = line.count("{") - line.count("}")
            if depth <= 0 and "{" not in line:
                current = None
            continue

        recipient = _recipient_from_transfer_line(line)
        if (
            recipient
            and recipient in current["param_names"]
            and _is_eth_recipient_param(current["params_by_name"].get(recipient, {}))
        ):
            entry = get_catalog_entry("arbitrary-send-eth")
            param_types = ",".join(param["type"] for param in current["params"])
            signature = f"{current['name']}({param_types})"
            findings.append(
                {
                    "id": f"VULN_{idx:03d}",
                    "type": "arbitrary-send-eth",
                    "category": entry["category"],
                    "description": (
                        f"{signature} sends ETH to parameter '{recipient}' "
                        f"at line {line_no}."
                    ),
                    "function": signature,
                    "line": str(line_no),
                    "impact": "high",
                    "confidence": "medium",
                    "elements": [
                        {"name": current["name"], "type": "function", "line": str(current["start_line"])},
                        {"name": recipient, "type": "variable", "line": str(line_no)},
                        {"name": line.strip(), "type": "node", "line": str(line_no)},
                    ],
                    "external_calls": [f"- {line.strip()}"],
                    "state_writes_after_calls": [],
                    "target_parameter": recipient,
                    "formalizable": entry["formalizable"],
                    "propriedade_formal": entry["property"],
                    "padrao_cvl": entry["cvl_pattern"],
                    "repair_strategy": entry["repair_strategy"],
                    "source": "manual_fallback",
                }
            )
            idx += 1

        depth += line.count("{") - line.count("}")
        if depth <= 0:
            current = None
            depth = 0

    return findings


def _function_body(source: str, function_name: str) -> tuple[str, int]:
    match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*{{", source)
    if not match:
        return "", 0

    start = match.start()
    brace = source.find("{", match.end() - 1)
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                line_no = source[:start].count("\n") + 1
                return source[start:index + 1], line_no
    return "", 0


def _function_bodies(source: str) -> list[dict]:
    functions = []
    pattern = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)[^{;]*{")
    for match in pattern.finditer(source):
        name = match.group(1)
        params_raw = match.group(2)
        brace = source.find("{", match.end() - 1)
        depth = 0
        for index in range(brace, len(source)):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    line_no = source[:match.start()].count("\n") + 1
                    params = _parse_params_from_signature(params_raw)
                    header = source[match.start():brace]
                    functions.append(
                        {
                            "name": name,
                            "params": params,
                            "signature": f"{name}({','.join(param['type'] for param in params)})",
                            "header": header,
                            "visibility": _visibility_from_header(header),
                            "body": source[match.start():index + 1],
                            "start_line": line_no,
                        }
                    )
                    break
    return functions


def _visibility_from_header(header: str) -> str:
    match = re.search(r"\b(public|external|internal|private)\b", header)
    return match.group(1) if match else ""


def _parse_params_from_signature(params_raw: str) -> list[dict]:
    params = []
    for index, param in enumerate(part.strip() for part in params_raw.split(",") if part.strip()):
        cleaned = re.sub(r"\s+(memory|calldata|storage)\b", "", param)
        cleaned = cleaned.replace("address payable", "address")
        parts = cleaned.split()
        if len(parts) == 1:
            params.append({"type": parts[0], "name": f"arg{index}"})
        else:
            params.append({"type": " ".join(parts[:-1]), "name": parts[-1]})
    return params


def _low_level_call_contexts(source: str) -> list[dict]:
    contexts = []
    assignment_pattern = re.compile(
        r"\(\s*bool\s+([A-Za-z_][A-Za-z0-9_]*)[^)]*\)\s*=\s*([^;\n]*\.call(?:\s*\{[^;]*?\})?\s*\([^;\n]*\))"
    )
    bare_pattern = re.compile(
        r"(?<![=])\b([A-Za-z_][A-Za-z0-9_]*|\)|\])\s*\.call(?:\s*\{[^;]*?\})?\s*\([^;\n]*\)"
    )

    for function in _function_bodies(source):
        body = function["body"]
        lines = body.splitlines()
        for index, line in enumerate(lines):
            if ".call" not in line:
                continue

            assignment = assignment_pattern.search(line)
            if assignment:
                success_var = assignment.group(1)
                checked, check_line, check_kind = _success_var_checked(lines, index + 1, success_var)
                contexts.append(
                    {
                        "function": function["signature"],
                        "function_name": function["name"],
                        "line": function["start_line"] + index,
                        "call": assignment.group(2).strip(),
                        "success_variable": success_var,
                        "checked_return": checked,
                        "check_line": function["start_line"] + check_line - 1 if check_line else "",
                        "check_kind": check_kind,
                    }
                )
                continue

            if bare_pattern.search(line):
                contexts.append(
                    {
                        "function": function["signature"],
                        "function_name": function["name"],
                        "line": function["start_line"] + index,
                        "call": line.strip(),
                        "success_variable": "",
                        "checked_return": False,
                        "check_line": "",
                        "check_kind": "ignored_return",
                    }
                )

    return contexts


def _success_var_checked(lines: list[str], start_index: int, success_var: str) -> tuple[bool, int, str]:
    escaped = re.escape(success_var)
    check_patterns = [
        (re.compile(rf"\brequire\s*\(\s*{escaped}\b"), "require_success"),
        (re.compile(rf"\brequire\s*\(\s*{escaped}\s*==\s*true\b"), "require_success"),
        (re.compile(rf"\bassert\s*\(\s*{escaped}\b"), "assert_success"),
        (re.compile(rf"\bif\s*\(\s*!\s*{escaped}\s*\)"), "if_not_success"),
        (re.compile(rf"\bif\s*\(\s*{escaped}\s*==\s*false\s*\)"), "if_false_success"),
        (re.compile(rf"\bif\s*\(\s*false\s*==\s*{escaped}\s*\)"), "if_false_success"),
        (re.compile(rf"\bif\s*\(\s*{escaped}\s*\)"), "if_success"),
        (re.compile(rf"\breturn\s+{escaped}\s*;"), "return_success"),
    ]
    for offset, line in enumerate(lines[start_index:], start=start_index):
        if re.search(rf"\b{escaped}\s*=", line):
            return False, 0, ""
        for pattern, kind in check_patterns:
            if pattern.search(line):
                return True, offset + 1, kind
    return False, 0, ""


def _parse_line_spec(value) -> list[int]:
    if isinstance(value, int):
        return [value]
    if not isinstance(value, str) or not value.strip():
        return []
    numbers = [int(number) for number in re.findall(r"\d+", value)]
    if not numbers:
        return []
    if len(numbers) >= 2 and "-" in value:
        return [numbers[0], numbers[-1]]
    return [numbers[0]]


def _function_names_from_finding(finding: dict) -> list[str]:
    candidates = []
    if finding.get("function"):
        candidates.append(str(finding["function"]))
    for element in finding.get("elements", []) or []:
        if isinstance(element, dict) and element.get("type") == "function":
            candidates.append(str(element.get("name", "")))

    names = []
    for candidate in candidates:
        match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", candidate)
        if match:
            names.append(match.group(1))
        elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
            names.append(candidate)
    return sorted(set(names))


def _low_level_context_for_finding(finding: dict, contexts: list[dict]) -> dict:
    finding_lines = set(_parse_line_spec(finding.get("line", "")))
    finding_function = _function_names_from_finding(finding)
    for element in finding.get("elements", []):
        if isinstance(element, dict):
            finding_lines.update(_parse_line_spec(element.get("line", "")))

    for context in contexts:
        if context["line"] in finding_lines:
            return context
        if context["function_name"] in finding_function:
            return context
    return {}


def _find_unchecked_lowlevel_fallbacks(source: str, start_index: int) -> list[dict]:
    findings = []
    idx = start_index
    entry = get_catalog_entry("unchecked-lowlevel")

    for context in _low_level_call_contexts(source):
        if context["checked_return"]:
            continue
        findings.append(
            {
                "id": f"VULN_{idx:03d}",
                "type": "unchecked-lowlevel",
                "category": entry["category"],
                "description": (
                    f"{context['function']} performs a low-level call at line "
                    f"{context['line']} without checking the returned success value."
                ),
                "function": context["function"],
                "line": str(context["line"]),
                "impact": "medium",
                "confidence": "medium",
                "elements": [
                    {"name": context["function_name"], "type": "function", "line": ""},
                    {"name": context["call"], "type": "node", "line": str(context["line"])},
                ],
                "external_calls": [context["call"]],
                "state_writes_after_calls": [],
                "target_parameter": "",
                "formalizable": entry["formalizable"],
                "propriedade_formal": entry["property"],
                "padrao_cvl": entry["cvl_pattern"],
                "repair_strategy": entry["repair_strategy"],
                "source": "manual_fallback",
                "low_level_call_context": context,
            }
        )
        idx += 1

    return findings


def _is_selfdestruct_authorized(signature_tail: str, body: str) -> bool:
    if re.search(r"\bonly(Owner|Admin|Gov|Governance|Operator|Guardian)\b", signature_tail):
        return True
    auth_names = "owner|admin|governor|governance|gov|operator|guardian"
    return bool(
        re.search(rf"\bmsg\.sender\s*==\s*({auth_names})\b", body)
        or re.search(rf"\b({auth_names})\s*==\s*msg\.sender\b", body)
    )


def _find_selfdestruct_fallbacks(source: str, start_index: int) -> list[dict]:
    findings = []
    idx = start_index
    lines = source.splitlines()
    current = None
    depth = 0
    body_lines: list[str] = []

    for line_no, line in enumerate(lines, start=1):
        if current is None:
            parsed = _parse_function_signature(line)
            if not parsed:
                continue
            name, params = parsed
            tail = line.split(")", 1)[-1]
            if not re.search(r"\b(public|external)\b", tail):
                continue
            current = {
                "name": name,
                "params": params,
                "signature_tail": tail,
                "start_line": line_no,
            }
            depth = line.count("{") - line.count("}")
            body_lines = [line]
            if depth <= 0 and "{" not in line:
                current = None
                body_lines = []
            continue

        body_lines.append(line)
        depth += line.count("{") - line.count("}")
        if depth > 0:
            continue

        body = "\n".join(body_lines)
        if "selfdestruct" in body and not _is_selfdestruct_authorized(current["signature_tail"], body):
            entry = get_catalog_entry("suicidal")
            param_types = ",".join(param["type"] for param in current["params"])
            signature = f"{current['name']}({param_types})"
            findings.append(
                {
                    "id": f"VULN_{idx:03d}",
                    "type": "suicidal",
                    "category": entry["category"],
                    "description": f"{signature} reaches selfdestruct without an obvious msg.sender authorization guard.",
                    "function": signature,
                    "line": str(current["start_line"]),
                    "impact": "high",
                    "confidence": "medium",
                    "elements": [
                        {"name": current["name"], "type": "function", "line": str(current["start_line"])},
                        {"name": "selfdestruct", "type": "node", "line": str(line_no)},
                    ],
                    "external_calls": ["selfdestruct"],
                    "state_writes_after_calls": [],
                    "target_parameter": "",
                    "formalizable": entry["formalizable"],
                    "propriedade_formal": entry["property"],
                    "padrao_cvl": entry["cvl_pattern"],
                    "repair_strategy": entry["repair_strategy"],
                    "source": "manual_fallback",
                }
            )
            idx += 1
        current = None
        body_lines = []

    return findings


def _state_variables(source: str) -> dict[str, dict]:
    variables = {}
    depth = 0
    pending = ""
    pending_start = 0

    for line_no, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if depth == 1 and stripped:
            if not pending_start:
                pending_start = line_no
            pending = f"{pending} {stripped}".strip()

            if "{" in stripped:
                pending = ""
                pending_start = 0
            elif ";" in stripped:
                declaration = pending.split(";", 1)[0].strip()
                parsed = _parse_state_variable_declaration(declaration, pending_start)
                if parsed:
                    variables[parsed["name"]] = parsed
                pending = ""
                pending_start = 0

        depth += line.count("{") - line.count("}")
        if depth != 1:
            pending = ""
            pending_start = 0

    return variables


def _parse_state_variable_declaration(declaration: str, line_no: int) -> dict | None:
    if re.search(
        r"\b(function|modifier|constructor|event|error|struct|enum|using|import|contract|interface|library)\b",
        declaration,
    ):
        return None
    before_assignment = declaration.split("=", 1)[0].strip()
    before_assignment = before_assignment.split(",", 1)[0].strip()
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)*$", before_assignment)
    if not match:
        return None
    name = match.group(1)
    var_type = before_assignment[:match.start(1)].strip()
    return {"name": name, "type": var_type, "line": line_no}


def _is_critical_state_variable(name: str, var_type: str) -> bool:
    lowered = name.lower()
    if "mapping" in var_type:
        return False
    if any(token in lowered for token in ["paid", "collected", "earned", "accrued", "balance"]):
        return False
    if lowered.startswith(("user", "account")):
        return False

    exact = {
        "owner",
        "admin",
        "governor",
        "governance",
        "guardian",
        "operator",
        "pauser",
        "treasury",
        "oracle",
        "implementation",
        "trustedforwarder",
    }
    if lowered in exact:
        return True

    if any(fragment in lowered for fragment in ["oracle", "treasury", "implementation", "forwarder"]):
        return True
    if any(fragment in lowered for fragment in ["unlock", "timelock", "delay"]):
        return True
    if "fee" in lowered:
        return any(fragment in lowered for fragment in ["protocol", "platform", "admin", "bps", "rate", "max", "min"])

    return False


def _auth_variables(state_vars: dict[str, dict]) -> list[str]:
    candidates = []
    for name in state_vars:
        lowered = name.lower()
        if lowered in {"owner", "admin", "governor", "governance", "guardian", "operator"}:
            candidates.append(name)
    return candidates


def _has_owner_admin_auth(function: dict, auth_vars: list[str]) -> bool:
    header = re.sub(r"\s+", " ", function.get("header", ""))
    body_compact = re.sub(r"\s+", "", function.get("body", ""))
    if re.search(r"\bonly[A-Za-z0-9_]*(Owner|Admin|Govern|Guardian|Operator)\b", header):
        return True

    caller = r"(?:msg\.sender|_msgSender\(\))"
    for var in auth_vars:
        escaped = re.escape(var)
        if re.search(rf"require\({caller}=={escaped}(?:,|\))", body_compact):
            return True
        if re.search(rf"require\({escaped}=={caller}(?:,|\))", body_compact):
            return True
        if re.search(rf"if\({caller}!={escaped}\){{?revert", body_compact):
            return True
        if re.search(rf"if\({escaped}!={caller}\){{?revert", body_compact):
            return True
    return False


def _critical_writes(function: dict, state_vars: dict[str, dict]) -> list[dict]:
    writes = []
    lines = function["body"].splitlines()
    for name, state_var in state_vars.items():
        if not _is_critical_state_variable(name, state_var.get("type", "")):
            continue
        pattern = re.compile(
            rf"\b{re.escape(name)}\s*(\[[^\]]+\])?\s*(=(?!=)|\+=|-=|\*=|/=|%=)"
        )
        for offset, line in enumerate(lines):
            match = pattern.search(line)
            if not match:
                continue
            index_expr = match.group(1) or ""
            operator = match.group(2)
            if index_expr and "msg.sender" in index_expr:
                continue
            if operator != "=":
                continue
            if not _looks_like_admin_update_function(function, name):
                continue
            writes.append(
                {
                    "variable": name,
                    "line": function["start_line"] + offset,
                    "statement": line.strip(),
                    "operator": operator,
                }
            )
    return writes


def _looks_like_admin_update_function(function: dict, variable_name: str) -> bool:
    name = function.get("name", "")
    lowered_name = name.lower()
    lowered_var = variable_name.lower()
    admin_prefixes = (
        "set",
        "change",
        "update",
        "configure",
        "extend",
        "upgrade",
        "migrate",
        "transfer",
    )
    if not lowered_name.startswith(admin_prefixes):
        return False
    if lowered_var in {"owner", "admin", "governor", "governance", "guardian", "operator", "pauser"}:
        return True
    if any(fragment in lowered_name for fragment in ["owner", "admin", "govern", "guardian", "operator"]):
        return True
    if any(fragment in lowered_name for fragment in ["fee", "oracle", "treasury", "implementation", "forwarder"]):
        return True
    if any(fragment in lowered_name for fragment in ["lock", "unlock", "delay", "timelock"]):
        return True
    if any(fragment in lowered_var for fragment in ["fee", "oracle", "treasury", "implementation", "forwarder"]):
        return True
    if any(fragment in lowered_var for fragment in ["unlock", "timelock", "delay"]):
        return True
    return False


def _find_unprotected_critical_updates(source: str, start_index: int) -> list[dict]:
    state_vars = _state_variables(source)
    auth_vars = _auth_variables(state_vars)
    findings = []
    idx = start_index
    entry = get_catalog_entry("unprotected-critical-update")

    for function in _function_bodies(source):
        if function.get("visibility") not in {"public", "external"}:
            continue
        writes = _critical_writes(function, state_vars)
        if not writes:
            continue
        if _has_owner_admin_auth(function, auth_vars):
            continue

        for write in writes:
            findings.append(
                {
                    "id": f"VULN_{idx:03d}",
                    "type": "unprotected-critical-update",
                    "category": entry["category"],
                    "description": (
                        f"{function['signature']} updates critical state variable "
                        f"'{write['variable']}' at line {write['line']} without an owner/admin guard."
                    ),
                    "function": function["signature"],
                    "line": str(write["line"]),
                    "impact": "high",
                    "confidence": "medium",
                    "elements": [
                        {"name": function["name"], "type": "function", "line": str(function["start_line"])},
                        {"name": write["variable"], "type": "variable", "line": str(write["line"])},
                        {"name": write["statement"], "type": "node", "line": str(write["line"])},
                    ],
                    "external_calls": [],
                    "state_writes_after_calls": [write["statement"]],
                    "target_parameter": write["variable"],
                    "formalizable": entry["formalizable"],
                    "propriedade_formal": entry["property"],
                    "padrao_cvl": entry["cvl_pattern"],
                    "repair_strategy": entry["repair_strategy"],
                    "source": "manual_fallback",
                }
            )
            idx += 1

    return findings


def _compact_solidity(source: str) -> str:
    return re.sub(r"\s+", "", source)


def _is_erc2771_context(source: str) -> bool:
    compact = _compact_solidity(source)
    if "ERC2771Context" in source:
        return True
    if "calldataload(sub(calldatasize(),20))" in compact:
        return True
    if "_msgSender" in source and "isTrustedForwarder(" in source:
        return True
    return (
        "_msgSender" in source
        and re.search(r"\b[A-Za-z_][A-Za-z0-9_]*forwarder[A-Za-z0-9_]*\b", source, re.IGNORECASE)
    )


def _extract_forwarder_identifiers(source: str) -> list[str]:
    names = set()
    for match in re.finditer(r"\b[A-Za-z_][A-Za-z0-9_]*forwarder[A-Za-z0-9_]*\b", source, re.IGNORECASE):
        names.add(match.group(0))

    trusted_body, _ = _function_body(source, "isTrustedForwarder")
    for match in re.finditer(
        r"\breturn\s+([A-Za-z_][A-Za-z0-9_]*)\s*==\s*([A-Za-z_][A-Za-z0-9_]*)",
        trusted_body,
    ):
        names.update(match.groups())

    return sorted(names)


def _has_is_trusted_forwarder_guard(compact_body: str) -> bool:
    trusted_call = r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?isTrustedForwarder\(msg\.sender\)"
    return (
        re.search(rf"!{trusted_call}", compact_body)
        or re.search(rf"{trusted_call}==false", compact_body)
        or re.search(rf"false=={trusted_call}", compact_body)
        or re.search(rf"if\({trusted_call}\){{?revert", compact_body)
    )


def _has_forwarder_identifier_guard(compact_body: str, forwarder_names: list[str]) -> bool:
    for name in forwarder_names:
        escaped = re.escape(name)
        if re.search(rf"msg\.sender!={escaped}", compact_body):
            return True
        if re.search(rf"{escaped}!=msg\.sender", compact_body):
            return True
        if re.search(rf"if\((?:msg\.sender=={escaped}|{escaped}==msg\.sender)\){{?revert", compact_body):
            return True
    return False


def _has_forwarder_multicall_guard(multicall_body: str, forwarder_names: list[str]) -> bool:
    compact = re.sub(r"\s+", "", multicall_body)
    return (
        _has_is_trusted_forwarder_guard(compact)
        or _has_forwarder_identifier_guard(compact, forwarder_names)
    )


def _find_erc2771_multicall_context(source: str, start_index: int) -> list[dict]:
    if not _is_erc2771_context(source):
        return []

    multicall_body, line_no = _function_body(source, "multicall")
    if not multicall_body:
        return []
    if "delegatecall" not in multicall_body:
        return []
    forwarder_names = _extract_forwarder_identifiers(source)
    if _has_forwarder_multicall_guard(multicall_body, forwarder_names):
        return []

    entry = get_catalog_entry("erc2771-multicall-context")
    forwarder_marker = forwarder_names[0] if forwarder_names else "ERC2771Context"
    return [
        {
            "id": f"VULN_{start_index:03d}",
            "type": "erc2771-multicall-context",
            "category": entry["category"],
            "description": (
                "Contract combines ERC2771 calldata-suffix sender recovery with "
                "delegatecall-based multicall without blocking forwarded multicalls."
            ),
            "function": "multicall(bytes[])",
            "line": str(line_no),
            "impact": "high",
            "confidence": "medium",
            "elements": [
                {"name": forwarder_marker, "type": "variable", "line": ""},
                {"name": "multicall", "type": "function", "line": str(line_no)},
                {"name": "delegatecall", "type": "node", "line": ""},
            ],
            "external_calls": ["delegatecall inside multicall"],
            "state_writes_after_calls": [],
            "target_parameter": "",
            "formalizable": entry["formalizable"],
            "propriedade_formal": entry["property"],
            "padrao_cvl": entry["cvl_pattern"],
            "repair_strategy": entry["repair_strategy"],
            "source": "manual_fallback",
        }
    ]


def _fallback_findings(contract_path: str, existing_types: set[str], start_index: int) -> list[dict]:
    if not contract_path or not os.path.exists(contract_path):
        return []

    source = Path(contract_path).read_text(encoding="utf-8")
    findings = []
    idx = start_index

    def add(check_type: str, function: str, description: str, impact: str, confidence: str):
        nonlocal idx
        entry = get_catalog_entry(check_type)
        findings.append(
            {
                "id": f"VULN_{idx:03d}",
                "type": check_type,
                "category": entry["category"],
                "description": description,
                "function": function,
                "line": "",
                "impact": impact,
                "confidence": confidence,
                "elements": [],
                "external_calls": [],
                "state_writes_after_calls": [],
                "target_parameter": "",
                "formalizable": entry["formalizable"],
                "propriedade_formal": entry["property"],
                "padrao_cvl": entry["cvl_pattern"],
                "repair_strategy": entry["repair_strategy"],
                "source": "manual_fallback",
            }
        )
        idx += 1

    if "tx.origin" in source and "tx-origin" not in existing_types:
        add("tx-origin", "modifier/function", "Contract source uses tx.origin.", "medium", "high")
    if "selfdestruct" in source and "suicidal" not in existing_types:
        findings.extend(_find_selfdestruct_fallbacks(source, idx))
        idx = start_index + len(findings)
    sends_eth = ".transfer(" in source or ".send(" in source or ".call{value" in source
    if sends_eth and "arbitrary-send-eth" not in existing_types:
        findings.extend(_find_arbitrary_send_fallbacks(source, idx))
        idx = start_index + len(findings)
    if "unchecked-lowlevel" not in existing_types:
        findings.extend(_find_unchecked_lowlevel_fallbacks(source, idx))
        idx = start_index + len(findings)
    if "erc2771-multicall-context" not in existing_types:
        findings.extend(_find_erc2771_multicall_context(source, idx))
        idx = start_index + len(findings)
    if "unprotected-critical-update" not in existing_types:
        findings.extend(_find_unprotected_critical_updates(source, idx))

    return findings


def normalize_slither_json(slither_json: dict, contract_path: str = "") -> dict:
    detectors = slither_json.get("results", {}).get("detectors", [])
    vulnerabilities = []
    low_level_contexts = []
    if contract_path and os.path.exists(contract_path):
        source = Path(contract_path).read_text(encoding="utf-8")
        low_level_contexts = _low_level_call_contexts(source)

    for idx, detector in enumerate(detectors, start=1):
        check_type = detector.get("check", "")
        entry = get_catalog_entry(check_type)
        description = detector.get("description", "").strip()
        elements = _elements(detector)

        vulnerability = {
                "id": f"VULN_{idx:03d}",
                "type": check_type,
                "category": entry["category"],
                "description": description,
                "function": _function_name(detector),
                "line": _line_range(detector.get("elements", [])),
                "impact": detector.get("impact", "").lower(),
                "confidence": detector.get("confidence", "").lower(),
                "elements": elements,
                "external_calls": _external_calls(description),
                "state_writes_after_calls": _state_writes(description),
                "target_parameter": _target_parameter(detector),
                "formalizable": entry["formalizable"],
                "propriedade_formal": entry["property"],
                "padrao_cvl": entry["cvl_pattern"],
                "repair_strategy": entry["repair_strategy"],
                "source": "slither",
            }
        if check_type == "low-level-calls":
            context = _low_level_context_for_finding(vulnerability, low_level_contexts)
            if context:
                vulnerability["low_level_call_context"] = context
                if context["checked_return"]:
                    vulnerability["description"] += (
                        "\nPipeline context: low-level call return value appears to be checked "
                        f"via {context['check_kind']} at line {context['check_line']}."
                    )
                else:
                    vulnerability["description"] += (
                        "\nPipeline context: low-level call return value is not clearly checked."
                    )

        vulnerabilities.append(vulnerability)

    existing_types = {item["type"] for item in vulnerabilities}
    vulnerabilities.extend(_fallback_findings(contract_path, existing_types, len(vulnerabilities) + 1))

    return {
        "vulnerabilidades": vulnerabilities,
        "stats": {
            "total": len(vulnerabilities),
            "formalizable": sum(1 for item in vulnerabilities if item["formalizable"]),
            "non_formalizable": sum(1 for item in vulnerabilities if not item["formalizable"]),
        },
    }
