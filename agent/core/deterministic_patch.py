"""Deterministic source patches for narrow, mechanical repair classes."""

from __future__ import annotations

import re
from typing import Any

from core.solidity_source import mask_comments_and_strings, matching_brace


def apply_deterministic_patches(
    source: str,
    confirmed_findings: list[dict[str, Any]],
) -> tuple[str, list[dict[str, Any]]]:
    patched = source
    applied: list[dict[str, Any]] = []

    for finding in confirmed_findings:
        if finding.get("type") != "missing-zero-check":
            continue
        parameter = str(finding.get("target_parameter") or _variable_element_name(finding) or "").strip()
        function_name = _function_name(str(finding.get("function") or ""))
        if not parameter or not function_name:
            continue

        patched_next, changed = _insert_zero_check(
            patched,
            function_name,
            parameter,
            str(finding.get("id") or ""),
        )
        if changed:
            patched = patched_next
            applied.append(
                {
                    "id": finding.get("id"),
                    "type": finding.get("type"),
                    "function": finding.get("function"),
                    "target_parameter": parameter,
                }
            )

    return patched, applied


def _function_name(signature: str) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", signature)
    return match.group(1) if match else ""


def _variable_element_name(finding: dict[str, Any]) -> str:
    for element in finding.get("elements") or []:
        if isinstance(element, dict) and element.get("type") == "variable":
            return str(element.get("name") or "")
    return ""


def _insert_zero_check(source: str, function_name: str, parameter: str, vuln_id: str) -> tuple[str, bool]:
    # Located on masked source so a "function foo(" written in a comment cannot match
    # and a brace inside a string literal cannot close the body early. A truncated body
    # made an existing guard invisible and the patch inserted a duplicate require.
    masked = mask_comments_and_strings(source)
    match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*{{", masked, re.DOTALL)
    if not match:
        return source, False

    brace_index = masked.find("{", match.end() - 1)
    end_index = matching_brace(masked, brace_index)
    # Masked body as well, so a commented-out check does not count as present.
    body = masked[brace_index:end_index + 1]
    escaped = re.escape(parameter)
    if re.search(rf"\b{escaped}\s*!=\s*address\s*\(\s*0\s*\)", body):
        return source, False
    if re.search(rf"address\s*\(\s*0\s*\)\s*!=\s*\b{escaped}\b", body):
        return source, False

    line_start = source.rfind("\n", 0, match.start()) + 1
    base_indent = re.match(r"\s*", source[line_start:match.start()]).group(0)
    indent = base_indent + "    "
    fix_comment = f" // FIX {vuln_id}" if vuln_id else ""
    require_line = f'{indent}require({parameter} != address(0), "Zero address");{fix_comment}'

    if "\n" not in source[brace_index:end_index + 1]:
        inner = source[brace_index + 1:end_index].strip()
        inner_lines = [f"{indent}{inner}"] if inner else []
        replacement_lines = ["{", require_line, *inner_lines, f"{base_indent}}}"]
        replacement = "\n".join(replacement_lines)
        return source[:brace_index] + replacement + source[end_index + 1:], True

    line_end = source.find("\n", brace_index)
    if line_end == -1:
        return source, False

    insertion = f"\n{require_line}"

    return source[:line_end] + insertion + source[line_end:], True


