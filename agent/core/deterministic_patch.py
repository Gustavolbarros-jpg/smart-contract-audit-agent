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
        kind = finding.get("type")
        if kind in _STATEMENT_PATCHES:
            patched_next, changed = _STATEMENT_PATCHES[kind](
                patched, _function_name(str(finding.get("function") or "")), str(finding.get("id") or "")
            )
            if changed:
                patched = patched_next
                applied.append({"id": finding.get("id"), "type": kind, "function": finding.get("function")})
            continue
        if kind != "missing-zero-check":
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
    # Slither writes "f(address)"; the static fallbacks write the bare name "f".
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|$)", signature)
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




_CONTROL_KEYWORDS = {"require", "assert", "if", "while", "for", "return", "emit", "revert"}


def _function_body(masked: str, function_name: str) -> tuple[int, int] | None:
    match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*{{", masked, re.DOTALL)
    if not match:
        return None
    brace_index = masked.find("{", match.end() - 1)
    return brace_index, matching_brace(masked, brace_index)


def _top_level_args(call_args: str) -> int:
    depth = 0
    count = 1 if call_args.strip() else 0
    for char in call_args:
        depth += char in "([{"
        depth -= char in ")]}"
        if char == "," and depth == 0:
            count += 1
    return count


def _replace_tx_origin(source: str, _function: str, vuln_id: str) -> tuple[str, bool]:
    """tx.origin -> msg.sender, only where it authorizes by comparison.

    A line that already compares against msg.sender (the usual "caller is an EOA" check) is
    left alone: replacing it would make the comparison trivially true.
    """
    raw_lines = source.splitlines(keepends=True)
    masked_lines = mask_comments_and_strings(source).splitlines(keepends=True)
    changed = False
    for index, (raw, masked) in enumerate(zip(raw_lines, masked_lines)):
        if "msg.sender" in masked or not re.search(r"\btx\.origin\s*[!=]=|[!=]=\s*tx\.origin\b", masked):
            continue
        for hit in reversed(list(re.finditer(r"\btx\.origin\b", masked))):
            raw = raw[: hit.start()] + "msg.sender" + raw[hit.end():]
        newline = "\n" if raw.endswith("\n") else ""
        raw_lines[index] = f"{raw.rstrip(chr(10))} // FIX {vuln_id}{newline}" if vuln_id else raw
        changed = True
    return "".join(raw_lines), changed


def _fresh_name(source: str, base: str, taken: set[str]) -> str:
    n = 1
    while f"{base}{n}" in source or f"{base}{n}" in taken:
        n += 1
    taken.add(f"{base}{n}")
    return f"{base}{n}"


_LOW_LEVEL_STATEMENT = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<expr>[A-Za-z_][^\n;=]*?\.call\s*(?:\{[^}\n]*\})?\s*\([^\n;]*\))[ \t]*;"
)
_TOKEN_TRANSFER_STATEMENT = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<expr>[A-Za-z_][\w.\[\]]*\.(?:transfer|transferFrom)\s*\((?P<args>[^\n;]*)\))[ \t]*;"
)


def _rewrite_statements(source, function_name, pattern, build, accept=lambda match: True):
    masked = mask_comments_and_strings(source)
    span = _function_body(masked, function_name) if function_name else None
    if not span:
        return source, False
    start, end = span
    matches = [
        m for m in pattern.finditer(masked, start, end + 1)
        if m.group("expr").split("(")[0].split(".")[0].strip() not in _CONTROL_KEYWORDS and accept(m)
    ]
    # Built in source order so generated names read top to bottom, applied back to front so
    # earlier offsets stay valid.
    replacements = [build(m.group("indent"), source[m.start("expr"): m.end("expr")]) for m in matches]
    for match, replacement in reversed(list(zip(matches, replacements))):
        source = source[: match.start()] + replacement + source[match.end():]
    return source, bool(matches)


def _require_low_level_success(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    fix = f" // FIX {vuln_id}" if vuln_id else ""
    taken: set[str] = set()

    def build(indent: str, expr: str) -> str:
        name = _fresh_name(source, "callOk", taken)
        return f'{indent}(bool {name}, ) = {expr};\n{indent}require({name}, "Low-level call failed");{fix}'

    return _rewrite_statements(source, function_name, _LOW_LEVEL_STATEMENT, build)


def _require_token_transfer_success(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    fix = f" // FIX {vuln_id}" if vuln_id else ""

    def build(indent: str, expr: str) -> str:
        return f'{indent}require({expr}, "Token transfer failed");{fix}'

    # ETH transfer takes one argument and returns nothing; only the ERC20 forms are wrapped.
    return _rewrite_statements(
        source, function_name, _TOKEN_TRANSFER_STATEMENT, build,
        accept=lambda m: _top_level_args(m.group("args")) >= 2,
    )


_STATEMENT_PATCHES = {
    "tx-origin": _replace_tx_origin,
    "unchecked-lowlevel": _require_low_level_success,
    "unchecked-transfer": _require_token_transfer_success,
}
