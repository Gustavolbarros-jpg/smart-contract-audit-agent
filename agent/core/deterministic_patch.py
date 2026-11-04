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


def _find_definition(masked: str, function_name: str, parameter: str) -> re.Match | None:
    """The function (or constructor) definition that takes ``parameter``.

    A file can hold several contracts and so several constructors; the finding names only
    "constructor", so the one whose parameter list contains the flagged name is chosen.
    """
    if function_name != "constructor":
        return re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*{{", masked, re.DOTALL)
    for match in re.finditer(r"\bconstructor\s*\(([^)]*)\)[^{;]*{", masked, re.DOTALL):
        if re.search(rf"\b{re.escape(parameter)}\b", match.group(1)):
            return match
    return None


def _insert_zero_check(source: str, function_name: str, parameter: str, vuln_id: str) -> tuple[str, bool]:
    # Located on masked source so a "function foo(" written in a comment cannot match
    # and a brace inside a string literal cannot close the body early. A truncated body
    # made an existing guard invisible and the patch inserted a duplicate require.
    masked = mask_comments_and_strings(source)
    match = _find_definition(masked, function_name, parameter)
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

    fix_comment = f" // FIX {vuln_id}" if vuln_id else ""
    statement = f'require({parameter} != address(0), "Zero address");{fix_comment}'
    return _insert_first_statement(source, match.start(), brace_index, end_index, statement)


def _insert_first_statement(
    source: str, function_start: int, brace_index: int, end_index: int, statement: str
) -> tuple[str, bool]:
    line_start = source.rfind("\n", 0, function_start) + 1
    base_indent = re.match(r"\s*", source[line_start:function_start]).group(0)
    indent = base_indent + "    "
    line = f"{indent}{statement}"

    if "\n" not in source[brace_index:end_index + 1]:
        inner = source[brace_index + 1:end_index].strip()
        inner_lines = [f"{indent}{inner}"] if inner else []
        replacement = "\n".join(["{", line, *inner_lines, f"{base_indent}}}"])
        return source[:brace_index] + replacement + source[end_index + 1:], True

    line_end = source.find("\n", brace_index)
    if line_end == -1:
        return source, False
    return source[:line_end] + f"\n{line}" + source[line_end:], True


_CONTROL_KEYWORDS = {"require", "assert", "if", "while", "for", "return", "emit", "revert"}


def _function_bodies(masked: str, function_name: str) -> list[tuple[int, int]]:
    """Body span of every definition with this name; overloads share one finding's name."""
    spans = []
    for match in re.finditer(rf"\bfunction\s+{re.escape(function_name)}\s*\([^)]*\)[^{{;]*{{", masked, re.DOTALL):
        brace_index = masked.find("{", match.end() - 1)
        spans.append((brace_index, matching_brace(masked, brace_index)))
    return spans


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
    r"(?m)^(?P<indent>[ \t]*)(?P<expr>[A-Za-z_][\w.\[\]]*(?:\([^;\n()]*\))?\.(?:transfer|transferFrom)\s*\((?P<args>[^\n;]*)\))[ \t]*;"
)


def _rewrite_statements(source, function_name, pattern, build, accept=lambda match: True):
    masked = mask_comments_and_strings(source)
    spans = _function_bodies(masked, function_name) if function_name else []
    matches = [
        m
        for start, end in spans
        for m in pattern.finditer(masked, start, end + 1)
        if m.group("expr").split("(")[0].split(".")[0].strip() not in _CONTROL_KEYWORDS and accept(m)
    ]
    if not matches:
        return source, False
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

    # `IFoo(account).call(data)` is a high-level call to a method that happens to be named
    # call; it returns the interface's own type, so the (bool, bytes) form would not compile.
    # A cast to a type name (leading capital) marks it; address variables and payable() do not.
    return _rewrite_statements(
        source, function_name, _LOW_LEVEL_STATEMENT, build,
        accept=lambda m: not re.match(r"\s*[A-Z]\w*\s*\(", m.group("expr")),
    )


def _require_token_transfer_success(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    fix = f" // FIX {vuln_id}" if vuln_id else ""

    def build(indent: str, expr: str) -> str:
        return f'{indent}require({expr}, "Token transfer failed");{fix}'

    # ETH transfer takes one argument and returns nothing; only the ERC20 forms are wrapped.
    return _rewrite_statements(
        source, function_name, _TOKEN_TRANSFER_STATEMENT, build,
        accept=lambda m: _top_level_args(m.group("args")) >= 2,
    )


_OWNER_STATE_VARIABLE = re.compile(
    r"\baddress(?:\s+payable)?\s+(?:(?:public|private|internal|immutable|constant)\s+)*owner\b"
)
_HEADER_KEYWORDS = {"external", "public", "internal", "private", "payable", "view", "pure", "virtual", "override"}


def _require_owner(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    """Guard an unprotected selfdestruct with the contract's own ``owner``.

    Only applied when the contract already declares an ``address owner`` and the function
    has no modifier at all, so the guard never duplicates or contradicts an existing one.
    """
    masked = mask_comments_and_strings(source)
    if not function_name or not _OWNER_STATE_VARIABLE.search(masked):
        return source, False
    match = re.search(rf"\bfunction\s+{re.escape(function_name)}\s*\(([^)]*)\)([^{{;]*){{", masked, re.DOTALL)
    if not match:
        return source, False
    header = re.sub(r"returns\s*\([^)]*\)", "", match.group(2))
    if set(re.findall(r"[A-Za-z_]\w*", header)) - _HEADER_KEYWORDS:
        return source, False

    brace_index = masked.find("{", match.end() - 1)
    end_index = matching_brace(masked, brace_index)
    body = masked[brace_index:end_index + 1]
    if re.search(r"msg\.sender\s*[!=]=\s*owner\b|\bowner\s*[!=]=\s*msg\.sender", body):
        return source, False
    fix = f" // FIX {vuln_id}" if vuln_id else ""
    return _insert_first_statement(
        source, match.start(), brace_index, end_index, f'require(msg.sender == owner, "Not owner");{fix}'
    )


_SEND_STATEMENT = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<expr>[A-Za-z_][^\n;=]*?\.send\s*\([^\n;]*\))[ \t]*;"
)


def _require_send_success(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    fix = f" // FIX {vuln_id}" if vuln_id else ""

    def build(indent: str, expr: str) -> str:
        return f'{indent}require({expr}, "Send failed");{fix}'

    return _rewrite_statements(source, function_name, _SEND_STATEMENT, build)


_TRANSFER_FROM_SOURCE = re.compile(r"\.transferFrom\s*\(\s*([A-Za-z_]\w*)\s*,")


def _use_msg_sender_as_token_source(source: str, function_name: str, vuln_id: str) -> tuple[str, bool]:
    """``token.transferFrom(from, ...)`` -> ``token.transferFrom(msg.sender, ...)``.

    Slither only accepts a literal msg.sender as the source: a ``require(from == msg.sender)``
    guard leaves the finding in place. Applied only where ``from`` is a parameter of the flagged
    function and the function never mentions msg.sender or a modifier, because an allowance or
    operator check keyed on the caller means the pull is authorized some other way and the
    rewrite would break it.
    """
    masked = mask_comments_and_strings(source)
    edits: list[tuple[int, int]] = []
    for match in re.finditer(
        rf"\bfunction\s+{re.escape(function_name)}\s*\(([^)]*)\)([^{{;]*){{", masked, re.DOTALL
    ):
        parameters = set(re.findall(r"(\w+)\s*(?:,|$)", match.group(1).strip()))
        header = re.sub(r"returns\s*\([^)]*\)", "", match.group(2))
        if set(re.findall(r"[A-Za-z_]\w*", header)) - _HEADER_KEYWORDS:
            continue
        brace_index = masked.find("{", match.end() - 1)
        end_index = matching_brace(masked, brace_index)
        body = masked[brace_index:end_index + 1]
        if "msg.sender" in body:
            continue
        for call in _TRANSFER_FROM_SOURCE.finditer(masked, brace_index, end_index + 1):
            if call.group(1) in parameters:
                edits.append((call.start(1), call.end(1)))
    if not edits or not function_name:
        return source, False
    for start, end in reversed(edits):
        line_end = source.find("\n", end)
        line_end = len(source) if line_end == -1 else line_end
        source = source[:start] + "msg.sender" + source[end:line_end] + (
            f" // FIX {vuln_id}" if vuln_id else ""
        ) + source[line_end:]
    return source, True


_STATEMENT_PATCHES = {
    "arbitrary-send-erc20": _use_msg_sender_as_token_source,
    "suicidal": _require_owner,
    "unchecked-send": _require_send_success,
    "tx-origin": _replace_tx_origin,
    "unchecked-lowlevel": _require_low_level_success,
    "unchecked-transfer": _require_token_transfer_success,
}
