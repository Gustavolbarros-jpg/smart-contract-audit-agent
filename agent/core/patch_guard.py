"""Minimal-diff guard for LLM-generated Solidity patches."""

from __future__ import annotations

from collections import Counter, defaultdict
import difflib
import re
from typing import Any


def analyze_patch(
    original_source: str,
    fixed_source: str,
    confirmed_findings: list[dict[str, Any]] | None = None,
    diagnosis: dict[str, Any] | list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compare an LLM patch against confirmed findings and flag broad edits."""

    confirmed_findings = confirmed_findings or []
    original_blocks = _find_code_blocks(original_source)
    fixed_blocks = _find_code_blocks(fixed_source)
    allowed_ranges = _build_allowed_ranges(
        original_source,
        confirmed_findings,
        diagnosis,
        original_blocks,
    )

    changed_hunks = _changed_hunks(original_source, fixed_source, allowed_ranges)
    issues: list[dict[str, Any]] = []
    issues.extend(_string_literal_issues(original_source, fixed_source))
    issues.extend(_public_signature_issues(original_blocks, fixed_blocks))
    issues.extend(_state_variable_issues(original_source, fixed_source))
    issues.extend(_comment_issues(original_source, fixed_source, allowed_ranges))
    issues.extend(_outside_target_change_issues(changed_hunks))

    error_count = sum(1 for issue in issues if issue["severity"] == "error")
    warning_count = sum(1 for issue in issues if issue["severity"] == "warning")
    status = "blocked" if error_count else "warning" if warning_count else "ok"

    return {
        "status": status,
        "should_block": bool(error_count),
        "summary": {
            "changed_hunks": len(changed_hunks),
            "issues": len(issues),
            "errors": error_count,
            "warnings": warning_count,
        },
        "allowed_ranges": allowed_ranges,
        "issues": issues,
        "changed_hunks": changed_hunks,
    }


def compact_patch_guard_report(report: dict[str, Any], limit: int = 8) -> dict[str, Any]:
    """Build a small report suitable for an LLM repair prompt."""

    issues = report.get("issues", [])
    blocking_issues = [
        _compact_issue(issue)
        for issue in issues
        if issue.get("severity") == "error"
    ][:limit]
    warnings = [
        _compact_issue(issue)
        for issue in issues
        if issue.get("severity") == "warning"
    ][:limit]
    changed_hunks = [
        _compact_hunk(hunk)
        for hunk in report.get("changed_hunks", [])
        if not hunk.get("allowed") or _hunk_touches_issue(hunk, issues)
    ][:limit]

    return {
        "status": report.get("status", ""),
        "summary": report.get("summary", {}),
        "allowed_ranges": report.get("allowed_ranges", []),
        "blocking_issues": blocking_issues,
        "warnings": warnings,
        "relevant_hunks": changed_hunks,
    }


def repair_obvious_patch_guard_issues(
    original_source: str,
    fixed_source: str,
    report: dict[str, Any],
) -> tuple[str, list[dict[str, Any]]]:
    """Deterministically undo simple unrelated edits caught by the guard."""

    issue_types = {issue.get("type") for issue in report.get("issues", [])}
    repaired = fixed_source
    corrections: list[dict[str, Any]] = []

    if "modified_string_literal" in issue_types:
        repaired, literal_corrections = _restore_replaced_line_string_literals(
            original_source,
            repaired,
        )
        corrections.extend(literal_corrections)

    return repaired, corrections


def _restore_replaced_line_string_literals(
    original_source: str,
    fixed_source: str,
) -> tuple[str, list[dict[str, Any]]]:
    original_lines = original_source.splitlines()
    fixed_lines = fixed_source.splitlines()
    keep_trailing_newline = fixed_source.endswith("\n")
    matcher = difflib.SequenceMatcher(None, original_lines, fixed_lines)
    repaired_lines = list(fixed_lines)
    corrections: list[dict[str, Any]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag != "replace" or (i2 - i1) != (j2 - j1):
            continue

        for offset in range(i2 - i1):
            original_line = original_lines[i1 + offset]
            fixed_line = repaired_lines[j1 + offset]
            restored = _restore_line_string_literals(original_line, fixed_line)
            if restored == fixed_line:
                continue
            repaired_lines[j1 + offset] = restored
            corrections.append(
                {
                    "type": "restore_string_literals",
                    "original_line": i1 + offset + 1,
                    "fixed_line": j1 + offset + 1,
                }
            )

    repaired = "\n".join(repaired_lines)
    if keep_trailing_newline:
        repaired += "\n"
    return repaired, corrections


def _restore_line_string_literals(original_line: str, fixed_line: str) -> str:
    original_literals = _line_string_spans(original_line)
    fixed_literals = _line_string_spans(fixed_line)
    if not original_literals or len(original_literals) != len(fixed_literals):
        return fixed_line
    if [item["raw"] for item in original_literals] == [item["raw"] for item in fixed_literals]:
        return fixed_line

    restored = fixed_line
    for original, fixed in reversed(list(zip(original_literals, fixed_literals))):
        restored = restored[:fixed["start"]] + original["raw"] + restored[fixed["end"]:]
    return restored


def _line_string_spans(line: str) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    i = 0
    quote = ""
    start = 0

    while i < len(line):
        char = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not quote:
            if char == "/" and nxt == "/":
                break
            if char in ("'", '"'):
                quote = char
                start = i
            i += 1
            continue

        if char == "\\" and i + 1 < len(line):
            i += 2
            continue
        if char == quote:
            spans.append({"start": start, "end": i + 1, "raw": line[start:i + 1]})
            quote = ""
        i += 1

    return spans


def _compact_issue(issue: dict[str, Any]) -> dict[str, Any]:
    return {
        "severity": issue.get("severity", ""),
        "type": issue.get("type", ""),
        "line": issue.get("line", ""),
        "detail": issue.get("detail", ""),
        "evidence": issue.get("evidence", {}),
    }


def _compact_hunk(hunk: dict[str, Any]) -> dict[str, Any]:
    return {
        "tag": hunk.get("tag", ""),
        "original_start": hunk.get("original_start", ""),
        "original_end": hunk.get("original_end", ""),
        "fixed_start": hunk.get("fixed_start", ""),
        "fixed_end": hunk.get("fixed_end", ""),
        "allowed": hunk.get("allowed", False),
        "original_excerpt": hunk.get("original_excerpt", []),
        "fixed_excerpt": hunk.get("fixed_excerpt", []),
    }


def _hunk_touches_issue(hunk: dict[str, Any], issues: list[dict[str, Any]]) -> bool:
    start = hunk.get("original_start", 0)
    end = hunk.get("original_end", 0)
    if not isinstance(start, int) or not isinstance(end, int):
        return False
    for issue in issues:
        line = issue.get("line")
        if isinstance(line, int) and start <= line <= end:
            return True
    return False


def _issue(
    severity: str,
    issue_type: str,
    detail: str,
    line: int | str = "",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "severity": severity,
        "type": issue_type,
        "line": line,
        "detail": detail,
    }
    if evidence:
        item["evidence"] = evidence
    return item


def _mask_comments_and_strings(source: str) -> str:
    out: list[str] = []
    i = 0
    state = "code"
    quote = ""

    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char == "/" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                out.extend([" ", " "])
                i += 2
                state = "block_comment"
                continue
            if char in ("'", '"'):
                out.append(" ")
                quote = char
                i += 1
                state = "string"
                continue
            out.append(char)
            i += 1
            continue

        if state == "line_comment":
            out.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                state = "code"
                continue
            out.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < len(source):
                out.append("\n" if char == "\n" else " ")
                out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            out.append("\n" if char == "\n" else " ")
            if char == quote:
                state = "code"
            i += 1

    return "".join(out)


def _line_no(source: str, index: int) -> int:
    return source.count("\n", 0, max(index, 0)) + 1


def _matching_brace(masked_source: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked_source)):
        char = masked_source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(masked_source) - 1


def _find_code_blocks(source: str) -> list[dict[str, Any]]:
    masked = _mask_comments_and_strings(source)
    blocks: list[dict[str, Any]] = []

    for match in re.finditer(r"\b(function|modifier|constructor)\b", masked):
        kind = match.group(1)
        name = "constructor"
        if kind in {"function", "modifier"}:
            name_match = re.match(
                rf"{kind}\s+([A-Za-z_][A-Za-z0-9_]*)",
                masked[match.start() :],
            )
            if not name_match:
                continue
            name = name_match.group(1)

        semi = masked.find(";", match.end())
        brace = masked.find("{", match.end())
        if brace != -1 and (semi == -1 or brace < semi):
            header_end = brace
            end_index = _matching_brace(masked, brace)
        elif semi != -1:
            header_end = semi
            end_index = semi
        else:
            continue

        header = source[match.start() : header_end].strip()
        visibility = _visibility(header)
        blocks.append(
            {
                "kind": kind,
                "name": name,
                "visibility": visibility,
                "start_line": _line_no(source, match.start()),
                "end_line": _line_no(source, end_index),
                "header": _collapse_space(header),
                "canonical_signature": _canonical_function_header(kind, header),
            }
        )

    return blocks


def _visibility(header: str) -> str:
    match = re.search(r"\b(public|external|internal|private)\b", header)
    return match.group(1) if match else ""


def _collapse_space(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip())


def _canonical_function_header(kind: str, header: str) -> str:
    cleaned = _collapse_space(header)
    if kind != "function":
        return cleaned

    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", cleaned)
    if not match:
        return cleaned

    name = match.group(1)
    open_paren = cleaned.find("(", match.end() - 1)
    close_paren = _matching_paren(cleaned, open_paren)
    if close_paren == -1:
        return cleaned

    params = cleaned[open_paren + 1 : close_paren]
    suffix = cleaned[close_paren + 1 :]
    visibility = _visibility(suffix)
    mutability = " ".join(
        token for token in ("payable", "view", "pure") if re.search(rf"\b{token}\b", suffix)
    )
    returns = ""
    returns_match = re.search(r"\breturns\s*\(", suffix)
    if returns_match:
        ret_open = suffix.find("(", returns_match.end() - 1)
        ret_close = _matching_paren(suffix, ret_open)
        if ret_close != -1:
            returns = suffix[ret_open + 1 : ret_close]

    param_types = ",".join(_canonical_param(param) for param in _split_params(params))
    return_types = ",".join(_canonical_param(param) for param in _split_params(returns))
    pieces = [f"{name}({param_types})"]
    if visibility:
        pieces.append(visibility)
    if mutability:
        pieces.append(mutability)
    pieces.append(f"returns({return_types})")
    return " ".join(pieces)


def _matching_paren(value: str, open_index: int) -> int:
    if open_index < 0:
        return -1
    depth = 0
    for index in range(open_index, len(value)):
        char = value[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _split_params(params: str) -> list[str]:
    if not params.strip():
        return []

    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(params):
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(params[start:index].strip())
            start = index + 1
    parts.append(params[start:].strip())
    return [part for part in parts if part]


def _canonical_param(param: str) -> str:
    normalized = _normalize_type_spacing(param)
    tokens = normalized.split()
    if len(tokens) <= 1:
        return normalized

    last = tokens[-1]
    if _looks_like_param_name(last):
        tokens = tokens[:-1]
    return _normalize_type_spacing(" ".join(tokens))


def _looks_like_param_name(token: str) -> bool:
    if token in {"memory", "calldata", "storage", "payable"}:
        return False
    if re.match(r"^(u?int)([0-9]+)?(\[\])*$", token):
        return False
    if re.match(r"^bytes([0-9]+)?(\[\])*$", token):
        return False
    if token in {"address", "bool", "string"}:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", token))


def _normalize_type_spacing(value: str) -> str:
    value = _collapse_space(value)
    value = re.sub(r"\s*=>\s*", "=>", value)
    value = re.sub(r"\s*([(),\[\]])\s*", r"\1", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _build_allowed_ranges(
    source: str,
    findings: list[dict[str, Any]],
    diagnosis: dict[str, Any] | list[dict[str, Any]] | None,
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    max_line = len(source.splitlines())

    def add_for_line(line: int, reason: str) -> None:
        block = _block_containing_line(blocks, line)
        if block:
            ranges.append(
                {
                    "start": block["start_line"],
                    "end": block["end_line"],
                    "reason": f"{reason}: {block['kind']} {block['name']}",
                }
            )
            return
        ranges.append(
            {
                "start": max(1, line - 3),
                "end": min(max_line, line + 3),
                "reason": reason,
            }
        )

    def add_for_function(name: str, reason: str) -> None:
        for block in blocks:
            if block["name"] == name:
                ranges.append(
                    {
                        "start": block["start_line"],
                        "end": block["end_line"],
                        "reason": f"{reason}: {block['kind']} {name}",
                    }
                )

    for finding in findings:
        finding_id = finding.get("id", "finding")
        for line in _lines_from_finding(finding):
            add_for_line(line, finding_id)
        for name in _function_names_from_finding(finding):
            add_for_function(name, finding_id)
        if finding.get("type") == "tx-origin":
            for block in _tx_origin_modifier_blocks(source, blocks):
                ranges.append(
                    {
                        "start": block["start_line"],
                        "end": block["end_line"],
                        "reason": f"{finding_id}: modifier {block['name']} uses tx.origin",
                    }
                )

    for failure in _diagnosis_failures(diagnosis):
        failure_id = failure.get("id", "diagnosis")
        line = failure.get("linha")
        if isinstance(line, int):
            add_for_line(line, failure_id)
        elif isinstance(line, str) and line.isdigit():
            add_for_line(int(line), failure_id)

    return _merge_ranges(ranges)


def _tx_origin_modifier_blocks(
    source: str,
    blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return modifier blocks whose body contains a tx.origin reference."""
    lines = source.splitlines()
    result = []
    for block in blocks:
        if block.get("kind") != "modifier":
            continue
        start = block["start_line"] - 1
        end = block["end_line"]
        snippet = "\n".join(lines[start:end])
        if "tx.origin" in snippet:
            result.append(block)
    return result


def _block_containing_line(blocks: list[dict[str, Any]], line: int) -> dict[str, Any] | None:
    containing = [
        block for block in blocks if block["start_line"] <= line <= block["end_line"]
    ]
    if not containing:
        return None
    return min(containing, key=lambda block: block["end_line"] - block["start_line"])


def _lines_from_finding(finding: dict[str, Any]) -> list[int]:
    lines: list[int] = []
    lines.extend(_parse_line_spec(finding.get("line", "")))
    for element in finding.get("elements", []) or []:
        if isinstance(element, dict):
            lines.extend(_parse_line_spec(element.get("line", "")))
    return sorted(set(lines))


def _parse_line_spec(value: Any) -> list[int]:
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


def _function_names_from_finding(finding: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    if finding.get("function"):
        candidates.append(str(finding["function"]))
    for element in finding.get("elements", []) or []:
        if isinstance(element, dict) and element.get("type") == "function":
            candidates.append(str(element.get("name", "")))

    names: list[str] = []
    for candidate in candidates:
        if not candidate or candidate == "modifier/function":
            continue
        if "." in candidate:
            candidate = candidate.rsplit(".", 1)[-1]
        match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", candidate)
        if match:
            names.append(match.group(1))
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate):
            names.append(candidate)

    return sorted(set(names))


def _diagnosis_failures(
    diagnosis: dict[str, Any] | list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if diagnosis is None:
        return []
    if isinstance(diagnosis, list):
        return [item for item in diagnosis if isinstance(item, dict)]
    failures = diagnosis.get("falhas", []) if isinstance(diagnosis, dict) else []
    return [item for item in failures if isinstance(item, dict)]


def _merge_ranges(ranges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not ranges:
        return []

    ordered = sorted(ranges, key=lambda item: (item["start"], item["end"]))
    merged: list[dict[str, Any]] = []
    for item in ordered:
        if not merged or item["start"] > merged[-1]["end"] + 1:
            merged.append(
                {
                    "start": item["start"],
                    "end": item["end"],
                    "reason": item["reason"],
                }
            )
            continue
        merged[-1]["end"] = max(merged[-1]["end"], item["end"])
        if item["reason"] not in merged[-1]["reason"]:
            merged[-1]["reason"] += f"; {item['reason']}"
    return merged


def _changed_hunks(
    original_source: str,
    fixed_source: str,
    allowed_ranges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    original_lines = original_source.splitlines()
    fixed_lines = fixed_source.splitlines()
    matcher = difflib.SequenceMatcher(None, original_lines, fixed_lines)
    hunks: list[dict[str, Any]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        original_start = i1 + 1
        original_end = i2 if i2 > i1 else i1 + 1
        fixed_start = j1 + 1
        fixed_end = j2 if j2 > j1 else j1 + 1
        hunks.append(
            {
                "tag": tag,
                "original_start": original_start,
                "original_end": original_end,
                "fixed_start": fixed_start,
                "fixed_end": fixed_end,
                "allowed": _range_allowed(original_start, original_end, allowed_ranges),
                "original_excerpt": original_lines[i1:min(i2, i1 + 3)],
                "fixed_excerpt": fixed_lines[j1:min(j2, j1 + 3)],
            }
        )

    return hunks


def _range_allowed(
    start: int,
    end: int,
    allowed_ranges: list[dict[str, Any]],
    margin: int = 1,
) -> bool:
    for allowed in allowed_ranges:
        if start <= allowed["end"] + margin and end >= allowed["start"] - margin:
            return True
    return False


def _string_literals(source: str) -> list[dict[str, Any]]:
    literals: list[dict[str, Any]] = []
    i = 0
    state = "code"
    quote = ""
    start = 0
    value_chars: list[str] = []

    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char == "/" and nxt == "/":
                state = "line_comment"
                i += 2
                continue
            if char == "/" and nxt == "*":
                state = "block_comment"
                i += 2
                continue
            if char in ("'", '"'):
                state = "string"
                quote = char
                start = i
                value_chars = []
            i += 1
            continue

        if state == "line_comment":
            if char == "\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                i += 2
                continue
            i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < len(source):
                value_chars.append(char)
                value_chars.append(nxt)
                i += 2
                continue
            if char == quote:
                literals.append(
                    {
                        "value": "".join(value_chars),
                        "line": _line_no(source, start),
                    }
                )
                state = "code"
                i += 1
                continue
            value_chars.append(char)
            i += 1

    return literals


def _string_literal_issues(original_source: str, fixed_source: str) -> list[dict[str, Any]]:
    original_literals = _string_literals(original_source)
    fixed_counts = Counter(item["value"] for item in _string_literals(fixed_source))
    original_by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for literal in original_literals:
        original_by_value[literal["value"]].append(literal)

    issues: list[dict[str, Any]] = []
    for value, literals in original_by_value.items():
        missing = len(literals) - fixed_counts[value]
        for literal in literals[: max(0, missing)]:
            issues.append(
                _issue(
                    "error",
                    "modified_string_literal",
                    "An original string literal disappeared or was modified.",
                    literal["line"],
                    {"original": value},
                )
            )
    return issues


def _public_signature_issues(
    original_blocks: list[dict[str, Any]],
    fixed_blocks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    original_public = [
        block for block in original_blocks
        if block["kind"] == "function" and block["visibility"] in {"public", "external"}
    ]
    fixed_public = [
        block for block in fixed_blocks
        if block["kind"] == "function" and block["visibility"] in {"public", "external"}
    ]
    fixed_signatures = {block["canonical_signature"] for block in fixed_public}
    fixed_names = {block["name"] for block in fixed_public}
    original_names = {block["name"] for block in original_public}

    issues: list[dict[str, Any]] = []
    for block in original_public:
        if block["canonical_signature"] in fixed_signatures:
            continue
        if block["name"] in fixed_names:
            issues.append(
                _issue(
                    "error",
                    "public_external_signature_changed",
                    "A public/external function signature changed.",
                    block["start_line"],
                    {
                        "function": block["name"],
                        "original_signature": block["canonical_signature"],
                    },
                )
            )
        else:
            issues.append(
                _issue(
                    "error",
                    "public_external_function_missing",
                    "A public/external function was removed or renamed.",
                    block["start_line"],
                    {
                        "function": block["name"],
                        "original_signature": block["canonical_signature"],
                    },
                )
            )

    for block in fixed_public:
        if block["name"] not in original_names:
            issues.append(
                _issue(
                    "warning",
                    "public_external_function_added",
                    "A new public/external function was added.",
                    "",
                    {
                        "function": block["name"],
                        "fixed_signature": block["canonical_signature"],
                    },
                )
            )

    return issues


def _find_state_variables(source: str) -> list[dict[str, Any]]:
    masked = _mask_comments_and_strings(source)
    source_lines = source.splitlines()
    masked_lines = masked.splitlines()
    variables: list[dict[str, Any]] = []
    depth = 0
    pending = ""
    pending_start = 0

    for line_no, masked_line in enumerate(masked_lines, start=1):
        stripped = masked_line.strip()
        if depth == 1 and stripped:
            if not pending_start:
                pending_start = line_no
            pending = f"{pending} {stripped}".strip()

            if "{" in stripped:
                pending = ""
                pending_start = 0
            elif ";" in stripped:
                declaration = pending.split(";", 1)[0].strip()
                source_declaration = " ".join(
                    line.strip()
                    for line in source_lines[pending_start - 1 : line_no]
                ).split(";", 1)[0]
                parsed = _parse_state_variable(declaration, source_declaration, pending_start)
                if parsed:
                    variables.append(parsed)
                pending = ""
                pending_start = 0

        depth += masked_line.count("{") - masked_line.count("}")
        if depth != 1:
            pending = ""
            pending_start = 0

    return variables


def _parse_state_variable(
    masked_declaration: str,
    source_declaration: str,
    line_no: int,
) -> dict[str, Any] | None:
    if re.search(
        r"\b(function|modifier|constructor|event|error|struct|enum|using|import|contract|interface|library)\b",
        masked_declaration,
    ):
        return None
    if "(" in masked_declaration and not masked_declaration.strip().startswith("mapping"):
        return None

    before_assignment = source_declaration.split("=", 1)[0].strip()
    before_assignment = before_assignment.split(",", 1)[0].strip()
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\]\s*)*$", before_assignment)
    if not match:
        return None

    name = match.group(1)
    canonical = _normalize_type_spacing(before_assignment)
    return {
        "name": name,
        "line": line_no,
        "canonical": canonical,
    }


def _state_variable_issues(original_source: str, fixed_source: str) -> list[dict[str, Any]]:
    original_vars = {item["name"]: item for item in _find_state_variables(original_source)}
    fixed_vars = {item["name"]: item for item in _find_state_variables(fixed_source)}

    issues: list[dict[str, Any]] = []
    for name, original in original_vars.items():
        fixed = fixed_vars.get(name)
        if not fixed:
            issues.append(
                _issue(
                    "error",
                    "state_variable_missing_or_renamed",
                    "An original state variable disappeared or was renamed.",
                    original["line"],
                    {"state_variable": name},
                )
            )
            continue
        if fixed["canonical"] != original["canonical"]:
            issues.append(
                _issue(
                    "error",
                    "state_variable_declaration_changed",
                    "An original state variable declaration changed.",
                    original["line"],
                    {
                        "state_variable": name,
                        "original": original["canonical"],
                        "fixed": fixed["canonical"],
                    },
                )
            )
    return issues


def _comments(source: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    i = 0
    state = "code"
    quote = ""

    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char in ("'", '"'):
                state = "string"
                quote = char
                i += 1
                continue
            if char == "/" and nxt == "/":
                start = i
                end = source.find("\n", i)
                if end == -1:
                    end = len(source)
                comments.append(
                    {
                        "text": source[start:end].strip(),
                        "start_line": _line_no(source, start),
                        "end_line": _line_no(source, end),
                    }
                )
                i = end
                continue
            if char == "/" and nxt == "*":
                start = i
                end = source.find("*/", i + 2)
                if end == -1:
                    end = len(source)
                else:
                    end += 2
                comments.append(
                    {
                        "text": _collapse_space(source[start:end]),
                        "start_line": _line_no(source, start),
                        "end_line": _line_no(source, end),
                    }
                )
                i = end
                continue
            i += 1
            continue

        if state == "string":
            if char == "\\" and i + 1 < len(source):
                i += 2
                continue
            if char == quote:
                state = "code"
            i += 1

    return comments


def _comment_issues(
    original_source: str,
    fixed_source: str,
    allowed_ranges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    fixed_counts = Counter(comment["text"] for comment in _comments(fixed_source))
    issues: list[dict[str, Any]] = []

    for comment in _comments(original_source):
        if fixed_counts[comment["text"]] > 0:
            fixed_counts[comment["text"]] -= 1
            continue
        if _range_allowed(comment["start_line"], comment["end_line"], allowed_ranges):
            continue
        issues.append(
            _issue(
                "warning",
                "comment_changed_outside_target",
                "An original comment outside the target range disappeared or changed.",
                comment["start_line"],
                {"comment": comment["text"]},
            )
        )

    return issues


def _outside_target_change_issues(changed_hunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for hunk in changed_hunks:
        if hunk["allowed"]:
            continue
        issues.append(
            _issue(
                "warning",
                "change_outside_target_range",
                "A source hunk changed outside the lines/functions tied to confirmed findings.",
                hunk["original_start"],
                {
                    "tag": hunk["tag"],
                    "original_start": hunk["original_start"],
                    "original_end": hunk["original_end"],
                    "fixed_start": hunk["fixed_start"],
                    "fixed_end": hunk["fixed_end"],
                },
            )
        )
    return issues
