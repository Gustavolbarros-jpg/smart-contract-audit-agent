"""Call-graph based context expansion.

Line-window context (``build_contract_brief``'s ``radius``) slices by proximity in
the *file*. Vulnerability logic is often reached through a call: the guard that a
finding appears to be missing may live in a callee or in an applied modifier, and a
window never reaches it. This module slices by proximity in the *call graph*.

Depth defaults to 2 following the measurement in CCIHunter (ACM TOSEM 10.1145/3764867):
across 14,039 functions in 16 DApp projects, 84.50% have call depth 1 and 11.97%
depth 2, so depth 2 covers ~96% of cases before context size stops paying off.
"""

from __future__ import annotations

import re

from core.solidity_source import (
    Definition,
    mask_comments_and_strings,
    numbered_snippet,
    parse_definitions,
)


DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_CHARS = 6000

CALL_RE = re.compile(r"(?:\bthis\s*\.\s*)?\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Control flow, builtins and value types read like calls but resolve to nothing.
NOT_A_CALL = frozenset(
    {
        "if", "for", "while", "switch", "catch", "return", "returns",
        "require", "assert", "revert", "emit", "new", "delete", "try",
        "function", "modifier", "constructor", "fallback", "receive",
        "address", "payable", "bool", "string", "bytes", "byte",
        "keccak256", "sha256", "sha3", "ripemd160", "ecrecover", "addmod",
        "mulmod", "selfdestruct", "suicide", "blockhash", "gasleft",
        "type", "abi", "msg", "block", "tx", "super", "this",
        "memory", "storage", "calldata", "wei", "gwei", "ether",
        "seconds", "minutes", "hours", "days", "weeks",
    }
)

_NUMERIC_TYPE_RE = re.compile(r"^(?:u?int|bytes)\d*$")


def _is_callable_name(name: str) -> bool:
    return name not in NOT_A_CALL and not _NUMERIC_TYPE_RE.match(name)


def called_names(definition: Definition) -> list[str]:
    """Names invoked by a definition: applied modifiers plus in-body calls.

    Applied modifiers are included deliberately — for access-control and reentrancy
    findings the guard usually lives in the modifier, not in the function body.
    """
    masked = mask_comments_and_strings(definition.body)
    brace = masked.find("{")
    header, body = (masked[:brace], masked[brace:]) if brace != -1 else ("", masked)

    names: list[str] = []

    # Header: skip the parameter list, then take bare identifiers (applied modifiers).
    paren = header.find("(")
    if paren != -1:
        depth = 0
        tail_start = len(header)
        for index in range(paren, len(header)):
            if header[index] == "(":
                depth += 1
            elif header[index] == ")":
                depth -= 1
                if depth == 0:
                    tail_start = index + 1
                    break
        tail = header[tail_start:]
        tail = re.sub(r"\breturns\s*\([^)]*\)", " ", tail)
        for token in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)", tail):
            if token in {
                "public", "private", "internal", "external",
                "view", "pure", "payable", "virtual", "override", "returns",
            }:
                continue
            if _is_callable_name(token):
                names.append(token)

    for match in CALL_RE.finditer(body):
        name = match.group(1)
        if _is_callable_name(name):
            names.append(name)

    return list(dict.fromkeys(names))


def _index_by_name(definitions: list[Definition]) -> dict[str, list[Definition]]:
    index: dict[str, list[Definition]] = {}
    for definition in definitions:
        index.setdefault(definition.name, []).append(definition)
    return index


def enclosing_definition(definitions: list[Definition], line: int) -> Definition | None:
    """Innermost definition whose line span contains ``line``."""
    candidates = [d for d in definitions if d.start_line <= line <= d.end_line]
    if not candidates:
        return None
    return min(candidates, key=lambda d: d.end_line - d.start_line)


def collect_reachable(
    source: str,
    entries: list[Definition],
    max_depth: int = DEFAULT_MAX_DEPTH,
    definitions: list[Definition] | None = None,
) -> list[tuple[Definition, int, str]]:
    """Breadth-first walk from ``entries``, returning ``(definition, depth, caller)``.

    Overloads resolve to every definition sharing the name — without type checking
    there is no way to pick one, and showing both is safer than guessing.
    """
    definitions = parse_definitions(source) if definitions is None else definitions
    by_name = _index_by_name(definitions)

    seen: set[tuple[str, int]] = set()
    ordered: list[tuple[Definition, int, str]] = []
    frontier = [(entry, 0, "") for entry in entries]

    while frontier:
        definition, depth, caller = frontier.pop(0)
        key = (definition.name, definition.start_line)
        if key in seen:
            continue
        seen.add(key)
        ordered.append((definition, depth, caller))

        if depth >= max_depth:
            continue

        for name in called_names(definition):
            for target in by_name.get(name, []):
                if (target.name, target.start_line) not in seen:
                    frontier.append((target, depth + 1, definition.name))

    return ordered


def build_call_context(
    source: str,
    findings: list[dict],
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> str:
    """Render the call-graph context for the functions containing ``findings``.

    Returns an empty string when no finding maps to a definition (state variable,
    pragma), leaving the caller's line-window context as the only source.
    """
    definitions = parse_definitions(source)
    if not definitions:
        return ""

    entries: list[Definition] = []
    for finding in findings:
        for line in _finding_lines(finding):
            found = enclosing_definition(definitions, line)
            if found is not None and found not in entries:
                entries.append(found)

        name = _finding_function_name(finding)
        if name:
            for candidate in definitions:
                if candidate.name == name and candidate not in entries:
                    entries.append(candidate)

    if not entries:
        return ""

    blocks: list[str] = []
    used = 0
    truncated = 0

    for definition, depth, caller in collect_reachable(source, entries, max_depth, definitions):
        origin = "entry" if depth == 0 else f"called by {caller}, depth {depth}"
        head = (
            f"--- {definition.header} ({definition.kind}, {origin}, "
            f"lines {definition.start_line}-{definition.end_line})"
        )
        snippet = numbered_snippet(source, definition.start_line, definition.end_line)
        block = f"{head}\n{snippet}"

        if used + len(block) > max_chars and blocks:
            truncated += 1
            continue
        blocks.append(block)
        used += len(block)

    if not blocks:
        return ""

    header = f"CALL_CONTEXT (depth<={max_depth})"
    if truncated:
        header += f" [{truncated} definition(s) omitted for size]"
    return "\n\n".join([header, *blocks])


def _finding_lines(finding: dict) -> list[int]:
    return [int(number) for number in re.findall(r"\d+", str(finding.get("line", "")))]


def _finding_function_name(finding: dict) -> str:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)", str(finding.get("function", "")))
    return match.group(1) if match else ""
