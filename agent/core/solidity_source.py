"""Shared primitives for scanning Solidity source text.

Masking and brace matching are duplicated in ``contract_context``, ``patch_guard``
and ``deterministic_patch``. New code should use this module; the older copies are
kept untouched for now to avoid a wide refactor in the same change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


DEFINITION_RE = re.compile(
    r"\b(function\s+([A-Za-z_][A-Za-z0-9_]*)|modifier\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|constructor|fallback|receive)\s*\("
)

CONTRACT_RE = re.compile(
    r"\b(?:contract|library|interface|abstract\s+contract)\s+([A-Za-z_][A-Za-z0-9_]*)"
)


@dataclass(frozen=True)
class Definition:
    """A function, modifier, constructor, fallback or receive with a body."""

    name: str
    kind: str
    signature: str
    start_line: int
    end_line: int
    body: str
    contract: str = ""

    @property
    def header(self) -> str:
        return f"{self.contract}.{self.name}" if self.contract else self.name


def mask_comments_and_strings(source: str) -> str:
    """Blank out comments and string literals, preserving offsets and newlines."""
    out: list[str] = []
    index = 0
    state = "code"
    quote = ""

    while index < len(source):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if char == "/" and nxt == "/":
                out.extend([" ", " "])
                index += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                out.extend([" ", " "])
                index += 2
                state = "block_comment"
                continue
            if char in ("'", '"'):
                out.append(" ")
                quote = char
                index += 1
                state = "string"
                continue
            out.append(char)
            index += 1
            continue

        if state == "line_comment":
            out.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                out.extend([" ", " "])
                index += 2
                state = "code"
                continue
            out.append("\n" if char == "\n" else " ")
            index += 1
            continue

        # state == "string"
        out.append("\n" if char == "\n" else " ")
        if char == "\\" and index + 1 < len(source):
            out.append("\n" if nxt == "\n" else " ")
            index += 2
            continue
        if char == quote:
            state = "code"
        index += 1

    return "".join(out)


def matching_brace(masked_source: str, open_index: int) -> int:
    """Index of the ``}`` closing the ``{`` at ``open_index``, on masked source."""
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


def _matching_paren(masked_source: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked_source)):
        char = masked_source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _line_of(masked_source: str, offset: int) -> int:
    return masked_source.count("\n", 0, offset) + 1


def _enclosing_contract(masked_source: str, offset: int) -> str:
    last = ""
    for match in CONTRACT_RE.finditer(masked_source, 0, offset):
        last = match.group(1)
    return last


def parse_definitions(source: str) -> list[Definition]:
    """Parse every definition that has a body, with 1-based line numbers.

    Unlike a single regex over the whole header, the parameter list is matched by
    balancing parentheses, so nested types (tuples, function types, arrays) do not
    truncate the match. Declarations without a body (interfaces, ``abstract``) are
    skipped since there is nothing to expand into.
    """
    masked = mask_comments_and_strings(source)
    definitions: list[Definition] = []

    for match in DEFINITION_RE.finditer(masked):
        keyword = match.group(1)
        if keyword.startswith("function"):
            kind, name = "function", match.group(2)
        elif keyword.startswith("modifier"):
            kind, name = "modifier", match.group(3)
        else:
            kind = name = keyword

        paren_open = masked.index("(", match.end() - 1)
        paren_close = _matching_paren(masked, paren_open)
        if paren_close == -1:
            continue

        # Everything up to the body opener is the header (visibility, modifiers, returns).
        brace = masked.find("{", paren_close)
        semicolon = masked.find(";", paren_close)
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            continue  # declaration without a body

        end = matching_brace(masked, brace)
        start_line = _line_of(masked, match.start())

        definitions.append(
            Definition(
                name=name,
                kind=kind,
                signature=" ".join(source[match.start():brace].split()),
                start_line=start_line,
                end_line=_line_of(masked, end),
                body=source[match.start():end + 1],
                contract=_enclosing_contract(masked, match.start()),
            )
        )

    return definitions


def numbered_snippet(source: str, start_line: int, end_line: int) -> str:
    """Render an inclusive 1-based line range with the pipeline's number format."""
    lines = source.splitlines()
    start = max(start_line, 1)
    end = min(end_line, len(lines))
    return "\n".join(f"{idx:04d}: {lines[idx - 1]}" for idx in range(start, end + 1))
