"""Mutation operators for generating held-out vulnerability instances.

Adapted from CCIHunter (ACM TOSEM 10.1145/3764867), which defines seven operators over
Solidity and trains on the distance between original and mutant. We apply them in the
opposite direction: starting from a contract the pipeline already repaired, a mutation
re-introduces a defect at a position and in a form the agent has never seen.

This exists to separate two things the benchmark cannot distinguish on its own:

  generalizing — the agent diagnoses and repairs an instance absent from the fix library
  copying      — the agent reproduces a stored snippet that happens to fit

``fix_library.get_examples_for_prompt`` retrieves by exact ``vuln_type`` match, so a
mutated instance of an unseen class receives no examples at all. What the agent produces
then is its own.

Mutations are applied to masked source offsets, so operators never fire inside a string
literal or a comment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.solidity_source import mask_comments_and_strings, parse_definitions


@dataclass(frozen=True)
class Mutation:
    """One injected defect, with the source it produced."""

    operator: str
    description: str
    line: int
    original: str
    mutated: str
    expected_class: str
    source: str

    @property
    def label(self) -> str:
        return f"{self.operator}@{self.line}"


# operator -> (pattern, replacement, expected perspective class, description)
_ASSIGNMENT_SWAPS = (
    ("-=", "+=", "subtraction became addition"),
    ("+=", "-=", "addition became subtraction"),
)

_BINARY_SWAPS = (
    (">=", ">", "inclusive bound became exclusive"),
    ("<=", "<", "inclusive bound became exclusive"),
    ("==", "!=", "equality became inequality"),
    ("!=", "==", "inequality became equality"),
    ("&&", "||", "conjunction became disjunction"),
)

_VISIBILITY_SWAPS = (
    ("internal", "public", "internal function became publicly callable"),
    ("private", "public", "private function became publicly callable"),
)

OPERATORS = ("AOR", "BOR", "UOR", "EED", "MD", "PKR", "FVR")


def _line_of(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _line_text(source: str, offset: int) -> str:
    start = source.rfind("\n", 0, offset) + 1
    end = source.find("\n", offset)
    return source[start:end if end != -1 else len(source)].strip()


def _replace_at(source: str, start: int, end: int, replacement: str) -> str:
    return source[:start] + replacement + source[end:]


def _token_positions(masked: str, token: str) -> list[int]:
    positions = []
    index = masked.find(token)
    while index != -1:
        positions.append(index)
        index = masked.find(token, index + 1)
    return positions


def _mutate_operator_token(
    source: str,
    masked: str,
    swaps: tuple[tuple[str, str, str], ...],
    operator: str,
    expected_class: str,
    limit: int,
) -> list[Mutation]:
    mutations: list[Mutation] = []

    for token, replacement, description in swaps:
        for position in _token_positions(masked, token):
            if len(mutations) >= limit:
                return mutations
            # Skip when the token is part of a longer operator (e.g. "==" inside "===",
            # or ">=" whose "=" belongs to ">>=").
            before = masked[position - 1] if position else ""
            after = masked[position + len(token)]  if position + len(token) < len(masked) else ""
            if before in "=!<>+-*/&|" or after in "=":
                continue

            mutated_source = _replace_at(source, position, position + len(token), replacement)
            mutations.append(
                Mutation(
                    operator=operator,
                    description=f"{description} ({token} -> {replacement})",
                    line=_line_of(source, position),
                    original=_line_text(source, position),
                    mutated=_line_text(mutated_source, position),
                    expected_class=expected_class,
                    source=mutated_source,
                )
            )

    return mutations


def mutate_aor(source: str, limit: int = 3) -> list[Mutation]:
    """Assignment Operator Replacement — flips the direction of a balance update."""
    return _mutate_operator_token(
        source, mask_comments_and_strings(source), _ASSIGNMENT_SWAPS,
        "AOR", "integer_overflow", limit,
    )


def mutate_bor(source: str, limit: int = 3) -> list[Mutation]:
    """Binary Operator Replacement — weakens a guard's comparison."""
    return _mutate_operator_token(
        source, mask_comments_and_strings(source), _BINARY_SWAPS,
        "BOR", "comparison_logic", limit,
    )


def mutate_uor(source: str, limit: int = 3) -> list[Mutation]:
    """Unary Operator Replacement — drops a negation, inverting a guard."""
    masked = mask_comments_and_strings(source)
    mutations: list[Mutation] = []

    for match in re.finditer(r"require\s*\(\s*(!)", masked):
        if len(mutations) >= limit:
            break
        position = match.start(1)
        mutated_source = _replace_at(source, position, position + 1, "")
        mutations.append(
            Mutation(
                operator="UOR",
                description="negation removed from a require guard",
                line=_line_of(source, position),
                original=_line_text(source, position),
                mutated=_line_text(mutated_source, position),
                expected_class="comparison_logic",
                source=mutated_source,
            )
        )

    return mutations


def mutate_eed(source: str, limit: int = 3) -> list[Mutation]:
    """Event Emission Deletion — a state change stops being observable."""
    masked = mask_comments_and_strings(source)
    mutations: list[Mutation] = []

    for match in re.finditer(r"[ \t]*emit\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^;]*\)\s*;", masked):
        if len(mutations) >= limit:
            break
        mutated_source = _replace_at(source, match.start(), match.end(), "")
        mutations.append(
            Mutation(
                operator="EED",
                description="event emission deleted",
                line=_line_of(source, match.start()),
                original=_line_text(source, match.start()),
                mutated="",
                expected_class="missing_events",
                source=mutated_source,
            )
        )

    return mutations


def mutate_md(source: str, limit: int = 3) -> list[Mutation]:
    """Modifier Deletion — removes an applied modifier, dropping its access check.

    The highest-value operator here: it produces a genuine access-control defect whose
    guard lived outside the function body.
    """
    masked = mask_comments_and_strings(source)
    modifier_names = {d.name for d in parse_definitions(source) if d.kind == "modifier"}
    if not modifier_names:
        return []

    mutations: list[Mutation] = []

    for definition in parse_definitions(source):
        if definition.kind != "function" or len(mutations) >= limit:
            continue

        header_end = masked.find("{", masked.find(definition.name))
        start = masked.find(definition.name)
        if start == -1 or header_end == -1:
            continue

        header = masked[start:header_end]
        for name in modifier_names:
            match = re.search(rf"\s\b{re.escape(name)}\b(?!\s*\()", header)
            if match is None or len(mutations) >= limit:
                continue
            absolute = start + match.start()
            mutated_source = _replace_at(source, absolute, absolute + len(match.group(0)), "")
            mutations.append(
                Mutation(
                    operator="MD",
                    description=f"modifier {name} removed from {definition.name}",
                    line=_line_of(source, absolute),
                    original=_line_text(source, absolute),
                    mutated=_line_text(mutated_source, absolute),
                    expected_class="unrestricted_write",
                    source=mutated_source,
                )
            )

    return mutations


def mutate_pkr(source: str, limit: int = 3) -> list[Mutation]:
    """Payable Keyword Replacement — a function stops rejecting value."""
    masked = mask_comments_and_strings(source)
    mutations: list[Mutation] = []

    for match in re.finditer(r"\spayable(?=\s)", masked):
        if len(mutations) >= limit:
            break
        mutated_source = _replace_at(source, match.start(), match.end(), "")
        mutations.append(
            Mutation(
                operator="PKR",
                description="payable keyword removed",
                line=_line_of(source, match.start()),
                original=_line_text(source, match.start()),
                mutated=_line_text(mutated_source, match.start()),
                expected_class="unrestricted_transfer",
                source=mutated_source,
            )
        )

    return mutations


def mutate_fvr(source: str, limit: int = 3) -> list[Mutation]:
    """Function Visibility Replacement — widens who can call a function."""
    masked = mask_comments_and_strings(source)
    mutations: list[Mutation] = []

    for definition in parse_definitions(source):
        if definition.kind != "function" or len(mutations) >= limit:
            continue
        start = masked.find(definition.name)
        header_end = masked.find("{", start) if start != -1 else -1
        if start == -1 or header_end == -1:
            continue

        header = masked[start:header_end]
        for token, replacement, description in _VISIBILITY_SWAPS:
            match = re.search(rf"\b{token}\b", header)
            if match is None or len(mutations) >= limit:
                continue
            absolute = start + match.start()
            mutated_source = _replace_at(source, absolute, absolute + len(token), replacement)
            mutations.append(
                Mutation(
                    operator="FVR",
                    description=f"{description} ({definition.name})",
                    line=_line_of(source, absolute),
                    original=_line_text(source, absolute),
                    mutated=_line_text(mutated_source, absolute),
                    expected_class="unrestricted_write",
                    source=mutated_source,
                )
            )
            break

    return mutations


_OPERATOR_FUNCTIONS = {
    "AOR": mutate_aor,
    "BOR": mutate_bor,
    "UOR": mutate_uor,
    "EED": mutate_eed,
    "MD": mutate_md,
    "PKR": mutate_pkr,
    "FVR": mutate_fvr,
}


def mutate(
    source: str,
    operators: tuple[str, ...] = OPERATORS,
    limit_per_operator: int = 3,
) -> list[Mutation]:
    """Every mutation the requested operators can produce, each a standalone variant.

    Mutations are independent: each carries a source with exactly one defect injected,
    so a pipeline run attributes its result to a single known cause.
    """
    mutations: list[Mutation] = []
    for operator in operators:
        function = _OPERATOR_FUNCTIONS.get(operator)
        if function is None:
            continue
        mutations.extend(function(source, limit_per_operator))
    return mutations


def summarize(mutations: list[Mutation]) -> dict[str, int]:
    """Count mutations per operator, for reporting coverage of a mutation run."""
    counts: dict[str, int] = {}
    for mutation in mutations:
        counts[mutation.operator] = counts.get(mutation.operator, 0) + 1
    return counts
