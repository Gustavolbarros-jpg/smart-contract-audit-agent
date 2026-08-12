"""Classify a produced fix as copied, adapted or novel relative to the fix library.

The pipeline feeds previous successful fixes back to the model as few-shot examples
(``fix_library.get_examples_for_prompt``). That helps, but it makes a passing benchmark
ambiguous: the agent may be reasoning about the contract, or it may be replaying a
snippet that happens to fit. This module makes the distinction measurable.

  copied  — identical to a stored fix once comments and whitespace are normalized
  adapted — same structure, different identifiers (the template was instantiated)
  novel   — no stored fix has this structure

Retrieval is an exact ``vuln_type`` match, so a finding of an unseen class receives no
examples and any fix for it is necessarily novel. Pair this with ``core.mutation`` to
generate instances that are absent from the library by construction.

A high adapted rate is not failure on its own — instantiating a template correctly is
useful work. The signal to watch is whether *novel* ever appears: an agent that only
ever emits copied and adapted fixes has not shown it can handle an unseen class.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from core.solidity_source import mask_comments_and_strings


COPIED = "copied"
ADAPTED = "adapted"
NOVEL = "novel"

# Kept literal when abstracting structure: these carry the meaning of a guard, while
# variable and function names are exactly what a template substitutes.
SOLIDITY_KEYWORDS = frozenset(
    {
        "require", "assert", "revert", "if", "else", "return", "emit", "new",
        "address", "payable", "bool", "string", "bytes", "uint", "uint256", "int",
        "int256", "msg", "sender", "value", "data", "origin", "tx", "block",
        "timestamp", "number", "this", "super", "true", "false", "memory",
        "storage", "calldata", "call", "delegatecall", "staticcall", "transfer",
        "send", "selfdestruct", "keccak256", "abi", "encodePacked", "length",
    }
)

_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_NUMBER_RE = re.compile(r"\b\d+\b")
_STRING_RE = re.compile(r"\"[^\"]*\"|'[^']*'")


@dataclass(frozen=True)
class Verdict:
    kind: str
    similarity: float
    closest: str = ""
    closest_type: str = ""

    @property
    def is_novel(self) -> bool:
        return self.kind == NOVEL


def strip_comments(snippet: str) -> str:
    """Remove comments while keeping string literals intact.

    ``mask_comments_and_strings`` blanks both, which would erase the revert message —
    part of what distinguishes two guards — so comment positions are taken from the
    mask and the characters are then read from the original.
    """
    masked = mask_comments_and_strings(snippet)
    out = []
    index = 0
    while index < len(snippet):
        if masked[index : index + 2] == "  " and snippet[index : index + 2] in ("//", "/*"):
            if snippet[index : index + 2] == "//":
                end = snippet.find("\n", index)
                index = len(snippet) if end == -1 else end
            else:
                end = snippet.find("*/", index)
                index = len(snippet) if end == -1 else end + 2
            out.append(" ")
            continue
        out.append(snippet[index])
        index += 1
    return "".join(out)


def normalize_snippet(snippet: str) -> str:
    """Drop comments and collapse whitespace, preserving tokens and string literals."""
    return " ".join(strip_comments(snippet).split())


def structural_form(snippet: str) -> str:
    """Abstract identifiers, numbers and string literals away, keeping the shape.

    ``require(newKing != address(0), "Zero address")`` and
    ``require(to != address(0), "Bad recipient")`` share a structural form; a fix that
    checks a different property does not.

    Substitution runs through letter-free sentinels because plain placeholders collide:
    a numeric ``N`` written first is itself a valid identifier — and ``\\b`` treats any
    non-word delimiter as a boundary — so the identifier pass would rewrite it to ``ID``,
    making ``require(x > 0)`` and ``require(x > 100)`` look alike.
    """
    text = normalize_snippet(snippet)
    text = _STRING_RE.sub("\x01", text)
    text = _NUMBER_RE.sub("\x02", text)

    def replace(match: re.Match) -> str:
        word = match.group(0)
        return word if word.lower() in SOLIDITY_KEYWORDS else "\x03"

    text = _IDENTIFIER_RE.sub(replace, text)
    return text.replace("\x01", '"S"').replace("\x02", "N").replace("\x03", "ID")


def similarity(left: str, right: str) -> float:
    return difflib.SequenceMatcher(None, left, right).ratio()


def classify_fix(
    snippet: str,
    library_entries: list[dict],
    adapted_threshold: float = 0.9,
    vuln_type: str = "",
) -> Verdict:
    """Compare a produced fix against stored fixes.

    ``library_entries`` are ``fix_library`` patterns; only ``fix_snippet`` and
    ``vuln_type`` are read, so a raw list of library dicts can be passed directly.

    ``vuln_type``, when given, restricts comparison to entries of that same class —
    matching how the pipeline itself retrieves few-shot examples (exact ``vuln_type``
    match in ``fix_library.get_examples_for_prompt``). Without it, a structurally
    generic guard (e.g. a single ``require(a == b, "msg")``) can score high against
    an unrelated class purely because most one-line require guards share a shape;
    that reads as "adapted" when the class itself has no stored fix at all, which is
    exactly the novel case this module exists to surface. Omit it only to preserve
    the previous type-blind behavior (existing tests rely on this default).
    """
    if not snippet.strip():
        return Verdict(NOVEL, 0.0)

    entries = library_entries
    if vuln_type:
        entries = [e for e in library_entries if str(e.get("vuln_type") or "") == vuln_type]

    normalized = normalize_snippet(snippet)
    form = structural_form(snippet)

    best_ratio = 0.0
    best_snippet = ""
    best_type = ""

    for entry in entries:
        stored = str(entry.get("fix_snippet") or "")
        if not stored.strip():
            continue

        if normalize_snippet(stored) == normalized:
            return Verdict(COPIED, 1.0, stored, str(entry.get("vuln_type") or ""))

        ratio = similarity(form, structural_form(stored))
        if ratio > best_ratio:
            best_ratio = ratio
            best_snippet = stored
            best_type = str(entry.get("vuln_type") or "")

    kind = ADAPTED if best_ratio >= adapted_threshold else NOVEL
    return Verdict(kind, round(best_ratio, 3), best_snippet, best_type)


def report(verdicts: list[Verdict]) -> dict:
    """Aggregate verdicts into the counts a generalization run should report."""
    counts = {COPIED: 0, ADAPTED: 0, NOVEL: 0}
    for verdict in verdicts:
        counts[verdict.kind] = counts.get(verdict.kind, 0) + 1

    total = len(verdicts) or 1
    return {
        "total": len(verdicts),
        "counts": counts,
        "novel_rate": round(counts[NOVEL] / total, 3),
        "copied_rate": round(counts[COPIED] / total, 3),
    }
