"""Parse Certora table output to extract counterexample variable assignments."""

from __future__ import annotations

import re

_NOISE_VARS = {
    "e.block.basefee",
    "e.block.blobbasefee",
    "e.block.coinbase",
    "e.block.difficulty",
    "e.block.gaslimit",
    "e.block.number",
    "e.block.timestamp",
}

_ASSERT_TRANSLATIONS = {
    "lastReverted": "the rule expected the call to REVERT, but it did NOT",
    "lastHasRevertMessage": "the call did not produce the expected revert message",
}


def extract_counterexamples(log: str) -> dict[str, dict[str, str]]:
    """Return {rule_name: {var_name: value}} for each violated rule in the Certora log table."""
    result: dict[str, dict[str, str]] = {}

    for table_block in _find_table_blocks(log):
        _parse_table(table_block, result)

    return result


def format_counterexample_for_prompt(
    counterexamples: dict[str, dict[str, str]],
    failing_rule_names: list[str],
) -> str:
    """Build a compact text block for inclusion in diagnosis prompts."""
    if not counterexamples:
        return ""

    relevant = {
        rule: vars_
        for rule, vars_ in counterexamples.items()
        if _rule_matches_any(rule, failing_rule_names)
    }
    if not relevant:
        relevant = counterexamples

    lines = ["CERTORA COUNTEREXAMPLES:"]
    for rule, vars_ in relevant.items():
        lines.append(f"Rule {rule} VIOLATED:")
        assert_msg = vars_.get("_assert_message", "")
        if assert_msg:
            translated = _ASSERT_TRANSLATIONS.get(assert_msg, assert_msg)
            lines.append(f"  Assert: {assert_msg} ({translated})")
        lines.append("  Inputs that caused the violation:")
        max_key_len = max((len(k) for k in vars_ if not k.startswith("_")), default=0)
        for var, val in vars_.items():
            if var.startswith("_"):
                continue
            annotation = _annotate_value(var, val)
            padded = var.ljust(max_key_len)
            lines.append(f"    {padded} = {val}{annotation}")

    return "\n".join(lines)


def _rule_matches_any(rule: str, names: list[str]) -> bool:
    if rule in names:
        return True
    rule_base = rule.split("-")[0]
    for n in names:
        if n and (n == rule or n.split("-")[0] == rule_base):
            return True
    return False


def _annotate_value(var: str, val: str) -> str:
    """Add a human-readable annotation hint for known patterns."""
    lower_val = val.lower()
    if var == "e.msg.sender":
        if "0x0" == lower_val or val == "0":
            return " (zero address)"
        return " (caller)"
    if var == "e.tx.origin":
        return " (transaction origin)"
    if var == "e.msg.value":
        return " (ETH sent)"
    if lower_val.startswith("0x") and len(lower_val) < 8 and lower_val not in ("0x0",):
        return " (arbitrary address, different from msg.sender)"
    return ""


def _find_table_blocks(log: str) -> list[str]:
    """Extract ASCII table blocks from the log."""
    blocks = []
    lines = log.splitlines()
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("*") and stripped.endswith("*") and len(stripped) > 10:
            if start is None:
                start = i
            else:
                blocks.append("\n".join(lines[start : i + 1]))
                start = None
    return blocks


def _parse_table(block: str, result: dict[str, dict[str, str]]) -> None:
    lines = block.splitlines()
    current_rule: str | None = None
    current_violated = False
    current_vars: dict[str, str] = {}
    assert_message = ""

    for line in lines:
        if not line.startswith("|"):
            continue
        cols = line.split("|")
        if len(cols) < 6:
            continue

        rule_col = cols[1].strip()
        verified_col = cols[2].strip()
        desc_col = cols[4].strip() if len(cols) > 4 else ""
        vars_col = cols[5].strip() if len(cols) > 5 else ""

        # Skip header rows ("Rule name") and separator rows (----)
        if rule_col in ("Rule name",) or (rule_col and set(rule_col) <= {"-", " "}):
            continue

        if rule_col:
            # Flush previous rule if violated
            if current_rule and current_violated:
                _store_rule(result, current_rule, current_vars, assert_message)
            current_rule = rule_col
            current_violated = verified_col.startswith("Violated")
            current_vars = {}
            assert_message = ""
            # Parse assert message from description
            if "Assert message:" in desc_col:
                assert_message = desc_col.replace("Assert message:", "").strip()
            # Parse first local var on same row
            if vars_col and vars_col != "no local variables":
                _add_var(current_vars, vars_col)
        else:
            # Continuation row
            if verified_col == "(sat)" and current_rule and not current_violated:
                pass  # satisified but not violated (rule_not_vacuous passing)
            if vars_col and vars_col != "no local variables" and current_rule:
                _add_var(current_vars, vars_col)

    # Flush last rule
    if current_rule and current_violated:
        _store_rule(result, current_rule, current_vars, assert_message)


def _add_var(vars_: dict[str, str], raw: str) -> None:
    """Parse 'name=value' pairs from a local vars cell."""
    # May have multiple pairs separated by spaces if compact
    for part in re.split(r"\s{2,}", raw):
        part = part.strip()
        if "=" not in part:
            continue
        idx = part.index("=")
        name = part[:idx].strip()
        val = part[idx + 1:].strip()
        if name in _NOISE_VARS:
            continue
        vars_[name] = val


def _store_rule(
    result: dict[str, dict[str, str]],
    rule: str,
    vars_: dict[str, str],
    assert_message: str,
) -> None:
    stored = dict(vars_)
    if assert_message:
        stored["_assert_message"] = assert_message
    result[rule] = stored
