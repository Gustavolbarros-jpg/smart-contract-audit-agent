"""General CVL pattern library for LLM-guided spec generation.

These snippets are not contract-specific. They are compact examples that teach
the model how valid CVL shapes look while the deterministic validator keeps the
final spec grounded in the actual contract interface.
"""

from __future__ import annotations


SPEC_PATTERNS = {
    "missing-zero-check": {
        "goal": "A function receiving an address parameter must revert when that parameter is zero.",
        "use_when": "Slither reports missing-zero-check for a concrete address parameter.",
        "valid_example": """// VULN_XXX - missing-zero-check
rule zero_address_targetFunction {
  env e;
  address x;
  require x == 0;
  targetFunction@withrevert(e, x);
  assert lastReverted;
}""",
        "avoid": [
            "Do not write address(0); use 0 in CVL.",
            "Do not omit require x == 0; otherwise the rule asks all inputs to revert.",
        ],
    },
    "tx-origin": {
        "goal": "An owner-only function must revert when e.msg.sender is not owner().",
        "use_when": "The contract uses tx.origin or an equivalent unsafe authorization check.",
        "valid_example": """// VULN_XXX - tx-origin
rule auth_reverts_when_msg_sender_not_owner {
  env e;
  require e.msg.sender != owner();
  ownerOnlyFunction@withrevert(e);
  assert lastReverted;
}""",
        "avoid": [
            "Do not call a random public function; call an actual owner-only function.",
            "Do not call owner(e); owner is an envfree getter and must be owner().",
        ],
    },
    "suicidal": {
        "goal": "A function that can trigger selfdestruct must reject non-owner callers.",
        "use_when": "A public/external function can reach selfdestruct.",
        "valid_example": """// VULN_XXX - suicidal
rule destroy_reverts_for_non_owner {
  env e;
  require e.msg.sender != owner();
  destroy@withrevert(e);
  assert lastReverted;
}""",
        "avoid": [
            "Do not test the constructor.",
            "Do not model selfdestruct directly in CVL; call the Solidity function.",
        ],
    },
    "arbitrary-send-eth": {
        "goal": "An ETH-transfering function must reject unauthorized callers or invalid recipients.",
        "use_when": "The target function and recipient policy are clear.",
        "valid_example": """// VULN_XXX - arbitrary-send-eth
rule unauthorized_recipient_reverts {
  env e;
  address to;
  uint256 amount;
  require e.msg.sender != owner();
  emergencyWithdraw@withrevert(e, to, amount);
  assert lastReverted;
}""",
        "avoid": [
            "Do not reference address(this).balance in CVL.",
            "Do not invent an authorized recipient variable that is not in the contract.",
        ],
    },
    "reentrancy-eth": {
        "goal": "Prefer static CEI validation. Use Certora only for a concrete state property.",
        "use_when": "There is a clear state getter and a meaningful postcondition.",
        "valid_example": """// VULN_XXX - reentrancy-eth
rule state_changes_after_withdraw {
  env e;
  uint256 amount;
  mathint before = balances(e.msg.sender);
  require before >= amount;
  withdraw(e, amount);
  mathint after = balances(e.msg.sender);
  assert after < before;
}""",
        "avoid": [
            "Do not test reentrancy by simply expecting the function to revert.",
            "Do not swap target functions between VULN IDs.",
            "Do not claim CEI is proven if the rule only checks a revert path.",
        ],
    },
    "timestamp": {
        "goal": "Only formalize timestamp findings with a specific business invariant.",
        "use_when": "The plan names a concrete function and objective property.",
        "valid_example": """// VULN_XXX - timestamp
rule timestamp_property_example {
  env e;
  // Add a contract-specific objective assertion here.
  satisfy e.block.timestamp >= 0;
}""",
        "avoid": [
            "Do not generate weak timestamp rules that always pass.",
            "If no objective property exists, skip formalization.",
        ],
    },
}


def pattern_for_type(vulnerability_type: str) -> dict | None:
    if vulnerability_type in SPEC_PATTERNS:
        return SPEC_PATTERNS[vulnerability_type]
    if vulnerability_type.startswith("reentrancy"):
        return SPEC_PATTERNS["reentrancy-eth"]
    if vulnerability_type == "block-number":
        return SPEC_PATTERNS["timestamp"]
    return None


def build_spec_pattern_context(selected_rules: list[dict]) -> str:
    """Return a compact markdown context containing only relevant patterns."""
    seen = set()
    chunks = ["# CVL Pattern Cookbook", ""]
    for item in selected_rules:
        vuln_type = item.get("type", "")
        pattern = pattern_for_type(vuln_type)
        if not pattern or vuln_type in seen:
            continue
        seen.add(vuln_type)
        chunks.extend(
            [
                f"## {vuln_type}",
                f"Goal: {pattern['goal']}",
                f"When to use: {pattern['use_when']}",
                "Valid shape:",
                "```cvl",
                pattern["valid_example"],
                "```",
                "Avoid:",
                *[f"- {item}" for item in pattern["avoid"]],
                "",
            ]
        )
    return "\n".join(chunks).strip() + "\n"
