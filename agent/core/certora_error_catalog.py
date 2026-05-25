"""Catalog of Certora/CVL errors observed by the pipeline.

This is the durable memory layer for Certora failures: when Certora rejects a
spec, we classify the log into known causes and map them to deterministic
pipeline actions instead of asking the LLM to rediscover the same rule.
"""

from __future__ import annotations

import re


CERTORA_ERROR_PATTERNS = [
    {
        "id": "cvl_methods_semicolon",
        "severity": "blocking",
        "pattern": r"methods block entries must end with `;`",
        "cause": "CVL 2 methods{} entries must be function declarations ending with semicolons.",
        "pipeline_action": "Rebuild methods{} deterministically from the Solidity interface.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/methods.html",
    },
    {
        "id": "cvl_methods_body",
        "severity": "blocking",
        "pattern": r"unexpected token near `\{`",
        "cause": "The spec probably contains a Solidity-style function body inside methods{}.",
        "pipeline_action": "Strip method bodies or replace the whole methods{} block deterministically.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/methods.html",
    },
    {
        "id": "cvl_rules_wrapper",
        "severity": "blocking",
        "pattern": r"unexpected token near `rules`",
        "cause": "CVL rules are top-level declarations; there is no rules{} wrapper.",
        "pipeline_action": "Remove the rules{} wrapper and keep each rule at top level.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/basics.html",
    },
    {
        "id": "cvl_loose_rule_statements",
        "severity": "blocking",
        "pattern": r"unexpected token near `env`",
        "cause": "The model emitted rule statements after a VULN comment without wrapping them in rule name { ... }.",
        "pipeline_action": "Wrap loose VULN_XXX statement blocks into named CVL rules from the formal plan.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/statements.html",
    },
    {
        "id": "cvl_duplicate_declaration",
        "severity": "blocking",
        "pattern": r"Redeclaring variables is not supported",
        "cause": "The model placed multiple mini-tests inside one rule, redeclaring env/local variables.",
        "pipeline_action": "Remove duplicate @withrevert prelude or split the rule into one coherent proof.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/statements.html",
    },
    {
        "id": "cvl_payable_in_methods",
        "severity": "blocking",
        "pattern": r"unexpected token near `;`",
        "cause": "The methods{} entry may include unsupported Solidity modifiers such as payable.",
        "pipeline_action": "Remove payable and normalize address payable to address in methods{} entries.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/cvl2/changes.html",
    },
    {
        "id": "cvl_last_reverted_overwritten",
        "severity": "risk",
        "pattern": r"lastReverted",
        "cause": "lastReverted is overwritten after each contract call; rules must assert it immediately.",
        "pipeline_action": "Keep @withrevert calls adjacent to assert lastReverted and avoid getter calls in between.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/expr.html",
    },
    {
        "id": "solc_error",
        "severity": "blocking",
        "pattern": r"solc had an error|Compiling .* failed",
        "cause": "The Solidity contract or compiler configuration failed before formal verification.",
        "pipeline_action": "Block before LLM diagnosis and surface compiler details.",
        "source": "https://docs.certora.com/en/latest/docs/user-guide/getting-started/install.html",
    },
    {
        "id": "spec_error",
        "severity": "blocking",
        "pattern": r"Error in spec file|CVL syntax or type check failed",
        "cause": "Certora rejected the CVL spec during local syntax/type checking.",
        "pipeline_action": "Classify detailed errors and apply deterministic CVL repair before retrying.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/overview.html",
    },
    {
        "id": "cvl_invalid_envfree",
        "severity": "blocking",
        "pattern": r"declared `envfree` but depends on the environment|Specification marks method .* as 'envfree' but the method uses",
        "cause": "The methods{} block marked a function as envfree even though it reads restricted environment values such as msg.sender or block.timestamp.",
        "pipeline_action": "Rebuild methods{} without envfree for environment-dependent functions and rerun Certora.",
        "source": "https://docs.certora.com/en/latest/docs/cvl/methods.html",
    },
]


def analyze_certora_errors(log: str) -> dict:
    matches = []
    for entry in CERTORA_ERROR_PATTERNS:
        if re.search(entry["pattern"], log, flags=re.IGNORECASE):
            matches.append({key: value for key, value in entry.items() if key != "pattern"})

    return {
        "has_blocking_errors": any(item["severity"] == "blocking" for item in matches),
        "matches": matches,
    }


def has_certora_blocking_error(log: str) -> bool:
    if analyze_certora_errors(log)["has_blocking_errors"]:
        return True
    if "Results for all:" in log or "Failures summary:" in log:
        return False
    return analyze_certora_errors(log)["has_blocking_errors"]
