"""Tests for call-graph context expansion and the Solidity source primitives."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.call_expansion import (  # noqa: E402
    build_call_context,
    called_names,
    collect_reachable,
    enclosing_definition,
)
from core.solidity_source import mask_comments_and_strings, parse_definitions  # noqa: E402


SAMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _debit(address user, uint256 amount) internal {
        balances[user] -= amount;
    }

    function _audit(uint256 amount) internal view returns (bool) {
        return amount > 0;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(_audit(amount), "invalid");
        _debit(msg.sender, amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "failed");
    }

    function unrelated() external pure returns (uint256) {
        return 1;
    }
}
"""


class SolidityoSourceTests(unittest.TestCase):
    def test_masking_preserves_offsets_and_lines(self):
        source = 'a; // comment "x"\nb; /* block */ c;\nd("string");\n'
        masked = mask_comments_and_strings(source)
        self.assertEqual(len(masked), len(source))
        self.assertEqual(masked.count("\n"), source.count("\n"))
        self.assertNotIn("comment", masked)
        self.assertNotIn("string", masked)
        self.assertIn("a;", masked)
        self.assertIn("d(", masked)

    def test_braces_inside_strings_do_not_break_spans(self):
        source = """contract C {
    function f() external {
        emit Log("} not a real brace {");
        value = 1;
    }
}
"""
        definitions = parse_definitions(source)
        self.assertEqual(len(definitions), 1)
        self.assertEqual(definitions[0].name, "f")
        self.assertIn("value = 1;", definitions[0].body)

    def test_declaration_without_body_is_skipped(self):
        source = """interface I {
    function ping() external returns (uint256);
}
contract C is I {
    function ping() external returns (uint256) { return 1; }
}
"""
        names = [(d.name, d.contract) for d in parse_definitions(source)]
        self.assertEqual(names, [("ping", "C")])

    def test_nested_parentheses_in_parameters(self):
        source = """contract C {
    function f(uint256[] memory a, bytes calldata b) external returns (uint256, bool) {
        return (a.length, b.length > 0);
    }
}
"""
        definitions = parse_definitions(source)
        self.assertEqual(len(definitions), 1)
        self.assertEqual(definitions[0].name, "f")

    def test_line_numbers_are_one_based(self):
        definitions = {d.name: d for d in parse_definitions(SAMPLE)}
        withdraw = definitions["withdraw"]
        self.assertEqual(SAMPLE.splitlines()[withdraw.start_line - 1].strip(),
                         "function withdraw(uint256 amount) external onlyOwner {")
        self.assertEqual(SAMPLE.splitlines()[withdraw.end_line - 1].strip(), "}")

    def test_definition_kinds_and_contract(self):
        kinds = {(d.name, d.kind, d.contract) for d in parse_definitions(SAMPLE)}
        self.assertIn(("onlyOwner", "modifier", "Vault"), kinds)
        self.assertIn(("withdraw", "function", "Vault"), kinds)


class CalledNamesTests(unittest.TestCase):
    def setUp(self):
        self.definitions = {d.name: d for d in parse_definitions(SAMPLE)}

    def test_applied_modifier_counts_as_a_call(self):
        self.assertIn("onlyOwner", called_names(self.definitions["withdraw"]))

    def test_body_calls_are_collected(self):
        names = called_names(self.definitions["withdraw"])
        self.assertIn("_debit", names)
        self.assertIn("_audit", names)

    def test_builtins_and_visibility_are_not_calls(self):
        names = called_names(self.definitions["withdraw"])
        for noise in ("require", "external", "uint256", "msg", "call"):
            self.assertNotIn(noise, names)


class CollectReachableTests(unittest.TestCase):
    def test_depth_limit_is_respected(self):
        source = """contract C {
    function level3() internal {}
    function level2() internal { level3(); }
    function level1() internal { level2(); }
    function entry() external { level1(); }
}
"""
        definitions = parse_definitions(source)
        entry = [d for d in definitions if d.name == "entry"]
        reached = {d.name for d, _, _ in collect_reachable(source, entry, max_depth=2)}
        self.assertEqual(reached, {"entry", "level1", "level2"})

    def test_recursion_terminates(self):
        source = """contract C {
    function ping() internal { pong(); }
    function pong() internal { ping(); }
}
"""
        definitions = parse_definitions(source)
        entry = [d for d in definitions if d.name == "ping"]
        reached = [d.name for d, _, _ in collect_reachable(source, entry, max_depth=5)]
        self.assertEqual(sorted(reached), ["ping", "pong"])

    def test_overloads_are_all_included(self):
        source = """contract C {
    function pay(uint256 a) internal {}
    function pay(address a) internal {}
    function entry() external { pay(1); }
}
"""
        definitions = parse_definitions(source)
        entry = [d for d in definitions if d.name == "entry"]
        reached = [d.name for d, _, _ in collect_reachable(source, entry, max_depth=1)]
        self.assertEqual(reached.count("pay"), 2)

    def test_enclosing_definition_picks_innermost(self):
        definitions = parse_definitions(SAMPLE)
        withdraw = [d for d in definitions if d.name == "withdraw"][0]
        found = enclosing_definition(definitions, withdraw.start_line + 1)
        self.assertEqual(found.name, "withdraw")


class BuildCallContextTests(unittest.TestCase):
    def test_callee_and_modifier_bodies_reach_the_context(self):
        line = [d for d in parse_definitions(SAMPLE) if d.name == "withdraw"][0].start_line
        context = build_call_context(SAMPLE, [{"id": "V1", "line": str(line + 3)}])
        self.assertIn("CALL_CONTEXT", context)
        self.assertIn("balances[user] -= amount;", context)      # callee body
        self.assertIn('require(msg.sender == owner', context)    # modifier body
        self.assertNotIn("function unrelated", context)          # never called

    def test_finding_outside_any_definition_yields_nothing(self):
        self.assertEqual(build_call_context(SAMPLE, [{"line": "2"}]), "")

    def test_no_findings_yields_nothing(self):
        self.assertEqual(build_call_context(SAMPLE, []), "")

    def test_function_name_resolves_when_line_is_missing(self):
        context = build_call_context(SAMPLE, [{"function": "withdraw(uint256)"}])
        self.assertIn("function withdraw", context)

    def test_char_budget_keeps_at_least_the_entry(self):
        line = [d for d in parse_definitions(SAMPLE) if d.name == "withdraw"][0].start_line
        context = build_call_context(SAMPLE, [{"line": str(line + 1)}], max_chars=1)
        self.assertIn("function withdraw", context)
        self.assertIn("omitted for size", context)

    def test_state_update_after_external_call_is_visible(self):
        """The regression this change exists for: a line window hides the CEI violation."""
        source = """contract V {
    function claim() external {
        uint256 reward = 10;
        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "failed");
        balances[msg.sender] -= reward;
    }
}
"""
        call_line = 4
        context = build_call_context(source, [{"line": str(call_line)}])
        self.assertIn("balances[msg.sender] -= reward;", context)


if __name__ == "__main__":
    unittest.main()
