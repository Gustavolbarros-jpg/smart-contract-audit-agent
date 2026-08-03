"""Tests for the tree-sitter parsing backend and its agreement with the regex fallback."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core import treesitter_source  # noqa: E402
from core.call_expansion import build_call_context  # noqa: E402
from core.solidity_source import _parse_definitions_regex, parse_definitions  # noqa: E402


requires_backend = unittest.skipUnless(
    treesitter_source.available(), "tree-sitter backend not installed"
)


CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Vault {
    address public owner;

    modifier onlyOperator {
        require(msg.sender == owner, "Only operator");
        _;
    }

    modifier whenOpen() {
        require(!closed, "closed");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function pay(uint256 amount) internal {}

    function pay(address to) internal {}

    function withdraw(
        uint256 amount,
        address recipient
    )
        external
        onlyOperator
        returns (bool)
    {
        pay(amount);
        return true;
    }
}
"""


class BackendAvailabilityTests(unittest.TestCase):
    def test_availability_is_consistent_with_reason(self):
        if treesitter_source.available():
            self.assertEqual(treesitter_source.unavailable_reason(), "")
        else:
            self.assertNotEqual(treesitter_source.unavailable_reason(), "")

    def test_parse_returns_none_when_unavailable(self):
        if not treesitter_source.available():
            self.assertIsNone(treesitter_source.parse_definitions(CONTRACT))


@requires_backend
class ParseDefinitionsTests(unittest.TestCase):
    def setUp(self):
        self.definitions = parse_definitions(CONTRACT)
        self.by_name = {}
        for definition in self.definitions:
            self.by_name.setdefault(definition.name, []).append(definition)

    def test_modifier_without_parentheses_is_found(self):
        """Valid Solidity the regex misses: it requires "(" after the name.

        Observed in four of the five inverse contracts. The guard body never reached
        CALL_CONTEXT, so a caller guarded by it looked unprotected.
        """
        self.assertIn("onlyOperator", self.by_name)
        self.assertEqual(self.by_name["onlyOperator"][0].kind, "modifier")

    def test_regex_fallback_misses_it(self):
        names = {d.name for d in _parse_definitions_regex(CONTRACT)}
        self.assertNotIn("onlyOperator", names)

    def test_multi_line_signature_is_parsed(self):
        withdraw = self.by_name["withdraw"][0]
        self.assertEqual(withdraw.kind, "function")
        self.assertIn("pay(amount);", withdraw.body)

    def test_overloads_are_separate_definitions(self):
        self.assertEqual(len(self.by_name["pay"]), 2)
        starts = {d.start_line for d in self.by_name["pay"]}
        self.assertEqual(len(starts), 2)

    def test_constructor_is_captured(self):
        self.assertIn("constructor", self.by_name)

    def test_enclosing_contract_is_recorded(self):
        self.assertTrue(all(d.contract == "Vault" for d in self.definitions))

    def test_line_numbers_are_one_based_and_bracket_the_body(self):
        lines = CONTRACT.splitlines()
        for definition in self.definitions:
            self.assertIn(
                definition.name.replace("constructor", "constructor"),
                lines[definition.start_line - 1],
            )
            self.assertLessEqual(definition.end_line, len(lines))

    def test_declarations_without_a_body_are_skipped(self):
        source = """interface I { function ping() external returns (uint256); }
contract C is I { function ping() external returns (uint256) { return 1; } }
"""
        parsed = parse_definitions(source)
        self.assertEqual([(d.name, d.contract) for d in parsed], [("ping", "C")])


@requires_backend
class CalledNamesTests(unittest.TestCase):
    def test_applied_modifier_and_internal_call_are_found(self):
        withdraw = [d for d in parse_definitions(CONTRACT) if d.name == "withdraw"][0]
        names = treesitter_source.called_names(
            CONTRACT, withdraw.start_line, withdraw.end_line
        )
        self.assertIn("onlyOperator", names)
        self.assertIn("pay", names)

    def test_value_type_conversion_is_not_a_call(self):
        """The grammar distinguishes a conversion from a call structurally."""
        source = """contract C {
    function f(uint8 x) external { uint256 y = uint256(x); require(y > 0, "z"); }
}
"""
        names = treesitter_source.called_names(source, 1, 4)
        self.assertNotIn("uint256", names)

    def test_builtins_are_returned_for_the_caller_to_filter(self):
        """require() is syntactically an ordinary call; only a name table separates it."""
        source = """contract C {
    function f(uint8 x) external { require(x > 0, "z"); }
}
"""
        self.assertIn("require", treesitter_source.called_names(source, 1, 4))

    def test_call_expansion_filters_the_builtins_out(self):
        from core.call_expansion import called_names as expansion_called_names

        source = """contract C {
    function f(uint8 x) external { require(x > 0, "z"); helper(x); }
    function helper(uint8 x) internal {}
}
"""
        target = [d for d in parse_definitions(source) if d.name == "f"][0]
        names = expansion_called_names(target)
        self.assertIn("helper", names)
        self.assertNotIn("require", names)

    def test_external_member_call_is_not_resolved_internally(self):
        source = """contract C {
    function f() external { lib.helper(1); this.other(); }
    function other() external {}
}
"""
        names = treesitter_source.called_names(source, 1, 4)
        self.assertIn("other", names)     # this.other() is internal
        self.assertNotIn("helper", names)  # lib.helper() is not


@requires_backend
class ErrorRecoveryTests(unittest.TestCase):
    def test_source_with_syntax_errors_still_yields_definitions(self):
        """The MANDO-LLM motivation: usable output from code that does not compile."""
        source = """contract C {
    function good() external { value = 1; }
    function broken( external { <<< }
    function alsoGood() external { value = 2; }
}
"""
        names = {d.name for d in parse_definitions(source)}
        self.assertIn("good", names)
        self.assertTrue(treesitter_source.has_syntax_errors(source))

    def test_clean_source_reports_no_errors(self):
        self.assertFalse(treesitter_source.has_syntax_errors(CONTRACT))


@requires_backend
class CallContextIntegrationTests(unittest.TestCase):
    def test_parenthesis_less_modifier_body_reaches_the_context(self):
        withdraw = [d for d in parse_definitions(CONTRACT) if d.name == "withdraw"][0]
        context = build_call_context(CONTRACT, [{"line": str(withdraw.start_line + 1)}])
        self.assertIn('require(msg.sender == owner, "Only operator");', context)


if __name__ == "__main__":
    unittest.main()
