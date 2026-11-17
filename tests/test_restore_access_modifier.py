import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from core.deterministic_patch import apply_deterministic_patches  # noqa: E402

VAULT = """pragma solidity ^0.8.21;
contract V {
    address public owner;
    uint256 public rate;
    mapping(address => bool) public whitelist;
    bool public paused;
    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
    modifier onlyWhitelisted() { require(whitelist[msg.sender], "no"); _; }
    modifier notPaused() { require(!paused, "p"); _; }
    constructor() { owner = msg.sender; }
    function setRate(uint256 r) external %s {
        rate = r;
    }
}
"""


def _patch(source, function="setRate(uint256)"):
    return apply_deterministic_patches(
        source, [{"id": "VULN_007", "type": "unrestricted-write", "function": function}]
    )


class RestoreAccessModifierTests(unittest.TestCase):
    def test_restores_the_single_identity_gate(self):
        patched, applied = _patch(VAULT % "")
        self.assertEqual(len(applied), 1)
        self.assertIn("function setRate(uint256 r) external onlyOwner /* FIX VULN_007 */ {", patched)

    def test_one_line_function_body_still_compiles_shape(self):
        source = VAULT.replace("{\n        rate = r;\n    }", "{ rate = r; }") % ""
        patched, applied = _patch(source)
        self.assertEqual(len(applied), 1)
        self.assertIn("external onlyOwner /* FIX VULN_007 */ { rate = r; }", patched)

    def test_keeps_an_unrelated_modifier_and_adds_the_gate_after_it(self):
        patched, applied = _patch(VAULT % "notPaused")
        self.assertEqual(len(applied), 1)
        self.assertIn("external notPaused onlyOwner /* FIX VULN_007 */ {", patched)

    def test_does_not_duplicate_an_existing_gate(self):
        patched, applied = _patch(VAULT % "onlyOwner")
        self.assertEqual(applied, [])
        self.assertEqual(patched, VAULT % "onlyOwner")

    def test_mapping_and_pause_modifiers_are_not_identity_gates(self):
        source = VAULT.replace(
            'modifier onlyOwner() { require(msg.sender == owner, "no"); _; }', ""
        ) % ""
        patched, applied = _patch(source)
        self.assertEqual(applied, [])

    def test_two_identity_gates_are_ambiguous_so_nothing_is_guessed(self):
        source = VAULT.replace(
            "modifier notPaused()",
            'modifier onlyAdmin() { require(msg.sender == owner, "no"); _; }\n    modifier notPaused()',
        ) % ""
        patched, applied = _patch(source)
        self.assertEqual(applied, [])

    def test_overloaded_function_is_left_alone(self):
        source = VAULT % ""
        source = source.replace(
            "}\n}\n", "}\n    function setRate() external { rate = 0; }\n}\n"
        )
        patched, applied = _patch(source)
        self.assertEqual(applied, [])


if __name__ == "__main__":
    unittest.main()
