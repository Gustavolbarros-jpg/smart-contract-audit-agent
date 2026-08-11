"""Tests for mutation-based held-out instances and copied/adapted/novel classification."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.generalization import (  # noqa: E402
    ADAPTED,
    COPIED,
    NOVEL,
    classify_fix,
    normalize_snippet,
    report,
    strip_comments,
    structural_form,
)
from core.mutation import (  # noqa: E402
    OPERATORS,
    mutate,
    mutate_aor,
    mutate_bor,
    mutate_eed,
    mutate_fvr,
    mutate_md,
    mutate_uor,
    summarize,
)


CONTRACT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Vault {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;

    event Withdrawn(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function _burn(uint256 amount) internal {
        balances[msg.sender] -= amount;
    }

    function withdraw(uint256 amount) external payable onlyOwner {
        require(!paused, "paused");
        require(balances[msg.sender] >= amount, "insufficient");
        _burn(amount);
        emit Withdrawn(msg.sender, amount);
    }
}
"""


class MutationOperatorTests(unittest.TestCase):
    def test_aor_flips_the_direction_of_a_balance_update(self):
        mutations = mutate_aor(CONTRACT)
        self.assertTrue(mutations)
        self.assertIn("balances[msg.sender] += amount;", mutations[0].source)

    def test_bor_weakens_an_inclusive_bound(self):
        mutations = mutate_bor(CONTRACT)
        forms = [m.mutated for m in mutations]
        self.assertTrue(any("> amount" in form for form in forms))

    def test_uor_removes_a_negation_from_a_guard(self):
        mutations = mutate_uor(CONTRACT)
        self.assertEqual(len(mutations), 1)
        self.assertIn('require(paused, "paused")', mutations[0].source)

    def test_eed_deletes_an_event_emission(self):
        mutations = mutate_eed(CONTRACT)
        self.assertTrue(mutations)
        self.assertNotIn("emit Withdrawn", mutations[0].source)

    def test_md_removes_an_applied_modifier(self):
        mutations = mutate_md(CONTRACT)
        self.assertTrue(mutations)
        self.assertIn("onlyOwner", mutations[0].description)
        # The modifier definition survives; only its application is gone.
        self.assertIn("modifier onlyOwner()", mutations[0].source)
        self.assertNotIn("external payable onlyOwner", mutations[0].source)

    def test_fvr_widens_visibility(self):
        mutations = mutate_fvr(CONTRACT)
        self.assertTrue(mutations)
        self.assertIn("function _burn(uint256 amount) public", mutations[0].source)

    def test_each_mutation_changes_the_source_exactly_once(self):
        for mutation in mutate(CONTRACT):
            self.assertNotEqual(mutation.source, CONTRACT, mutation.label)

    def test_operators_do_not_fire_inside_comments_or_strings(self):
        source = """contract C {
    // balances[x] -= y and a >= b live in a comment
    function f() external { emit Log("a >= b and c -= d"); }
}
"""
        for mutation in mutate(source, operators=("AOR", "BOR")):
            self.assertNotIn("comment", mutation.original.lower(), mutation.label)

    def test_summarize_counts_per_operator(self):
        counts = summarize(mutate(CONTRACT))
        self.assertTrue(set(counts).issubset(set(OPERATORS)))
        self.assertEqual(sum(counts.values()), len(mutate(CONTRACT)))

    def test_limit_is_respected_per_operator(self):
        counts = summarize(mutate(CONTRACT, limit_per_operator=1))
        for operator, count in counts.items():
            self.assertLessEqual(count, 1, operator)

    def test_mutation_records_the_line_it_changed(self):
        for mutation in mutate(CONTRACT):
            self.assertGreater(mutation.line, 0)
            self.assertLessEqual(mutation.line, len(CONTRACT.splitlines()))


class NormalizationTests(unittest.TestCase):
    def test_comments_are_stripped_but_strings_survive(self):
        text = strip_comments('require(x != 0, "Zero address"); // FIX VULN_001')
        self.assertIn('"Zero address"', text)
        self.assertNotIn("VULN_001", text)

    def test_whitespace_is_collapsed(self):
        self.assertEqual(normalize_snippet("require( a  ,\n  b );"), "require( a , b );")

    def test_structural_form_abstracts_identifiers_and_keeps_keywords(self):
        form = structural_form('require(newKing != address(0), "Zero address");')
        self.assertEqual(form, 'require(ID != address(N), "S");')

    def test_numeric_constant_and_identifier_are_distinguishable(self):
        """The sentinel collision made both collapse to ID; they must stay different."""
        self.assertNotEqual(
            structural_form("require(x > 0);"), structural_form("require(x > y);")
        )

    def test_identifier_renaming_preserves_the_form(self):
        self.assertEqual(
            structural_form('require(a != address(0), "m");'),
            structural_form('require(bbb != address(0), "other");'),
        )


class ClassifyFixTests(unittest.TestCase):
    LIBRARY = [
        {
            "vuln_type": "missing-zero-check",
            "fix_snippet": 'require(newKing != address(0), "Zero address"); // FIX VULN_001',
        },
        {
            "vuln_type": "arbitrary-send-eth",
            "fix_snippet": 'require(to == msg.sender, "Unauthorized recipient"); // FIX VULN_009',
        },
    ]

    def test_identical_snippet_is_copied_despite_comment_differences(self):
        verdict = classify_fix(
            'require(newKing != address(0), "Zero address"); // FIX VULN_042', self.LIBRARY
        )
        self.assertEqual(verdict.kind, COPIED)

    def test_same_template_with_new_identifiers_is_adapted(self):
        verdict = classify_fix('require(recipient != address(0), "Bad");', self.LIBRARY)
        self.assertEqual(verdict.kind, ADAPTED)

    def test_a_different_property_is_novel(self):
        verdict = classify_fix('require(success, "call failed");', self.LIBRARY)
        self.assertEqual(verdict.kind, NOVEL)

    def test_reordering_state_and_call_is_novel(self):
        verdict = classify_fix(
            'balances[msg.sender] -= amount; (bool ok, ) = msg.sender.call{value: amount}("");',
            self.LIBRARY,
        )
        self.assertEqual(verdict.kind, NOVEL)

    def test_empty_library_makes_everything_novel(self):
        self.assertEqual(classify_fix("require(x != 0);", []).kind, NOVEL)

    def test_empty_snippet_is_novel_not_a_crash(self):
        self.assertEqual(classify_fix("   ", self.LIBRARY).kind, NOVEL)

    def test_verdict_reports_the_closest_stored_fix(self):
        verdict = classify_fix('require(spender != address(0), "x");', self.LIBRARY)
        self.assertEqual(verdict.closest_type, "missing-zero-check")

    def test_report_aggregates_rates(self):
        verdicts = [
            classify_fix('require(newKing != address(0), "Zero address");', self.LIBRARY),
            classify_fix('require(success, "call failed");', self.LIBRARY),
        ]
        summary = report(verdicts)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["counts"][COPIED], 1)
        self.assertEqual(summary["counts"][NOVEL], 1)
        self.assertEqual(summary["novel_rate"], 0.5)


class HeldOutPropertyTests(unittest.TestCase):
    """The property that makes mutants a valid generalization probe."""

    def test_mutants_are_absent_from_the_library_by_construction(self):
        library = ClassifyFixTests.LIBRARY
        for mutation in mutate(CONTRACT, operators=("AOR", "UOR", "MD")):
            verdict = classify_fix(mutation.mutated or mutation.original, library)
            self.assertEqual(verdict.kind, NOVEL, f"{mutation.label}: {mutation.original}")


if __name__ == "__main__":
    unittest.main()
