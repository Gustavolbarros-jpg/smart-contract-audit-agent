"""Uma violação formal tem de virar achado reparável, com a função certa e o contraexemplo."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.formal_finding import (  # noqa: E402
    FORMAL_VIOLATION,
    assert_messages,
    findings_from_violations,
    function_under_rule,
    violated_rules,
)

SPEC = """methods {
    function owner() external returns(address) envfree;
    function balances(address) external returns(uint256) envfree;
    function paused() external returns(bool) envfree;
}

rule withdraw_debits_exactly {
    env e;
    uint256 amount;
    uint256 before = balances(e.msg.sender);

    withdraw(e, amount);

    assert to_mathint(balances(e.msg.sender)) == to_mathint(before) - to_mathint(amount);
}

rule only_the_owner_pauses {
    env e;
    require e.msg.sender != owner();

    pause@withrevert(e);

    assert lastReverted;
}
"""

LOG = """Checking rule withdraw_debits_exactly (1 out of 2)...
Violated: withdraw_debits_exactly
withdraw_debits_exactly: A property is violated
Violated: only_the_owner_pauses
Violated: only_the_owner_pauses-rule_not_vacuous

Results for all:
*------------------------------------------------------------------------------------*
|Rule name                 |Verified  |Time (sec)|Description                 |Local vars        |
|--------------------------|----------|----------|----------------------------|------------------|
|withdraw_debits_exactly   |Violated  |1         |Assert message: to_mathint(D |DeFiVault=8       |
|                          |(sat)     |          |                            |amount=3          |
|                          |          |          |                            |before=7          |
*------------------------------------------------------------------------------------*

Failures summary:
Failed on withdraw_debits_exactly:
Assert message: to_mathint(DeFiVault.balances(e.msg.send...

Done 0m
"""


class ViolatedRulesTests(unittest.TestCase):
    def test_the_vacuity_check_is_not_a_violation(self):
        self.assertEqual(
            violated_rules(LOG), ["withdraw_debits_exactly", "only_the_owner_pauses"]
        )

    def test_an_empty_log_has_no_violation(self):
        self.assertEqual(violated_rules(""), [])


class FunctionUnderRuleTests(unittest.TestCase):
    def test_the_envfree_getters_are_not_the_function_under_test(self):
        self.assertEqual(function_under_rule("withdraw_debits_exactly", SPEC), "withdraw")

    def test_a_withrevert_call_is_still_the_function(self):
        self.assertEqual(function_under_rule("only_the_owner_pauses", SPEC), "pause")

    def test_an_unknown_rule_gives_nothing(self):
        self.assertEqual(function_under_rule("no_such_rule", SPEC), "")


class AssertMessageTests(unittest.TestCase):
    def test_the_failure_summary_message_is_read(self):
        messages = assert_messages(LOG)
        self.assertIn("withdraw_debits_exactly", messages)
        self.assertTrue(messages["withdraw_debits_exactly"].startswith("to_mathint("))


class FindingsTests(unittest.TestCase):
    def test_one_finding_per_violated_rule_with_function_and_evidence(self):
        findings = findings_from_violations(LOG, SPEC)
        self.assertEqual([f["id"] for f in findings], ["VULN_F001", "VULN_F002"])
        self.assertEqual({f["type"] for f in findings}, {FORMAL_VIOLATION})
        self.assertEqual(findings[0]["function"], "withdraw()")
        self.assertEqual(findings[1]["function"], "pause()")
        self.assertEqual(findings[0]["rule"], "withdraw_debits_exactly")
        self.assertIn("amount", findings[0]["counterexample"])
        self.assertEqual(findings[0]["origin"], "certora_local_oracle")

    def test_the_description_names_the_property_and_the_function(self):
        finding = findings_from_violations(LOG, SPEC)[0]
        self.assertIn("withdraw_debits_exactly", finding["description"])
        self.assertIn("withdraw", finding["description"])

    def test_the_id_sequence_can_continue_an_existing_run(self):
        findings = findings_from_violations(LOG, SPEC, start_index=7)
        self.assertEqual([f["id"] for f in findings], ["VULN_F007", "VULN_F008"])

    def test_a_log_without_violations_produces_nothing(self):
        self.assertEqual(findings_from_violations("Verified: r\n", SPEC), [])


if __name__ == "__main__":
    unittest.main()


class CatalogTests(unittest.TestCase):
    """O achado formal tem de ser mapeado, senão cai na trilha 'unmapped'."""

    def test_the_class_is_in_the_catalog_as_a_security_finding(self):
        from core.vulnerability_catalog import get_catalog_entry

        entry = get_catalog_entry(FORMAL_VIOLATION)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["category"], "security")

    def test_no_deterministic_mold_claims_it(self):
        # O defeito é "o que quebrou a propriedade", não um padrão sintático: um molde
        # mecânico aqui estaria chutando.
        from core.deterministic_patch import _STATEMENT_PATCHES

        self.assertNotIn(FORMAL_VIOLATION, _STATEMENT_PATCHES)
        self.assertFalse(get_catalog_entry_static_confirmed())


def get_catalog_entry_static_confirmed() -> bool:
    from core.vulnerability_catalog import get_catalog_entry

    return bool(get_catalog_entry(FORMAL_VIOLATION).get("static_confirmed"))
