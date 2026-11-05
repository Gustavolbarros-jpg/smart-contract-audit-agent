import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.contract_choice import contract_with_most_critical_findings  # noqa: E402


def _function_in(contract):
    return {"type": "function", "name": "f", "type_specific_fields": {"parent": {"type": "contract", "name": contract}}}


def _node_in(contract):
    function = _function_in(contract)
    return {"type": "node", "name": "x", "type_specific_fields": {"parent": function}}


def _raw(*detectors):
    return {"results": {"detectors": list(detectors)}}


class ContractChoiceTests(unittest.TestCase):
    def test_contract_with_the_critical_finding_wins(self):
        raw = _raw(
            {"check": "arbitrary-send-eth", "elements": [_function_in("EtherStore")]},
            {"check": "naming-convention", "elements": [_function_in("EtherStoreAttack")]},
            {"check": "naming-convention", "elements": [_function_in("EtherStoreAttack")]},
        )
        self.assertEqual(contract_with_most_critical_findings(raw), "EtherStore")

    def test_parent_is_followed_from_a_node_to_its_contract(self):
        raw = _raw({"check": "suicidal", "elements": [_node_in("EtherGame")]})
        self.assertEqual(contract_with_most_critical_findings(raw), "EtherGame")

    def test_the_contract_with_more_critical_findings_is_chosen(self):
        raw = _raw(
            {"check": "tx-origin", "elements": [_function_in("A")]},
            {"check": "unchecked-lowlevel", "elements": [_function_in("B")]},
            {"check": "unchecked-lowlevel", "elements": [_function_in("B")]},
        )
        self.assertEqual(contract_with_most_critical_findings(raw), "B")

    def test_a_tie_leaves_the_choice_to_the_caller(self):
        raw = _raw(
            {"check": "unchecked-lowlevel", "elements": [_function_in("A")]},
            {"check": "unchecked-lowlevel", "elements": [_function_in("B")]},
        )
        self.assertEqual(contract_with_most_critical_findings(raw), "")

    def test_no_critical_finding_leaves_the_choice_to_the_caller(self):
        raw = _raw({"check": "naming-convention", "elements": [_function_in("A")]})
        self.assertEqual(contract_with_most_critical_findings(raw), "")


class HarnessExclusionTests(unittest.TestCase):
    def test_test_and_attack_contracts_are_never_chosen_even_with_more_findings(self):
        raw = _raw(
            {"check": "unchecked-transfer", "elements": [_function_in("ContractTest")]},
            {"check": "unchecked-transfer", "elements": [_function_in("ContractTest")]},
            {"check": "unchecked-transfer", "elements": [_function_in("EtherStoreAttack")]},
            {"check": "unchecked-transfer", "elements": [_function_in("SimpleBank")]},
        )
        self.assertEqual(contract_with_most_critical_findings(raw), "SimpleBank")

    def test_already_fixed_copy_is_not_chosen(self):
        raw = _raw(
            {"check": "unchecked-transfer", "elements": [_function_in("FixedBank")]},
            {"check": "unchecked-transfer", "elements": [_function_in("BankRemediated")]},
        )
        self.assertEqual(contract_with_most_critical_findings(raw), "")

    def test_only_harness_findings_leave_the_choice_to_the_caller(self):
        raw = _raw({"check": "arbitrary-send-eth", "elements": [_function_in("Attack")]})
        self.assertEqual(contract_with_most_critical_findings(raw), "")
