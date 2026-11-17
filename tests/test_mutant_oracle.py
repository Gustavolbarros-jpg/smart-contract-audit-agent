"""O braço de reparo tem de cobrar o resultado do oráculo, não aceitar o patch pela fé."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import mutant_oracle as mo  # noqa: E402
from core.mutation import mutate  # noqa: E402
from tools.certora_cli import LocalVerdict  # noqa: E402


SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
    }
}
"""


class RepairArmTests(unittest.TestCase):
    def _run(self, verdict, patches=(("VULN_001", "tx-origin"),)):
        mutation = mutate(SOURCE, operators=("AOR",), limit_per_operator=1)[0]
        applied = [{"id": vuln_id, "type": kind} for vuln_id, kind in patches]
        with tempfile.TemporaryDirectory() as tmp:
            contract = Path(tmp) / "Vault.sol"
            contract.write_text(SOURCE, encoding="utf-8")
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            with mock.patch.object(mo, "_static_repair", return_value=(SOURCE, applied, [{}])):
                with mock.patch.object(mo, "verify_locally", return_value=verdict):
                    result = mo._repair_and_check(
                        contract, Path(tmp) / "Vault.spec", "Vault", run_dir,
                        "AOR_at_10", mutation, 0, 60,
                    )
            # O arquivo do mutante não fica para trás no corpus.
            self.assertEqual(list(contract.parent.glob("*__oracle*.sol")), [])
        return result

    def test_a_verified_repair_counts_as_repaired(self):
        result = self._run(
            LocalVerdict(status="verified", rules={"r": "verified"}, sanity={"r-rule_not_vacuous": "violated"})
        )
        self.assertEqual(result["status"], mo.REPAIRED)
        self.assertEqual(result["patches"], ["tx-origin"])

    def test_a_rule_that_stopped_being_reachable_is_not_a_repair(self):
        result = self._run(
            LocalVerdict(status="verified", rules={"r": "verified"}, sanity={"r-rule_not_vacuous": "verified"})
        )
        self.assertEqual(result["status"], mo.VACUOUS)
        self.assertEqual(result["vacuous"], ["r"])

    def test_a_still_violated_rule_is_not_repaired(self):
        result = self._run(LocalVerdict(status="violated", rules={"r": "violated"}))
        self.assertEqual(result["status"], mo.NOT_REPAIRED)
        self.assertEqual(result["violated"], ["r"])

    def test_no_patch_applied_is_still_measured(self):
        result = self._run(LocalVerdict(status="violated", rules={"r": "violated"}), patches=())
        self.assertEqual(result["status"], mo.NOT_REPAIRED)
        self.assertEqual(result["patches"], [])


class SlitherFailureTests(unittest.TestCase):
    def test_a_mutant_that_does_not_compile_is_reported_as_such(self):
        from tools.slither_cli import SlitherRunError

        mutation = mutate(SOURCE, operators=("AOR",), limit_per_operator=1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            contract = Path(tmp) / "Vault.sol"
            contract.write_text(SOURCE, encoding="utf-8")
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            with mock.patch.object(mo, "_static_repair", side_effect=SlitherRunError("pragma")):
                result = mo._repair_and_check(
                    contract, Path(tmp) / "Vault.spec", "Vault", run_dir,
                    "AOR_at_10", mutation, 0, 60,
                )
        self.assertEqual(result["status"], "compile_error")
        self.assertIn("pragma", result["detail"])


if __name__ == "__main__":
    unittest.main()
