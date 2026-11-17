"""O probe não pode aceitar um reparo pela palavra do Slither: a spec congelada decide."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

import generalization_probe as probe  # noqa: E402
from tools.certora_cli import LocalVerdict  # noqa: E402


class OracleCheckTests(unittest.TestCase):
    def _check(self, verdict):
        with tempfile.TemporaryDirectory() as tmp:
            fixed = Path(tmp) / "Vault_FIXED.sol"
            fixed.write_text("contract Vault {}", encoding="utf-8")
            spec = Path(tmp) / "Vault.spec"
            spec.write_text("rule r { assert true; }", encoding="utf-8")
            with mock.patch.object(probe, "verify_locally", return_value=verdict) as call:
                result = probe._oracle_check(fixed, spec, "Vault", 60, None)
            return result, call

    def test_a_clean_verdict_is_a_repair(self):
        result, call = self._check(
            LocalVerdict(status="verified", rules={"r": "verified"}, sanity={"r-rule_not_vacuous": "violated"})
        )
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["vacuous"], [])
        # O caminho vai absoluto: o cwd muda para a pasta do contrato reparado.
        self.assertTrue(Path(call.call_args.args[0]).is_absolute())

    def test_a_rule_that_passed_unreachable_is_not_a_repair(self):
        result, _ = self._check(
            LocalVerdict(status="verified", rules={"r": "verified"}, sanity={"r-rule_not_vacuous": "verified"})
        )
        self.assertEqual(result["status"], "vacuous")
        self.assertEqual(result["vacuous"], ["r"])

    def test_a_violated_rule_is_reported_with_its_name(self):
        result, _ = self._check(LocalVerdict(status="violated", rules={"r": "violated"}))
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["violated"], ["r"])

    def test_a_prover_error_is_not_silently_a_repair(self):
        result, _ = self._check(LocalVerdict(status="error", detail="spec error"))
        self.assertEqual(result["status"], "error")


if __name__ == "__main__":
    unittest.main()
