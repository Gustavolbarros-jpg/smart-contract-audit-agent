"""run_certora must hand the Prover a file name it accepts, and the local oracle must
read a verdict out of the Prover's own log."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from tools import certora_cli  # noqa: E402


# Trimmed from runs/oracle_validation_20261116/: the real log of the validated pair.
VERIFIED_LOG = """Start Mon Nov 16 18:12:24 BRT 2026
Checking rule withdraw_debits_exactly (1 out of 2)...
Result for envfreeFuncsStaticCheck: envfreeFuncsStaticCheck: balances(address): SUCCESS
Verified: withdraw_debits_exactly
withdraw_debits_exactly: Properties successfully verified on all inputs
Violated: withdraw_debits_exactly-rule_not_vacuous
withdraw_debits_exactly-rule_not_vacuous: A property is violated

Results for all:
|Rule name                |Verified     |Time (sec)|
|withdraw_debits_exactly  |Not violated |1         |
Done 0m
"""

VIOLATED_LOG = """Start Mon Nov 16 18:12:42 BRT 2026
Violated: withdraw_debits_exactly
withdraw_debits_exactly: A property is violated
received `signalSkip` for rule withdraw_debits_exactly-rule_not_vacuous
Result for withdraw_debits_exactly: withdraw_debits_exactly: FAIL: to_mathint(DeFiVault.balances(e.msg.send...
Done 0m
"""

SPEC_ERROR_LOG = """Start Mon Nov 16 10:00:00 BRT 2026
Error in spec file (Vault.spec): unexpected token near `rules`
"""


class SafeCopyTests(unittest.TestCase):
    def test_hyphenated_name_gets_a_sanitized_copy_beside_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "gas-price.sol"
            source.write_text("contract A {}", encoding="utf-8")
            copy = certora_cli._certora_safe_copy(str(source))
            self.assertEqual(Path(copy).parent, source.parent)
            self.assertEqual(Path(copy).name, "_certora_gas_price.sol")
            self.assertEqual(Path(copy).read_text(encoding="utf-8"), "contract A {}")

    def test_plain_name_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Vault.sol"
            source.write_text("contract Vault {}", encoding="utf-8")
            self.assertIsNone(certora_cli._certora_safe_copy(str(source)))

    def test_run_passes_the_copy_and_removes_it_afterwards(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "gas-price.sol"
            source.write_text("contract A {}", encoding="utf-8")
            spec = Path(tmp) / "A.spec"
            spec.write_text("", encoding="utf-8")
            with mock.patch.object(certora_cli.subprocess, "run") as run:
                run.return_value = mock.Mock(stdout="", stderr="")
                certora_cli.run_certora(str(source), str(spec), tmp, "A")
            self.assertTrue(run.call_args.args[0][1].endswith("_certora_gas_price.sol:A"))
            self.assertFalse((Path(tmp) / "_certora_gas_price.sol").exists())


class ArgvTests(unittest.TestCase):
    def test_the_cloud_run_never_carries_the_local_only_flag(self):
        argv = certora_cli.certora_argv("/x/Vault.sol", "/x/Vault.spec", "Vault")
        self.assertNotIn(certora_cli.LOCAL_ONLY_FLAG, argv)
        self.assertEqual(argv[1], "/x/Vault.sol:Vault")
        self.assertEqual(argv[argv.index("--verify") + 1], "Vault:/x/Vault.spec")

    def test_the_oracle_keeps_the_allow_path_the_prover_demands(self):
        # Omitting it is what made the first oracle run die with "File outside of allowed
        # directories. The following are allowed: '.'".
        argv = certora_cli.certora_argv(
            "/x/Vault.sol", "/x/Vault.spec", "Vault", local_only=True
        )
        self.assertIn(certora_cli.LOCAL_ONLY_FLAG, argv)
        self.assertEqual(argv[argv.index("--solc_allow_path") + 1], "..")

    def test_an_absolute_allow_path_replaces_the_relative_default(self):
        argv = certora_cli.certora_argv(
            "/x/Vault.sol", "/x/Vault.spec", "Vault", local_only=True, allow_path="/repo"
        )
        self.assertEqual(argv[argv.index("--solc_allow_path") + 1], "/repo")


class LocalModeTests(unittest.TestCase):
    """AUDIT_CERTORA_LOCAL lets the whole pipeline run without cloud quota."""

    def _cloud_argv(self, env):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Vault.sol"
            source.write_text("contract Vault {}", encoding="utf-8")
            spec = Path(tmp) / "Vault.spec"
            spec.write_text("", encoding="utf-8")
            with mock.patch.dict(certora_cli.os.environ, env, clear=False):
                with mock.patch.object(certora_cli.subprocess, "run") as run:
                    run.return_value = mock.Mock(stdout="", stderr="")
                    certora_cli.run_certora(str(source), str(spec), tmp, "Vault")
            return run.call_args.args[0]

    def test_unset_means_the_cloud_run_as_before(self):
        with mock.patch.dict(certora_cli.os.environ, {}, clear=False):
            certora_cli.os.environ.pop("AUDIT_CERTORA_LOCAL", None)
            self.assertNotIn(certora_cli.LOCAL_ONLY_FLAG, self._cloud_argv({}))

    def test_one_means_local_only(self):
        self.assertIn(
            certora_cli.LOCAL_ONLY_FLAG, self._cloud_argv({"AUDIT_CERTORA_LOCAL": "1"})
        )

    def test_zero_is_not_a_request_for_the_local_verifier(self):
        self.assertNotIn(
            certora_cli.LOCAL_ONLY_FLAG, self._cloud_argv({"AUDIT_CERTORA_LOCAL": "0"})
        )


class VerdictParsingTests(unittest.TestCase):
    def test_verified_log_is_verified_and_the_vacuity_check_stays_out_of_it(self):
        verdict = certora_cli.parse_local_verdict(VERIFIED_LOG)
        self.assertEqual(verdict.status, "verified")
        self.assertEqual(verdict.rules, {"withdraw_debits_exactly": "verified"})
        self.assertEqual(
            verdict.sanity, {"withdraw_debits_exactly-rule_not_vacuous": "violated"}
        )
        self.assertEqual(verdict.violated_rules, [])
        self.assertTrue(verdict.conclusive)

    def test_violated_log_names_the_rule_that_failed(self):
        verdict = certora_cli.parse_local_verdict(VIOLATED_LOG)
        self.assertEqual(verdict.status, "violated")
        self.assertEqual(verdict.violated_rules, ["withdraw_debits_exactly"])
        self.assertTrue(verdict.conclusive)

    def test_the_results_table_is_not_read_as_a_verdict(self):
        # "|Rule name ... |Verified     |" would otherwise match a Verified: line.
        verdict = certora_cli.parse_local_verdict(VERIFIED_LOG)
        self.assertNotIn("Not", "".join(verdict.rules))
        self.assertEqual(len(verdict.rules), 1)

    def test_a_spec_error_is_an_error_not_a_verdict(self):
        verdict = certora_cli.parse_local_verdict(SPEC_ERROR_LOG)
        self.assertEqual(verdict.status, "error")
        self.assertEqual(verdict.rules, {})
        self.assertFalse(verdict.conclusive)
        self.assertIn("cvl", verdict.detail)

    def test_an_empty_log_is_an_error_with_a_reason(self):
        verdict = certora_cli.parse_local_verdict("")
        self.assertEqual(verdict.status, "error")
        self.assertIn("nenhum veredito", verdict.detail)


class VerifyLocallyTests(unittest.TestCase):
    def _run(self, tmp, log_text, **kwargs):
        source = Path(tmp) / "Vault.sol"
        source.write_text("contract Vault {}", encoding="utf-8")
        spec = Path(tmp) / "Vault.spec"
        spec.write_text("rule r { assert true; }", encoding="utf-8")

        def fake_run(argv, **call):
            call["stdout"].write(log_text)
            return mock.Mock(returncode=0)

        with mock.patch.object(certora_cli.subprocess, "run", side_effect=fake_run) as run:
            verdict = certora_cli.verify_locally(str(source), str(spec), "Vault", **kwargs)
        return verdict, run

    def test_it_asks_for_the_local_verifier_and_reports_the_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            verdict, run = self._run(tmp, VIOLATED_LOG)
            self.assertEqual(verdict.status, "violated")
            self.assertIn(certora_cli.LOCAL_ONLY_FLAG, run.call_args.args[0])
            self.assertIn(certora_cli.LOCAL_ONLY_FLAG, verdict.argv)

    def test_the_display_is_stripped_so_no_browser_opens(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(certora_cli.os.environ, {"DISPLAY": ":0"}):
                _, run = self._run(tmp, VERIFIED_LOG)
            self.assertNotIn("DISPLAY", run.call_args.kwargs["env"])

    def test_it_keeps_the_log_where_the_caller_asked(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "oracle.log"
            verdict, _ = self._run(tmp, VERIFIED_LOG, log_path=str(log))
            self.assertEqual(verdict.status, "verified")
            self.assertIn("Verified: withdraw_debits_exactly", log.read_text(encoding="utf-8"))

    def test_a_timeout_keeps_what_the_prover_had_already_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Vault.sol"
            source.write_text("contract Vault {}", encoding="utf-8")
            spec = Path(tmp) / "Vault.spec"
            spec.write_text("rule r { assert true; }", encoding="utf-8")

            def slow_run(argv, **call):
                call["stdout"].write("Checking rule r (1 out of 1)...\n")
                raise certora_cli.subprocess.TimeoutExpired(argv, 1)

            with mock.patch.object(certora_cli.subprocess, "run", side_effect=slow_run):
                verdict = certora_cli.verify_locally(str(source), str(spec), "Vault", timeout=1)
            self.assertEqual(verdict.status, "timeout")
            self.assertFalse(verdict.conclusive)
            self.assertIn("Checking rule r", verdict.log)

    def test_a_missing_spec_is_refused_before_the_prover_is_called(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Vault.sol"
            source.write_text("contract Vault {}", encoding="utf-8")
            with self.assertRaises(FileNotFoundError):
                certora_cli.verify_locally(str(source), str(Path(tmp) / "nope.spec"), "Vault")


if __name__ == "__main__":
    unittest.main()
