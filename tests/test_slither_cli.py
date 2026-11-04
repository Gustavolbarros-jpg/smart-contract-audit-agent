"""Tests for Slither invocation failure handling.

A crashed Slither run used to be returned as ``{"success": True, "detectors": []}``,
which the pipeline reports as a contract with nothing to fix. These tests pin the
distinction between "analyzed and found nothing" and "could not analyze".
"""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from tools.slither_cli import SlitherRunError, run_slither_raw  # noqa: E402


CONTRACT = str(ROOT / "smart-audt" / "contracts" / "SimpleBank.sol")


def _completed(stdout: str, stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        args=["slither"], returncode=returncode, stdout=stdout, stderr=stderr
    )


class SlitherFailureTests(unittest.TestCase):
    def test_empty_output_raises_instead_of_reporting_a_clean_contract(self):
        with mock.patch("subprocess.run", return_value=_completed("", "", 1)):
            with self.assertRaises(SlitherRunError) as ctx:
                run_slither_raw(CONTRACT)
        self.assertIn("exit 1", str(ctx.exception))

    def test_error_message_carries_stderr_when_present(self):
        stderr = "Traceback...\nurllib.error.HTTPError: HTTP Error 403: Forbidden"
        with mock.patch("subprocess.run", return_value=_completed("", stderr, 1)):
            with self.assertRaises(SlitherRunError) as ctx:
                run_slither_raw(CONTRACT)
        self.assertIn("403", str(ctx.exception))

    def test_error_message_is_actionable_when_both_streams_are_empty(self):
        with mock.patch("subprocess.run", return_value=_completed("", "", 1)):
            with self.assertRaises(SlitherRunError) as ctx:
                run_slither_raw(CONTRACT)
        message = str(ctx.exception)
        self.assertIn("Reproduza com:", message)
        self.assertIn("slither", message)

    def test_success_false_in_payload_raises(self):
        payload = '{"success": false, "error": "solc not found", "results": {}}'
        with mock.patch("subprocess.run", return_value=_completed(payload, "", 0)):
            with self.assertRaises(SlitherRunError) as ctx:
                run_slither_raw(CONTRACT)
        self.assertIn("solc not found", str(ctx.exception))

    def test_genuinely_clean_contract_is_not_an_error(self):
        payload = '{"success": true, "error": null, "results": {"detectors": []}}'
        with mock.patch("subprocess.run", return_value=_completed(payload, "", 0)):
            result = run_slither_raw(CONTRACT)
        self.assertEqual(result["results"]["detectors"], [])

    def test_findings_are_returned_unchanged(self):
        payload = '{"success": true, "results": {"detectors": [{"check": "tx-origin"}]}}'
        with mock.patch("subprocess.run", return_value=_completed(payload, "", 1)):
            result = run_slither_raw(CONTRACT)
        self.assertEqual(len(result["results"]["detectors"]), 1)

    def test_invalid_json_raises_value_error(self):
        with mock.patch("subprocess.run", return_value=_completed("not json", "", 0)):
            with self.assertRaises(ValueError):
                run_slither_raw(CONTRACT)

    def test_timeout_is_reported_as_timeout(self):
        with mock.patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="slither", timeout=120)
        ):
            with self.assertRaises(TimeoutError):
                run_slither_raw(CONTRACT)

    def test_missing_contract_raises_before_running(self):
        with self.assertRaises(FileNotFoundError):
            run_slither_raw(str(ROOT / "does-not-exist.sol"))


if __name__ == "__main__":
    unittest.main()


class TxOriginFallbackTests(unittest.TestCase):
    def _types(self, source):
        import tempfile
        from core.slither_normalizer import _fallback_findings

        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
        return [f["type"] for f in _fallback_findings(handle.name, set(), 1)]

    def test_real_use_is_reported(self):
        self.assertIn("tx-origin", self._types("contract C { function f() public { require(tx.origin == owner); } }"))

    def test_mention_in_a_comment_or_string_is_not(self):
        source = 'contract C { function f() public { require(msg.sender == owner, "not tx.origin"); // was tx.origin\n} }'
        self.assertNotIn("tx-origin", self._types(source))


class ProjectRunOptionsTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "src").mkdir()
        self.contract = self.root / "src" / "C.sol"
        self.contract.write_text("contract C {}", encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_contract_outside_a_foundry_project_keeps_the_default_cwd(self):
        from tools.slither_cli import _project_run_options

        self.assertEqual(_project_run_options(CONTRACT), {})

    def test_contract_inside_a_foundry_project_runs_from_its_root(self):
        from tools.slither_cli import _project_run_options

        (self.root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        self.assertEqual(_project_run_options(str(self.contract))["cwd"], str(self.root.resolve()))

    def test_all_three_spellings_of_the_solc_pin_are_read(self):
        from tools.slither_cli import pinned_solc

        for line in ('solc = "0.8.18"', "solc_version = '0.8.17'", 'solc-version = "0.8.19"'):
            with self.subTest(line=line):
                (self.root / "foundry.toml").write_text(f"[profile.default]\n{line}\n", encoding="utf-8")
                self.assertEqual(pinned_solc(self.root), line.split("=")[1].strip(" '\""))

    def test_explicit_solc_version_wins_over_the_project_pin(self):
        from tools.slither_cli import _project_run_options

        (self.root / "foundry.toml").write_text('solc = "0.8.17"\n', encoding="utf-8")
        with mock.patch.dict("os.environ", {"SOLC_VERSION": "0.8.26"}):
            self.assertNotIn("env", _project_run_options(str(self.contract)))

    def test_run_passes_the_project_root_to_subprocess(self):
        (self.root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        payload = '{"success": true, "error": null, "results": {"detectors": []}}'
        with mock.patch("subprocess.run", return_value=_completed(payload)) as run:
            run_slither_raw(str(self.contract))
        self.assertEqual(run.call_args.kwargs["cwd"], str(self.root.resolve()))

    def test_remappings_file_marks_a_project_without_foundry_toml(self):
        from tools.slither_cli import _project_run_options

        (self.root / "remappings.txt").write_text("lib/=lib/\n", encoding="utf-8")
        self.assertEqual(_project_run_options(str(self.contract))["cwd"], str(self.root.resolve()))

    def test_bare_src_directory_falls_back_to_its_parent(self):
        from tools.slither_cli import _project_run_options

        self.assertEqual(_project_run_options(str(self.contract))["cwd"], str(self.root.resolve()))


class InterfaceCallFallbackTests(unittest.TestCase):
    def _calls(self, statement):
        from core.slither_normalizer import _low_level_call_contexts

        source = f"contract C {{\n    function f(address a, bytes memory p) external {{\n        {statement}\n    }}\n}}"
        return _low_level_call_contexts(source)

    def test_interface_method_named_call_is_not_a_low_level_call(self):
        self.assertEqual(self._calls("IVirtualAccount(a).call(p);"), [])

    def test_payable_and_address_calls_are_still_low_level(self):
        for statement in ('payable(a).call{value: 1}("");', 'address(a).call(p);', "a.call(p);"):
            with self.subTest(statement=statement):
                self.assertEqual(len(self._calls(statement)), 1)
