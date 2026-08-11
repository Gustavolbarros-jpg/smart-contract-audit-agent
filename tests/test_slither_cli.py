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
