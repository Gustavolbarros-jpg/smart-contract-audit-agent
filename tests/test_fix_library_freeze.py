"""A biblioteca de moldes tem de poder ser congelada por braço do experimento."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core import fix_library  # noqa: E402


class LibraryPathTests(unittest.TestCase):
    def test_without_the_override_it_is_the_project_library(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUDIT_FIX_LIBRARY", None)
            self.assertEqual(fix_library.library_path(), fix_library.LIBRARY_PATH)

    def test_the_override_redirects_reads_and_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            arm = Path(tmp) / "arm_llm_only" / "fix_library.json"
            with mock.patch.dict(os.environ, {"AUDIT_FIX_LIBRARY": str(arm)}):
                self.assertEqual(fix_library.load_library(), {"version": 1, "patterns": []})
                fix_library.save_pattern(
                    "tx-origin", "replace_tx_origin", "f()", "require(msg.sender == owner);",
                    "Vault", "run-1",
                )
                stored = json.loads(arm.read_text(encoding="utf-8"))
            self.assertEqual(len(stored["patterns"]), 1)
            self.assertEqual(stored["patterns"][0]["vuln_type"], "tx-origin")

    def test_an_arms_write_never_reaches_the_project_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            arm = Path(tmp) / "fix_library.json"
            project = Path(tmp) / "project.json"
            with mock.patch.object(fix_library, "LIBRARY_PATH", project):
                with mock.patch.dict(os.environ, {"AUDIT_FIX_LIBRARY": str(arm)}):
                    fix_library.save_pattern(
                        "suicidal", "require_owner", "destroy()", "require(msg.sender == owner);",
                        "Vault", "run-1",
                    )
            self.assertTrue(arm.is_file())
            self.assertFalse(project.exists())

    def test_examples_come_from_the_arms_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            arm = Path(tmp) / "fix_library.json"
            arm.write_text(json.dumps({"version": 1, "patterns": [{
                "vuln_type": "tx-origin",
                "repair_strategy": "replace_tx_origin",
                "function_signature": "f()",
                "fix_snippet": "require(msg.sender == owner);",
                "contract_name": "Vault",
                "run_id": "run-0",
            }]}), encoding="utf-8")
            with mock.patch.dict(os.environ, {"AUDIT_FIX_LIBRARY": str(arm)}):
                examples = fix_library.get_examples_for_prompt(["tx-origin"])
                empty = fix_library.get_examples_for_prompt(["divide-before-multiply"])
            self.assertIn("require(msg.sender == owner);", examples)
            self.assertEqual(empty, "")


if __name__ == "__main__":
    unittest.main()
