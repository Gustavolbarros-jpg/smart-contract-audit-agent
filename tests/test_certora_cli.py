"""run_certora must hand the Prover a file name it accepts."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from tools import certora_cli  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
