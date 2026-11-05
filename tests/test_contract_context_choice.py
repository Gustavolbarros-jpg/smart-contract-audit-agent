"""The methods block and brief must describe the contract chosen for verification."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.contract_context import build_methods_block  # noqa: E402

SOURCE = """
contract Vault {
    function deposit(uint256 amount) external {
    }
}
contract Token {
    function totalSupply() external view returns (uint256) {
        return 0;
    }
}
"""


class ChosenContractTests(unittest.TestCase):
    def test_default_is_the_last_contract(self):
        self.assertIn("totalSupply", build_methods_block(SOURCE))

    def test_named_contract_is_described_instead(self):
        block = build_methods_block(SOURCE, "Vault")
        self.assertIn("deposit", block)
        self.assertNotIn("totalSupply", block)


if __name__ == "__main__":
    unittest.main()
