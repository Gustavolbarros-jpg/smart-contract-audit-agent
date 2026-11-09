import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from core.deterministic_patch import apply_deterministic_patches  # noqa: E402
from core.slither_normalizer import _low_level_call_contexts  # noqa: E402


def _checked(source):
    return [c["checked_return"] for c in _low_level_call_contexts(source)]


WRAP = "pragma solidity ^0.8.0;\ncontract C {\n%s\n}\n"


class UncheckedCallShapeTests(unittest.TestCase):
    def test_require_split_across_lines_counts_as_checked(self):
        body = '''  function send(address payable r, uint256 a) internal {
    (bool success, ) = r.call{value: a}("");
    require(
      success,
      "failed"
    );
  }'''
        self.assertEqual([True], _checked(WRAP % body))

    def test_success_handed_to_a_helper_counts_as_checked(self):
        body = '''  function call(address t, bytes memory d) internal returns (bytes memory) {
    (bool success, bytes memory ret) = t.call(d);
    return
      verify(t, success, ret, "e");
  }'''
        self.assertEqual([True], _checked(WRAP % body))

    def test_an_ignored_success_is_still_flagged(self):
        body = '''  function call(address t, bytes memory d) internal {
    (bool success, ) = t.call(d);
    emit Done(success);
  }'''
        self.assertEqual([False], _checked(WRAP % body))

    def test_transfer_under_a_one_line_if_is_wrapped_in_require(self):
        body = '''  function pay(IERC20 t, uint256 a) external {
    if (a > 0) t.transfer(msg.sender, a);
  }'''
        patched, applied = apply_deterministic_patches(
            WRAP % body, [{"id": "VULN_001", "type": "unchecked-transfer", "function": "pay(IERC20,uint256)"}]
        )
        self.assertEqual(1, len(applied))
        self.assertIn('if (a > 0) require(t.transfer(msg.sender, a), "Token transfer failed");', patched)


if __name__ == "__main__":
    unittest.main()


class SpecShapeTests(unittest.TestCase):
    def test_deterministic_zero_check_spec_declares_interface_params_as_address(self):
        from core.deterministic_spec import build_deterministic_spec

        methods = "methods {\n  function initialize(address _token, address _b) external;\n}"
        spec = build_deterministic_spec(methods, [{
            "id": "VULN_002", "type": "missing-zero-check",
            "function": "initialize(IERC20,address)", "target_parameter": "_b",
        }])
        self.assertIsNotNone(spec)
        self.assertNotIn("IERC20", spec)

    def test_auth_probe_is_skipped_when_the_contract_has_no_owner_getter(self):
        from tools.spec_validator import aplicar_auth_probe_rules

        spec = "methods {\n  function finalize() external;\n}\n// VULN_002 - suicidal\nrule finalize_owner_only {\n  finalize();\n}\n"
        fixed, changes = aplicar_auth_probe_rules(spec, {"name": "cancel", "params": []})
        self.assertEqual(spec, fixed)
        self.assertEqual([], changes)
