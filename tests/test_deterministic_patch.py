"""Tests for deterministic zero-check insertion.

Function bodies used to be delimited by counting braces on raw source, so a brace
inside a string literal closed the body early. The truncated body hid an existing
guard and a second, identical require was inserted.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.deterministic_patch import apply_deterministic_patches  # noqa: E402


FINDING = {
    "id": "V1",
    "type": "missing-zero-check",
    "function": "setOwner(address)",
    "target_parameter": "newOwner",
}


def _active_guards(source: str) -> int:
    return len(
        [
            line
            for line in source.splitlines()
            if "newOwner != address(0)" in line and not line.strip().startswith("//")
        ]
    )


class ZeroCheckInsertionTests(unittest.TestCase):
    def test_inserts_when_the_guard_is_absent(self):
        source = """contract C {
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertTrue(applied)
        self.assertEqual(_active_guards(patched), 1)

    def test_does_not_duplicate_an_existing_guard(self):
        source = """contract C {
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
"""
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertEqual(applied, [])
        self.assertEqual(patched, source)

    def test_brace_in_a_string_does_not_hide_an_existing_guard(self):
        """The regression: the string's brace truncated the body before the require."""
        source = """contract C {
    function setOwner(address newOwner) external {
        emit Log("closing } brace inside a string");
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
"""
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertEqual(applied, [])
        self.assertEqual(_active_guards(patched), 1)

    def test_brace_in_a_comment_does_not_hide_an_existing_guard(self):
        source = """contract C {
    function setOwner(address newOwner) external {
        // an unbalanced } lives in this comment
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
"""
        _, applied = apply_deterministic_patches(source, [FINDING])
        self.assertEqual(applied, [])

    def test_commented_out_guard_still_counts_as_missing(self):
        source = """contract C {
    function setOwner(address newOwner) external {
        // require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }
}
"""
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertTrue(applied)
        self.assertEqual(_active_guards(patched), 1)

    def test_function_named_in_a_comment_is_not_matched(self):
        source = """contract C {
    // function setOwner(address newOwner) external { old version }
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertTrue(applied)
        self.assertEqual(_active_guards(patched), 1)
        # The guard belongs to the real function, not the commented-out one.
        lines = patched.splitlines()
        guard_line = next(i for i, l in enumerate(lines) if "require(newOwner" in l)
        self.assertNotIn("//", lines[guard_line - 1])

    def test_reversed_comparison_also_counts_as_present(self):
        source = """contract C {
    function setOwner(address newOwner) external {
        require(address(0) != newOwner, "Zero address");
        owner = newOwner;
    }
}
"""
        _, applied = apply_deterministic_patches(source, [FINDING])
        self.assertEqual(applied, [])

    def test_unrelated_finding_types_are_ignored(self):
        source = "contract C { function setOwner(address newOwner) external {} }"
        _, applied = apply_deterministic_patches(source, [{**FINDING, "type": "tx-origin"}])
        self.assertEqual(applied, [])

    def test_missing_function_is_not_an_error(self):
        source = "contract C { function other() external {} }"
        patched, applied = apply_deterministic_patches(source, [FINDING])
        self.assertEqual(applied, [])
        self.assertEqual(patched, source)


if __name__ == "__main__":
    unittest.main()


def _patch(source, check, function="f()", vuln_id="V1"):
    finding = {"id": vuln_id, "type": check, "function": function}
    return apply_deterministic_patches(source, [finding])


class TxOriginTests(unittest.TestCase):
    def test_comparison_is_rewritten_to_msg_sender(self):
        source = 'contract C { address owner; function f() public {\n    require(tx.origin == owner, "no");\n} }'
        patched, applied = _patch(source, "tx-origin")
        self.assertIn("require(msg.sender == owner", patched)
        self.assertNotIn("tx.origin", patched.split("// FIX")[0])
        self.assertEqual(len(applied), 1)

    def test_eoa_check_against_msg_sender_is_left_alone(self):
        source = "contract C { function f() public {\n    require(tx.origin == msg.sender);\n} }"
        patched, applied = _patch(source, "tx-origin")
        self.assertEqual(patched, source)
        self.assertEqual(applied, [])

    def test_non_comparison_use_is_left_alone(self):
        source = "contract C { function f() public {\n    payable(tx.origin).transfer(1);\n} }"
        self.assertEqual(_patch(source, "tx-origin")[1], [])

    def test_mention_in_a_comment_is_not_patched(self):
        source = "contract C { function f() public {\n    // was: tx.origin == owner\n} }"
        self.assertEqual(_patch(source, "tx-origin")[1], [])


class UncheckedCallTests(unittest.TestCase):
    def test_ignored_call_gets_a_checked_result(self):
        source = 'contract C { function f(address t, bytes calldata p) external {\n        t.call(p);\n    } }'
        patched, applied = _patch(source, "unchecked-lowlevel", "f(address,bytes)")
        self.assertIn("(bool callOk1, ) = t.call(p);", patched)
        self.assertIn("require(callOk1,", patched)
        self.assertEqual(len(applied), 1)

    def test_two_calls_in_one_function_get_distinct_names(self):
        source = 'contract C { function f(address a, address b) external {\n        payable(a).call{value: 1}("");\n        payable(b).call{value: 2}("");\n    } }'
        patched, _ = _patch(source, "unchecked-lowlevel", "f(address,address)")
        self.assertIn("callOk1", patched)
        self.assertIn("callOk2", patched)

    def test_already_checked_call_is_untouched(self):
        source = 'contract C { function f(address t) external {\n        (bool ok, ) = t.call("");\n        require(ok);\n    } }'
        self.assertEqual(_patch(source, "unchecked-lowlevel", "f(address)")[1], [])

    def test_call_inside_require_is_untouched(self):
        source = 'contract C { function f(address t) external {\n        require(t.call(""));\n    } }'
        self.assertEqual(_patch(source, "unchecked-lowlevel", "f(address)")[1], [])


class UncheckedTransferTests(unittest.TestCase):
    def test_erc20_transfer_is_wrapped_in_require(self):
        source = "contract C { function f(address to) external {\n        token.transfer(to, 1);\n    } }"
        patched, applied = _patch(source, "unchecked-transfer", "f(address)")
        self.assertIn("require(token.transfer(to, 1),", patched)
        self.assertEqual(len(applied), 1)

    def test_eth_transfer_with_one_argument_is_untouched(self):
        source = "contract C { function f(address to) external {\n        payable(to).transfer(1);\n    } }"
        self.assertEqual(_patch(source, "unchecked-transfer", "f(address)")[1], [])

    def test_bare_function_name_from_the_static_fallback_is_accepted(self):
        source = 'contract C { function f(address t, bytes calldata p) external {\n        t.call(p);\n    } }'
        self.assertEqual(len(_patch(source, "unchecked-lowlevel", "f")[1]), 1)

    def test_non_function_label_is_not_a_function_name(self):
        source = 'contract C { function f(address t, bytes calldata p) external {\n        t.call(p);\n    } }'
        self.assertEqual(_patch(source, "unchecked-lowlevel", "modifier/function")[1], [])


class OwnerGuardTests(unittest.TestCase):
    def test_unprotected_selfdestruct_gets_an_owner_guard(self):
        source = "contract C {\n    address public owner;\n    function destroy() external {\n        selfdestruct(payable(msg.sender));\n    }\n}"
        patched, applied = _patch(source, "suicidal", "destroy")
        self.assertIn('require(msg.sender == owner, "Not owner"); // FIX V1', patched)
        self.assertLess(patched.index("require(msg.sender == owner"), patched.index("selfdestruct"))
        self.assertEqual(len(applied), 1)

    def test_no_owner_variable_means_no_patch(self):
        source = "contract C {\n    function destroy() external {\n        selfdestruct(payable(msg.sender));\n    }\n}"
        self.assertEqual(_patch(source, "suicidal", "destroy")[1], [])

    def test_function_with_a_modifier_is_left_alone(self):
        source = "contract C {\n    address owner;\n    function destroy() external onlyAdmin {\n        selfdestruct(payable(msg.sender));\n    }\n}"
        self.assertEqual(_patch(source, "suicidal", "destroy")[1], [])

    def test_existing_owner_check_is_not_duplicated(self):
        source = "contract C {\n    address owner;\n    function destroy() external {\n        require(msg.sender == owner);\n        selfdestruct(payable(owner));\n    }\n}"
        self.assertEqual(_patch(source, "suicidal", "destroy")[1], [])

    def test_return_clause_is_not_mistaken_for_a_modifier(self):
        source = "contract C {\n    address owner;\n    function destroy() external returns (bool) {\n        selfdestruct(payable(msg.sender));\n    }\n}"
        self.assertEqual(len(_patch(source, "suicidal", "destroy")[1]), 1)


class UncheckedSendTests(unittest.TestCase):
    def test_ignored_send_is_required(self):
        source = "contract C { function f(address to) external {\n        payable(to).send(1);\n    } }"
        patched, applied = _patch(source, "unchecked-send", "f(address)")
        self.assertIn("require(payable(to).send(1),", patched)
        self.assertEqual(len(applied), 1)

    def test_captured_send_is_untouched(self):
        source = "contract C { function f(address to) external {\n        bool ok = payable(to).send(1);\n        require(ok);\n    } }"
        self.assertEqual(_patch(source, "unchecked-send", "f(address)")[1], [])

    def test_interface_method_named_call_is_not_treated_as_a_low_level_call(self):
        source = "contract C { function f(address a, bytes calldata p) external {\n        IVirtualAccount(a).call(p);\n    } }"
        self.assertEqual(_patch(source, "unchecked-lowlevel", "f(address,bytes)")[1], [])

    def test_payable_and_address_receivers_are_still_patched(self):
        for receiver in ("payable(a)", "address(a)", "a"):
            with self.subTest(receiver=receiver):
                source = f'contract C {{ function f(address a) external {{\n        {receiver}.call("");\n    }} }}'
                self.assertEqual(len(_patch(source, "unchecked-lowlevel", "f(address)")[1]), 1)


class ConstructorZeroCheckTests(unittest.TestCase):
    def test_constructor_parameter_gets_a_zero_check(self):
        source = "contract C {\n    address owner;\n    constructor(address _owner) {\n        owner = _owner;\n    }\n}"
        finding = {"id": "V1", "type": "missing-zero-check", "function": "constructor(address)", "target_parameter": "_owner"}
        patched, applied = apply_deterministic_patches(source, [finding])
        self.assertIn('require(_owner != address(0), "Zero address"); // FIX V1', patched)
        self.assertEqual(len(applied), 1)

    def test_the_constructor_that_takes_the_parameter_is_chosen(self):
        source = (
            "contract A {\n    constructor(uint256 x) {\n        y = x;\n    }\n}\n"
            "contract B {\n    constructor(address _owner) {\n        owner = _owner;\n    }\n}"
        )
        finding = {"id": "V1", "type": "missing-zero-check", "function": "constructor(address)", "target_parameter": "_owner"}
        patched, _ = apply_deterministic_patches(source, [finding])
        self.assertLess(patched.index("contract B"), patched.index("require(_owner"))

    def test_existing_constructor_guard_is_not_duplicated(self):
        source = "contract C {\n    constructor(address _owner) {\n        require(_owner != address(0));\n        owner = _owner;\n    }\n}"
        finding = {"id": "V1", "type": "missing-zero-check", "function": "constructor(address)", "target_parameter": "_owner"}
        self.assertEqual(apply_deterministic_patches(source, [finding])[1], [])
