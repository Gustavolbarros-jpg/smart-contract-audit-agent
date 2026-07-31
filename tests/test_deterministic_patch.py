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
