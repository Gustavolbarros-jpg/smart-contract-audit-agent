"""Tests for the unrestricted-write Slither detector (agent/slither_plugins/unrestricted_write.py).

Two sources of ground truth:

- hand-written fixtures in tests/fixtures/unrestricted_write/, each a single contract
  whose header comment says which functions are POSITIVE and NEGATIVE;
- ``mutate_md`` mutants of the benchmark contracts: removing a modifier re-introduces a
  missing guard, and the unmutated original is the matching negative.

Not every MD mutant is an unrestricted write to privileged state (removing ``notPaused``
or ``nonReentrant`` is not, nor is removing ``onlyOwner`` from a function that writes no
state). ``EXPECTED_MD_FLAGGED`` pins which touched functions are reported, so a change
in either direction shows up here; docs/unrestricted-write-detector.md explains each miss.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.mutation import mutate_md  # noqa: E402
from core.slither_normalizer import normalize_slither_json  # noqa: E402
from core.solidity_source import parse_definitions  # noqa: E402

try:
    import slither  # noqa: F401
except ImportError:
    SLITHER_AVAILABLE = False
else:
    SLITHER_AVAILABLE = True
    from tools.slither_plugin_runner import run_unrestricted_write  # noqa: E402

SKIP_REASON = "slither is not importable; the unrestricted-write detector cannot run"

FIXTURES = ROOT / "tests" / "fixtures" / "unrestricted_write"
CONTRACTS = ROOT / "smart-audt" / "contracts"

# fixture -> functions that must be reported; every other function must not be.
FIXTURE_EXPECTATIONS = {
    "UnprotectedSetOwner.sol": {"setOwner"},
    "OnlyOwnerSetOwner.sol": set(),
    "InlineRequireOwner.sol": set(),
    "RoleMapping.sol": {"addAdmin"},
    "CustomModifierAuth.sol": set(),
    "SelfBalance.sol": set(),
    "Initializer.sol": set(),
    "ConstructorOnly.sol": set(),
    "HelperGuards.sol": set(),
    "UnprotectedConfig.sol": {"pause", "setFeeCollector"},
    "PaymentGated.sol": set(),
    "DenyList.sol": {"unblock"},
    "BodyLock.sol": set(),
}

# contract -> functions whose MD mutant must be reported. Every other MD mutant of the
# same contract must not be reported (see the module docstring).
EXPECTED_MD_FLAGGED = {
    "DeFiVault_FIXED.sol": {
        "removeFromWhitelist", "unpause", "setRewardRate", "setMaxWithdraw",
        "setLockPeriod", "transferOwnership",
    },
    "SimpleBank_FIXED.sol": {
        "collectFees", "setFeeCollector", "transferOwnership", "freeze", "unfreeze",
        "setFeePercent",
    },
    "SafeBankToken.sol": set(),
    "SafeBankToken2.sol": set(),
    "SuperSecureBank.sol": set(),
    "DeFiVault.sol": {
        "removeFromWhitelist", "unpause", "setRewardRate", "setMaxWithdraw",
        "setLockPeriod", "transferOwnership",
    },
    "SimpleBank.sol": {
        "collectFees", "setFeeCollector", "transferOwnership", "freeze", "unfreeze",
        "setFeePercent",
    },
    "CrowdfundingVault.sol": {"updateFee", "transferOwnership"},
    "King.sol": {"forceKing"},
    "EnterpriseTreasury300.sol": {
        "createGrant", "createProposal", "executeProposal", "setOperator", "setBlocked",
        "setFee", "setMaxDailyWithdrawal", "setFeeCollector", "setEmergencyCouncil",
        "transferOwnership", "unpause",
    },
    "VulnerableBankToken.sol": set(),
    "VulnerableBankTokenCorrected.sol": set(),
}


def _flagged_functions(results: list[dict]) -> dict[str, list[int]]:
    """Function name -> lines of that function, for every reported function."""
    flagged = {}
    for result in results:
        function = next(e for e in result["elements"] if e["type"] == "function")
        flagged[function["name"]] = function["source_mapping"]["lines"]
    return flagged


def _touched_function(source: str, line: int) -> str:
    """The function whose header the mutation edited; mutate_md's description can name
    a different one when the name first occurs elsewhere in the source."""
    for definition in parse_definitions(source):
        if definition.kind == "function" and definition.start_line <= line <= definition.end_line:
            return definition.name
    raise AssertionError(f"no function contains mutated line {line}")


@unittest.skipUnless(SLITHER_AVAILABLE, SKIP_REASON)
class FixtureTests(unittest.TestCase):
    def test_fixtures_flag_exactly_the_positive_functions(self):
        for name, expected in FIXTURE_EXPECTATIONS.items():
            with self.subTest(fixture=name):
                results = run_unrestricted_write(str(FIXTURES / name))
                self.assertEqual(set(_flagged_functions(results)), expected)

    def test_every_fixture_is_covered(self):
        on_disk = {path.name for path in FIXTURES.glob("*.sol")}
        self.assertEqual(on_disk, set(FIXTURE_EXPECTATIONS))

    def test_result_has_slither_json_shape(self):
        results = run_unrestricted_write(str(FIXTURES / "UnprotectedSetOwner.sol"))
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result["check"], "unrestricted-write")
        self.assertEqual(result["impact"], "High")
        self.assertEqual(result["confidence"], "Medium")
        self.assertIn("setOwner", result["description"])
        kinds = {element["type"] for element in result["elements"]}
        self.assertTrue({"function", "variable", "node"} <= kinds)
        for element in result["elements"]:
            self.assertTrue(element["name"])
            self.assertTrue(element["source_mapping"]["lines"])

    def test_normalizer_consumes_results(self):
        path = str(FIXTURES / "UnprotectedSetOwner.sol")
        payload = {"success": True, "results": {"detectors": run_unrestricted_write(path)}}
        normalized = normalize_slither_json(payload, path)["vulnerabilidades"]
        finding = next(v for v in normalized if v["type"] == "unrestricted-write")
        self.assertEqual(finding["impact"], "high")
        self.assertEqual(finding["function"], "setOwner")
        self.assertIn({"name": "owner", "type": "variable", "line": "6"}, finding["elements"])


@unittest.skipUnless(SLITHER_AVAILABLE, SKIP_REASON)
class MutationTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._tmp = self._tmpdir.name

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_originals_have_no_findings(self):
        for name in EXPECTED_MD_FLAGGED:
            with self.subTest(contract=name):
                self.assertEqual(run_unrestricted_write(str(CONTRACTS / name)), [])

    @unittest.skipUnless(
        os.environ.get("RUN_SLOW_TESTS"),
        "compiles ~80 mutants (about 45 s); set RUN_SLOW_TESTS=1 to run the recall sweep",
    )
    def test_md_mutants_are_flagged_on_the_touched_function(self):
        for name, expected in EXPECTED_MD_FLAGGED.items():
            source = (CONTRACTS / name).read_text(encoding="utf-8")
            seen_sources = set()
            for index, mutation in enumerate(mutate_md(source, limit=10_000)):
                if mutation.source in seen_sources:
                    continue  # mutate_md can emit the same edit under two descriptions
                seen_sources.add(mutation.source)
                touched = _touched_function(mutation.source, mutation.line)
                with self.subTest(contract=name, mutation=mutation.description, touched=touched):
                    mutant = Path(self._tmp) / f"{Path(name).stem}_MD{index}.sol"
                    mutant.write_text(mutation.source, encoding="utf-8")
                    flagged = _flagged_functions(run_unrestricted_write(str(mutant)))
                    was_flagged = touched in flagged and mutation.line in flagged[touched]
                    self.assertEqual(was_flagged, touched in expected)
                    # Removing a guard must not make the detector report other functions.
                    self.assertTrue(set(flagged) <= {touched})

    def test_contract_without_modifiers_still_reports_an_unguarded_setter(self):
        # TimelockVault.extendLock overwrites the constructor-set unlockTime for any caller.
        results = run_unrestricted_write(str(CONTRACTS / "TimelockVault.sol"))
        self.assertEqual(set(_flagged_functions(results)), {"extendLock"})


if __name__ == "__main__":
    unittest.main()
