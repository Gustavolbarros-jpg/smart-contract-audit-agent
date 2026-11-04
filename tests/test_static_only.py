import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.static_only import build_report, classify
from core.vulnerability_catalog import get_catalog_entry


def _finding(idx, check, function="f(address)"):
    return {"id": f"VULN_{idx:03d}", "type": check, "function": function, "line": "1", "impact": "low"}


class StaticOnlyTests(unittest.TestCase):
    def test_lanes_follow_catalog_policy(self):
        self.assertEqual(classify({}, get_catalog_entry("missing-zero-check")), "formalizable")
        self.assertEqual(classify({}, get_catalog_entry("unchecked-lowlevel")), "static_confirmed")
        self.assertEqual(classify({}, get_catalog_entry("timestamp")), "triage_only")
        self.assertEqual(classify({}, get_catalog_entry("not-a-real-detector")), "unmapped")

    def test_new_catalog_entries_are_triage_only(self):
        self.assertEqual(classify({}, get_catalog_entry("shadowing-state")), "triage_only")

    def test_patched_finding_counts_as_resolved_only_when_slither_stops_reporting_it(self):
        findings = [_finding(1, "missing-zero-check", "a(address)"), _finding(2, "missing-zero-check", "b(address)")]
        patches = [{"id": "VULN_001"}, {"id": "VULN_002"}]
        remaining = [_finding(1, "missing-zero-check", "b(address)")]
        report = build_report(findings, patches, remaining)
        by_id = {row["id"]: row for row in report["findings"]}
        self.assertTrue(by_id["VULN_001"]["resolved_after_rerun"])
        self.assertFalse(by_id["VULN_002"]["resolved_after_rerun"])
        self.assertEqual(report["patched"], 2)
        self.assertEqual(report["resolved_after_rerun"], 1)

    def test_unpatched_finding_is_never_resolved(self):
        report = build_report([_finding(1, "tx-origin", "m")], [], [])
        self.assertFalse(report["findings"][0]["resolved_after_rerun"])


if __name__ == "__main__":
    unittest.main()


class ScopeTests(unittest.TestCase):
    def _detector(self, *filenames):
        return {"check": "x", "elements": [{"source_mapping": {"filename_absolute": n}} for n in filenames]}

    def test_detectors_in_imported_files_are_dropped(self):
        from core.static_only import scoped_to_file

        here = Path("/p/A.sol")
        raw = {"results": {"detectors": [self._detector("/p/A.sol"), self._detector("/p/lib/B.sol")]}}
        kept = scoped_to_file(raw, here)["results"]["detectors"]
        self.assertEqual(len(kept), 1)

    def test_detector_without_source_mapping_is_kept(self):
        from core.static_only import scoped_to_file

        raw = {"results": {"detectors": [{"check": "x", "elements": []}]}}
        self.assertEqual(len(scoped_to_file(raw, Path("/p/A.sol"))["results"]["detectors"]), 1)

    def test_input_is_not_mutated(self):
        from core.static_only import scoped_to_file

        raw = {"results": {"detectors": [self._detector("/p/lib/B.sol")]}}
        scoped_to_file(raw, Path("/p/A.sol"))
        self.assertEqual(len(raw["results"]["detectors"]), 1)


class PluginMergeTests(unittest.TestCase):
    def test_plugin_results_are_appended_without_mutating_the_input(self):
        from core.static_only import with_plugin_findings

        raw = {"success": True, "results": {"detectors": [{"check": "a"}]}}
        merged = with_plugin_findings(raw, [{"check": "unrestricted-write"}])
        self.assertEqual([d["check"] for d in merged["results"]["detectors"]], ["a", "unrestricted-write"])
        self.assertEqual(len(raw["results"]["detectors"]), 1)

    def test_a_failing_plugin_does_not_block_the_run(self):
        from unittest import mock
        from core.static_only import _plugin_findings

        with mock.patch("tools.slither_plugin_runner.run_unrestricted_write", side_effect=RuntimeError("boom")):
            self.assertEqual(_plugin_findings("x.sol"), [])
