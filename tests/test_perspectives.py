"""Tests for perspective selection (CodeXplain adaptation)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.perspectives import (  # noqa: E402
    CLASS_PERSPECTIVES,
    DETECTOR_CLASS,
    GENERAL_PURPOSE,
    PERSPECTIVES,
    build_perspective_guidance,
    classify_detector,
    perspectives_for,
    render_perspectives,
)


class PerspectiveTableTests(unittest.TestCase):
    def test_the_nine_codexplain_perspectives_are_present(self):
        self.assertEqual(len(PERSPECTIVES), 9)

    def test_every_class_maps_to_known_perspectives(self):
        for vuln_class, keys in CLASS_PERSPECTIVES.items():
            for key in keys:
                self.assertIn(key, PERSPECTIVES, f"{vuln_class} references unknown {key}")

    def test_every_detector_maps_to_a_known_class(self):
        for detector, vuln_class in DETECTOR_CLASS.items():
            self.assertIn(vuln_class, CLASS_PERSPECTIVES, f"{detector} -> unknown {vuln_class}")

    def test_table_1_mapping_for_reentrancy(self):
        """CodeXplain Table 1: reentrancy -> state management, logic/flow, basic functionality."""
        self.assertEqual(
            CLASS_PERSPECTIVES["reentrancy"],
            ("state_management", "logic_and_flow", "basic_functionality"),
        )


class ClassifyDetectorTests(unittest.TestCase):
    def test_known_detectors_resolve_exactly(self):
        self.assertEqual(classify_detector("tx-origin"), "unrestricted_write")
        self.assertEqual(classify_detector("missing-zero-check"), "non_validated_arguments")
        self.assertEqual(classify_detector("suicidal"), "suicidal")

    def test_unknown_detector_resolves_by_name_shape(self):
        self.assertEqual(classify_detector("reentrancy-unknown-variant"), "reentrancy")
        self.assertEqual(classify_detector("some-overflow-thing"), "integer_overflow")
        self.assertEqual(classify_detector("unprotected-owner-setter"), "unrestricted_write")

    def test_reentrancy_events_is_reentrancy_not_missing_events(self):
        """"reentrancy-events" contains "event"; ordering must keep it a reentrancy."""
        self.assertEqual(classify_detector("reentrancy-events"), "reentrancy")

    def test_events_access_is_missing_events_not_access_control(self):
        """"events-access" is a missing event on a privileged action."""
        self.assertEqual(classify_detector("events-access"), "missing_events")

    def test_case_and_whitespace_are_normalized(self):
        self.assertEqual(classify_detector("  TX-ORIGIN "), "unrestricted_write")

    def test_unrecognized_detector_returns_empty(self):
        self.assertEqual(classify_detector("naming-convention"), "")
        self.assertEqual(classify_detector(""), "")


class PerspectiveSelectionTests(unittest.TestCase):
    def test_known_detector_uses_its_class_perspectives(self):
        keys = perspectives_for({"type": "reentrancy-eth"})
        self.assertEqual(keys, list(CLASS_PERSPECTIVES["reentrancy"]))

    def test_uncatalogued_detector_falls_back_to_category(self):
        keys = perspectives_for({"type": "naming-convention"}, category="security")
        self.assertEqual(keys, ["ownership_access_control", "state_management", "logic_and_flow"])

    def test_unknown_detector_and_category_uses_general_purpose(self):
        self.assertEqual(perspectives_for({"type": "naming-convention"}), list(GENERAL_PURPOSE))

    def test_selection_is_never_empty(self):
        for finding in ({}, {"type": ""}, {"type": "totally-unknown"}):
            self.assertTrue(perspectives_for(finding))


class RenderingTests(unittest.TestCase):
    def test_render_numbers_and_deduplicates(self):
        text = render_perspectives(["state_management", "state_management", "logic_and_flow"])
        self.assertIn("1. State Management Analysis:", text)
        self.assertIn("2. Logic and Flow Interpretation:", text)
        self.assertEqual(text.count("State Management Analysis"), 1)

    def test_unknown_keys_are_skipped(self):
        self.assertEqual(render_perspectives(["nope"]), "")

    def test_guidance_names_finding_detector_and_class(self):
        text = build_perspective_guidance([{"id": "VULN_001", "type": "reentrancy-eth"}])
        self.assertIn("ANALYSIS_PERSPECTIVES", text)
        self.assertIn("VULN_001 (reentrancy-eth -> reentrancy):", text)
        self.assertIn("State Management Analysis", text)

    def test_uncategorized_is_labelled_as_such(self):
        text = build_perspective_guidance([{"id": "V1", "type": "naming-convention"}])
        self.assertIn("-> uncategorized", text)

    def test_empty_findings_yield_empty_string(self):
        self.assertEqual(build_perspective_guidance([]), "")

    def test_categories_are_applied_per_finding_id(self):
        text = build_perspective_guidance(
            [{"id": "V1", "type": "unknown-detector"}], categories={"V1": "validation"}
        )
        self.assertIn("Step-by-Step Analysis", text)

    def test_multiple_findings_each_get_a_block(self):
        text = build_perspective_guidance(
            [{"id": "V1", "type": "tx-origin"}, {"id": "V2", "type": "timestamp"}]
        )
        self.assertIn("V1 (tx-origin", text)
        self.assertIn("V2 (timestamp", text)


class RealDetectorCoverageTests(unittest.TestCase):
    """Detectors observed on real contracts (inverse project, 108 findings)."""

    SECURITY = [
        "missing-zero-check", "timestamp", "reentrancy-events", "unchecked-transfer",
        "events-maths", "reentrancy-benign", "divide-before-multiply", "reentrancy-no-eth",
        "events-access", "incorrect-equality", "boolean-equal",
        "unprotected-critical-update", "tx-origin",
    ]
    INFORMATIONAL = ["naming-convention", "solc-version", "too-many-digits", "assembly"]

    def test_every_real_security_detector_gets_a_specific_class(self):
        unclassified = [d for d in self.SECURITY if not classify_detector(d)]
        self.assertEqual(unclassified, [])

    def test_informational_detectors_fall_back_rather_than_misclassify(self):
        for detector in self.INFORMATIONAL:
            self.assertEqual(classify_detector(detector), "")
            self.assertEqual(perspectives_for({"type": detector}), list(GENERAL_PURPOSE))


if __name__ == "__main__":
    unittest.main()
