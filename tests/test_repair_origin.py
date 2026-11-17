"""A origem do reparo tem de sair do caminho de código, não de inferência posterior."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))

from core.repair_origin import (  # noqa: E402
    DETERMINISTIC,
    LLM,
    NONE,
    count_by_origin,
    repair_origins,
    stamp_origins,
)
from orchestrator import comparar_resultados  # noqa: E402


class RepairOriginTests(unittest.TestCase):
    def test_the_deterministic_patch_wins_the_tie(self):
        # O patch mecânico roda antes da diagnose da LLM, então um ID coberto pelos dois
        # é dele.
        origins = repair_origins({"VULN_001"}, {"VULN_001"}, {"VULN_001"})
        self.assertEqual(origins, {"VULN_001": DETERMINISTIC})

    def test_what_is_left_over_is_the_llm(self):
        origins = repair_origins({"VULN_001", "VULN_002"}, {"VULN_001"}, {"VULN_002"})
        self.assertEqual(origins, {"VULN_001": DETERMINISTIC, "VULN_002": LLM})

    def test_a_confirmed_id_nobody_tried_is_none(self):
        origins = repair_origins({"VULN_001", "VULN_003"}, {"VULN_001"}, set())
        self.assertEqual(origins["VULN_003"], NONE)

    def test_empty_sets_give_an_empty_map(self):
        self.assertEqual(repair_origins(set(), set(), set()), {})


class CountByOriginTests(unittest.TestCase):
    def test_outcomes_are_split_by_origin(self):
        comparison = {
            "resolvidas": [{"id": "VULN_001"}, {"id": "VULN_002"}],
            "persistentes": [{"id": "VULN_003"}],
            "inconclusivas": [],
        }
        origins = {"VULN_001": DETERMINISTIC, "VULN_002": LLM, "VULN_003": LLM}
        counts = count_by_origin(comparison, origins)
        self.assertEqual(counts[DETERMINISTIC]["resolvidas"], 1)
        self.assertEqual(counts[LLM]["resolvidas"], 1)
        self.assertEqual(counts[LLM]["persistentes"], 1)

    def test_stamping_writes_the_origin_into_each_item(self):
        comparison = {"resolvidas": [{"id": "VULN_001"}], "persistentes": [], "inconclusivas": []}
        stamp_origins(comparison, {"VULN_001": LLM})
        self.assertEqual(comparison["resolvidas"][0]["origem"], LLM)
        self.assertEqual(comparison["por_origem"][LLM]["resolvidas"], 1)

    def test_an_unknown_id_counts_as_no_repair(self):
        comparison = {"resolvidas": [{"id": "VULN_009"}], "persistentes": [], "inconclusivas": []}
        counts = count_by_origin(comparison, {})
        self.assertEqual(counts[NONE]["resolvidas"], 1)


class ComparisonCarriesTheOriginTests(unittest.TestCase):
    CONFIRMED = [
        {"id": "VULN_001", "type": "tx-origin"},
        {"id": "VULN_002", "type": "unrestricted-write"},
    ]
    AFTER = {
        "analises": [
            {"id": "VULN_001", "status": "not_confirmed", "rule": "only_owner-rule_not_vacuous"},
            {"id": "VULN_002", "status": "confirmed", "rule": "write_guarded", "evidencia": "Violated"},
        ]
    }

    def test_each_entry_says_which_path_repaired_it(self):
        comparison = comparar_resultados(
            self.CONFIRMED,
            self.AFTER,
            {"VULN_001": DETERMINISTIC, "VULN_002": LLM},
        )
        self.assertEqual(comparison["resolvidas"][0]["origem"], DETERMINISTIC)
        self.assertEqual(comparison["persistentes"][0]["origem"], LLM)
        self.assertEqual(comparison["por_origem"][DETERMINISTIC]["resolvidas"], 1)
        self.assertEqual(comparison["por_origem"][LLM]["persistentes"], 1)

    def test_without_origins_the_comparison_is_unchanged(self):
        comparison = comparar_resultados(self.CONFIRMED, self.AFTER)
        self.assertNotIn("por_origem", comparison)
        self.assertNotIn("origem", comparison["resolvidas"][0])


if __name__ == "__main__":
    unittest.main()
