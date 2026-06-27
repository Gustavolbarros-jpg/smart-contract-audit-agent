import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent"
sys.path.insert(0, str(AGENT))

from core.certora_error_catalog import analyze_certora_errors, has_certora_blocking_error
from core.contract_context import build_methods_block, extract_primary_contract_name
from core.contract_registry import (
    BENCHMARK,
    EXPLORATORY,
    MANUAL,
    SCRATCH,
    contract_entries,
    contract_names,
    default_benchmark_contracts,
)
from core.diagnosis_context import (
    compact_certora_log,
    compact_confirmed_analyses,
    compact_plan_for_diagnosis,
    deterministic_diagnosis,
)
from core.deterministic_patch import apply_deterministic_patches
from core.deterministic_spec import build_deterministic_spec
from core.evaluation import summarize_run
from core.formal_candidate import build_formal_candidates
from core.formal_plan import sanitize_formal_plan
from core.import_context import has_imports, packages_path, solc_remappings
from core.patch_guard import (
    analyze_patch,
    compact_patch_guard_report,
    repair_obvious_patch_guard_issues,
)
from core.slither_normalizer import normalize_slither_json
from core.static_analysis import (
    analyze_static_after_fix,
    static_confirmed_analyses,
    static_confirmed_findings,
)
from core.spec_patterns import build_spec_pattern_context
from core.toolchain import extract_solidity_constraint, version_satisfies_constraint
from core.vulnerability_catalog import get_catalog_entry
from tools.spec_validator import (
    aplicar_auth_probe_rules,
    aplicar_target_binding_rules,
    corrigir_spec,
    deduplicar_spec,
    envolver_blocos_vuln_sem_rule,
    inserir_requires_zero_address,
    quebrar_instrucoes_multiplas,
    remover_prefixo_revert_duplicado,
    remover_rules_vazias,
    remover_wrapper_rules,
    substituir_hex_vazio_em_calls,
    substituir_methods_block,
    validar_spec,
)


METHODS = """methods {
  function owner() external returns(address) envfree;
  function balances(address) external returns(uint256) envfree;
  function claimReward() external;
  function withdraw(uint256 amount) external;
  function pause() external;
  function destroy() external;
  function transferOwnership(address newOwner) external;
}"""


def repair_spec(
    spec: str,
    rule_names: dict[str, str],
    rule_context: dict[str, dict] | None = None,
) -> str:
    spec, _ = substituir_methods_block(spec, METHODS)
    spec, _ = remover_rules_vazias(spec)
    spec, _ = remover_wrapper_rules(spec)
    spec, _ = envolver_blocos_vuln_sem_rule(spec, rule_names)
    spec, _ = quebrar_instrucoes_multiplas(spec)
    spec, _ = deduplicar_spec(spec)
    spec, _ = corrigir_spec(spec)
    spec, _ = inserir_requires_zero_address(spec)
    spec, _ = remover_prefixo_revert_duplicado(spec)
    spec, _ = aplicar_auth_probe_rules(spec, {"name": "pause", "params": []})
    spec, _ = aplicar_target_binding_rules(spec, rule_context or {}, METHODS)
    return spec


def normalize_contract_source(source: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
        handle.write(source)
        path = handle.name

    try:
        return normalize_slither_json({"results": {"detectors": []}}, path)
    finally:
        Path(path).unlink(missing_ok=True)


class CertoraLearningTests(unittest.TestCase):
    def test_catalog_classifies_redeclaration_error(self):
        log = "Error in spec file: Redeclaring variables is not supported; `e` was previously declared"
        analysis = analyze_certora_errors(log)
        ids = {item["id"] for item in analysis["matches"]}
        self.assertTrue(analysis["has_blocking_errors"])
        self.assertIn("cvl_duplicate_declaration", ids)

    def test_successful_certora_result_is_not_blocking(self):
        log = "Results for all:\nResult for rule_a: rule_a: SUCCESS"
        self.assertFalse(has_certora_blocking_error(log))

    def test_repairs_loose_vuln_statements_and_rules_wrapper(self):
        bad = """methods {
  function claimReward(env e) external {
    emit Bad();
  }
}

rules {
// VULN_001 - reentrancy
env e; mathint before = balances(e.msg.sender);
claimReward@withrevert(e);
assert lastReverted;
env e; mathint before = balances(e.msg.sender);
claimReward(e);
mathint after = balances(e.msg.sender);
assert after < before;

// VULN_006 - missing-zero-check
env e; address x = 0;
transferOwnership@withrevert(e, x);
assert lastReverted;
}
"""
        fixed = repair_spec(
            bad,
            {
                "VULN_001": "reentrancy_claimReward",
                "VULN_006": "zero_address_transferOwnership",
            },
        )
        ok, errors = validar_spec(fixed)
        self.assertTrue(ok, errors)
        self.assertIn("rule reentrancy_claimReward", fixed)
        self.assertIn("rule zero_address_transferOwnership", fixed)
        self.assertIn("require x == 0;", fixed)
        self.assertEqual(fixed.count("env e;"), 2)
        self.assertNotIn("rules {", fixed)

    def test_rewrites_auth_rule_to_owner_only_probe(self):
        bad = """methods {
  function owner() external returns(address) envfree;
  function claimReward() external;
  function pause() external;
}

// VULN_017 - tx-origin
rule auth_reverts_when_msg_sender_not_owner {
  env e;
  require e.msg.sender != owner();
  claimReward@withrevert(e);
  assert lastReverted;
}
"""
        fixed, corrections = aplicar_auth_probe_rules(bad, {"name": "pause", "params": []})
        ok, errors = validar_spec(fixed)
        self.assertTrue(ok, errors)
        self.assertTrue(corrections)
        self.assertIn("pause@withrevert(e);", fixed)
        self.assertNotIn("claimReward@withrevert(e);", fixed)

    def test_auth_repair_does_not_rewrite_unauthorized_recipient_rule(self):
        bad = """methods {
  function owner() external returns(address) envfree;
  function claimPrize(address to) external;
  function pause() external;
}

// VULN_009 - arbitrary-send-eth
rule unauthorized_recipient_reverts {
  env e;
  require e.msg.sender != owner();
  address to;
  claimPrize@withrevert(e, to);
  assert lastReverted;
}
"""
        fixed, corrections = aplicar_auth_probe_rules(bad, {"name": "pause", "params": []})
        self.assertFalse(corrections)
        self.assertIn("rule unauthorized_recipient_reverts", fixed)
        self.assertIn("claimPrize@withrevert(e, to);", fixed)
        self.assertNotIn("pause@withrevert(e);", fixed)

    def test_target_binding_rewrites_swapped_rule_calls(self):
        bad = """methods {
  function claimReward() external;
  function withdraw(uint256 amount) external;
  function pause() external;
  function destroy() external;
}

// VULN_001 - reentrancy
rule reentrancy_claimReward {
  env e;
  withdraw(e, 1);
  assert true;
}

// VULN_002 - reentrancy
rule reentrancy_withdraw {
  env e;
  claimReward(e);
  assert true;
}

// VULN_018 - suicidal
rule selfdestruct_auth {
  env e;
  pause@withrevert(e);
  assert lastReverted;
}
"""
        fixed, corrections = aplicar_target_binding_rules(
            bad,
            {
                "VULN_001": {
                    "type": "reentrancy-eth",
                    "function": "claimReward",
                    "rule_names": ["reentrancy_claimReward"],
                },
                "VULN_002": {
                    "type": "reentrancy-eth",
                    "function": "withdraw",
                    "rule_names": ["reentrancy_withdraw"],
                },
                "VULN_018": {
                    "type": "suicidal",
                    "function": "destroy",
                    "rule_names": ["selfdestruct_auth"],
                },
            },
            METHODS,
        )
        self.assertEqual(len(corrections), 3)
        self.assertIn("claimReward(e);", fixed)
        self.assertNotIn("withdraw(e, 1);", fixed)
        self.assertIn("uint256 amount;", fixed)
        self.assertIn("withdraw(e, amount);", fixed)
        self.assertIn("destroy@withrevert(e);", fixed)
        self.assertNotIn("pause@withrevert(e);", fixed)

    def test_pattern_context_is_general_and_relevant(self):
        context = build_spec_pattern_context(
            [
                {"type": "missing-zero-check"},
                {"type": "tx-origin"},
            ]
        )
        self.assertIn("missing-zero-check", context)
        self.assertIn("tx-origin", context)
        self.assertIn("Valid shape:", context)
        self.assertNotIn("DeFiVault", context)
        self.assertNotIn("timestamp_property_example", context)

    def test_diagnosis_context_compacts_large_plans(self):
        plan = {
            "selected_rules": [
                {
                    "id": "VULN_001",
                    "type": "missing-zero-check",
                    "function": "transferOwnership(address)",
                    "line": "10",
                    "rule_names": ["zero_address_reverts"],
                    "formal_property": "zero address must revert",
                    "cvl_strategy": "require_nonzero_address",
                    "repair_strategy": "require_nonzero_address",
                    "target_parameter": "newOwner",
                    "evidence": {"large": "x" * 1000},
                    "assumptions": ["irrelevant long field"],
                }
            ],
            "global_assumptions": ["large assumption"],
        }
        analyses = [
            {
                "id": "VULN_001",
                "type": "missing-zero-check",
                "function": "transferOwnership(address)",
                "rule": "zero_address_reverts",
                "status": "confirmed_static",
                "evidencia": "Result for zero_address_reverts: FAIL " + ("x" * 400),
            }
        ]

        compact_plan = compact_plan_for_diagnosis(plan)
        compact_analyses = compact_confirmed_analyses(analyses)

        self.assertEqual(compact_plan["selected_rules"][0]["id"], "VULN_001")
        self.assertNotIn("evidence", compact_plan["selected_rules"][0])
        self.assertNotIn("global_assumptions", compact_plan)
        self.assertLess(len(compact_analyses[0]["evidence"]), len(analyses[0]["evidencia"]))

    def test_compact_certora_log_drops_unselected_success_noise(self):
        log = """Result for envfreeFuncsStaticCheck: envfreeFuncsStaticCheck: owner(): SUCCESS
projection(): SUCCESS
Verified: harmless_rule
Violated: zero_address_reverts
Result for zero_address_reverts: zero_address_reverts: FAIL: lastReverted
"""
        compact = compact_certora_log(log, ["zero_address_reverts"])

        self.assertIn("zero_address_reverts", compact)
        self.assertNotIn("envfreeFuncsStaticCheck", compact)
        self.assertNotIn("projection(): SUCCESS", compact)
        self.assertNotIn("Verified: harmless_rule", compact)

    def test_deterministic_diagnosis_covers_known_repair_classes(self):
        confirmed = [
            {
                "id": "VULN_001",
                "type": "missing-zero-check",
                "function": "transferOwnership(address)",
                "rule": "zero_address_reverts",
                "status": "confirmed",
            },
            {
                "id": "VULN_002",
                "type": "tx-origin",
                "function": "modifier/function",
                "rule": "auth_reverts_when_msg_sender_not_owner",
                "status": "confirmed",
            },
            {
                "id": "VULN_003",
                "type": "unchecked-lowlevel",
                "function": "notifyPartner",
                "rule": "slither:unchecked-lowlevel",
                "status": "confirmed_static",
            },
        ]
        selected = [
            {
                "id": "VULN_001",
                "type": "missing-zero-check",
                "line": "42-43",
                "description": "newOwner lacks zero check",
                "target_parameter": "newOwner",
            },
            {
                "id": "VULN_002",
                "type": "tx-origin",
                "description": "tx.origin in onlyOwner",
            },
            {
                "id": "VULN_003",
                "type": "unchecked-lowlevel",
                "description": "target.call(payload) return ignored",
            },
        ]
        plan = {
            "selected_rules": [
                {"id": "VULN_001", "target_parameter": "newOwner"},
                {"id": "VULN_002"},
            ]
        }

        diagnosis = deterministic_diagnosis(confirmed, selected, plan)
        by_id = {item["id"]: item for item in diagnosis["falhas"]}

        self.assertEqual(set(by_id), {"VULN_001", "VULN_002", "VULN_003"})
        self.assertEqual(by_id["VULN_001"]["linha"], 42)
        self.assertIn("newOwner != address(0)", by_id["VULN_001"]["correcao_necessaria"])
        self.assertIn("msg.sender", by_id["VULN_002"]["correcao_necessaria"])
        self.assertIn("success boolean", by_id["VULN_003"]["correcao_necessaria"])

    def test_formal_plan_forces_clear_auth_findings(self):
        plan = {
            "selected_rules": [],
            "skipped_findings": [
                {"id": "VULN_011", "reason": "LLM was unsure about target function"}
            ],
        }
        candidates = [
            {
                "id": "VULN_011",
                "type": "tx-origin",
                "function": "modifier/function",
                "line": "",
                "property": "authorization must depend on msg.sender, not tx.origin",
                "rule_template": "auth_reverts_when_msg_sender_not_owner",
                "repair_strategy": "replace_tx_origin_with_msg_sender",
                "target_parameter": "",
                "evidence": {},
            }
        ]
        sanitized = sanitize_formal_plan(plan, candidates)
        selected_ids = {item["id"] for item in sanitized["selected_rules"]}
        skipped_ids = {item["id"] for item in sanitized["skipped_findings"]}
        self.assertIn("VULN_011", selected_ids)
        self.assertNotIn("VULN_011", skipped_ids)

    def test_constructor_findings_are_not_formal_candidates(self):
        candidates = build_formal_candidates(
            {
                "vulnerabilidades": [
                    {
                        "id": "VULN_001",
                        "type": "missing-zero-check",
                        "function": "constructor(address)",
                        "formalizable": True,
                    },
                    {
                        "id": "VULN_002",
                        "type": "missing-zero-check",
                        "function": "forceKing(address)",
                        "formalizable": True,
                    },
                ]
            }
        )
        self.assertEqual([item["id"] for item in candidates], ["VULN_002"])

    def test_reentrancy_is_static_review_for_now(self):
        entry = get_catalog_entry("reentrancy-eth")
        self.assertFalse(entry["formalizable"])
        self.assertEqual(entry["repair_strategy"], "static_review")

    def test_timestamp_is_static_review_for_now(self):
        entry = get_catalog_entry("timestamp")
        self.assertFalse(entry["formalizable"])
        self.assertEqual(entry["repair_strategy"], "static_review")

    def test_unchecked_lowlevel_is_static_confirmed(self):
        entry = get_catalog_entry("unchecked-lowlevel")
        self.assertFalse(entry["formalizable"])
        self.assertTrue(entry["static_confirmed"])
        self.assertEqual(entry["repair_strategy"], "require_low_level_call_success")

    def test_erc2771_multicall_context_is_static_confirmed(self):
        entry = get_catalog_entry("erc2771-multicall-context")
        self.assertFalse(entry["formalizable"])
        self.assertTrue(entry["static_confirmed"])
        self.assertEqual(entry["repair_strategy"], "block_forwarded_delegatecall_multicall")

    def test_unprotected_critical_update_is_static_review_for_now(self):
        entry = get_catalog_entry("unprotected-critical-update")
        self.assertFalse(entry["formalizable"])
        self.assertFalse(entry.get("static_confirmed", False))
        self.assertEqual(entry["repair_strategy"], "static_review")

    def test_static_unchecked_lowlevel_resolution_uses_slither_rerun(self):
        original = {
            "vulnerabilidades": [
                {
                    "id": "VULN_001",
                    "type": "unchecked-lowlevel",
                    "function": "refund",
                    "description": "ignored return value",
                }
            ]
        }
        fixed_clean = {"vulnerabilidades": []}
        findings = static_confirmed_findings(original)
        self.assertEqual(len(findings), 1)
        self.assertEqual(static_confirmed_analyses(findings)[0]["status"], "confirmed_static")
        fixed_analysis = analyze_static_after_fix(findings, fixed_clean)
        self.assertEqual(fixed_analysis[0]["status"], "not_confirmed")

        fixed_dirty = {
            "vulnerabilidades": [
                {
                    "id": "VULN_999",
                    "type": "unchecked-lowlevel",
                    "function": "refund",
                }
            ]
        }
        dirty_analysis = analyze_static_after_fix(findings, fixed_dirty)
        self.assertEqual(dirty_analysis[0]["status"], "confirmed")

    def test_low_level_calls_with_require_success_stays_non_actionable(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  function refund(address payable to) external {
    (bool ok, ) = to.call{value: 1}("");
    require(ok, "call failed");
  }
}
"""
        slither = {
            "results": {
                "detectors": [
                    {
                        "check": "low-level-calls",
                        "impact": "Informational",
                        "confidence": "High",
                        "description": "Low level call in T.refund(address):\n\t- (ok,None) = to.call{value: 1}()",
                        "elements": [
                            {
                                "type": "function",
                                "name": "refund",
                                "source_mapping": {"lines": [5, 6, 7]},
                            },
                            {
                                "type": "node",
                                "name": "(ok,None) = to.call{value: 1}()",
                                "source_mapping": {"lines": [6]},
                            },
                        ],
                    }
                ]
            }
        }
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
            path = handle.name

        try:
            report = normalize_slither_json(slither, path)
        finally:
            Path(path).unlink(missing_ok=True)

        self.assertEqual(len(report["vulnerabilidades"]), 1)
        finding = report["vulnerabilidades"][0]
        self.assertEqual(finding["type"], "low-level-calls")
        self.assertTrue(finding["low_level_call_context"]["checked_return"])
        self.assertEqual(static_confirmed_findings(report), [])

    def test_low_level_calls_with_if_not_success_stays_non_actionable(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  event Failed();

  function refund(address payable to) external {
    (bool ok, ) = to.call{value: 1}("");
    if (!ok) {
      emit Failed();
      return;
    }
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unchecked-lowlevel"
        ]
        self.assertEqual(findings, [])

    def test_low_level_success_returned_to_caller_stays_non_actionable(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  function transferOrFallback(address payable to) external {
    if (!_safeTransferETH(to, 1)) {
      return;
    }
  }

  function _safeTransferETH(address payable to, uint256 value) internal returns (bool) {
    (bool success, ) = to.call{value: value}("");
    return success;
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unchecked-lowlevel"
        ]
        self.assertEqual(findings, [])

    def test_internal_selfdestruct_does_not_create_fake_destroy_finding(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  function cancel() external {
    _end();
  }

  function _end() internal {
    selfdestruct(payable(msg.sender));
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "suicidal"
        ]
        self.assertEqual(findings, [])

    def test_guarded_selfdestruct_does_not_create_suicidal_fallback(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;

  modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
  }

  function destroy() external onlyOwner {
    selfdestruct(payable(owner));
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "suicidal"
        ]
        self.assertEqual(findings, [])

    def test_deterministic_patch_inserts_missing_zero_checks(self):
        source = """pragma solidity ^0.8.21;
contract T {
  address public vault;

  function setVaultAddress(address newVault) public {
    vault = newVault;
  }
}
"""
        fixed, patches = apply_deterministic_patches(
            source,
            [
                {
                    "id": "VULN_001",
                    "type": "missing-zero-check",
                    "function": "setVaultAddress(address)",
                    "target_parameter": "newVault",
                }
            ],
        )

        self.assertIn('require(newVault != address(0), "Zero address"); // FIX VULN_001', fixed)
        self.assertIn("vault = newVault;", fixed)
        self.assertEqual([item["id"] for item in patches], ["VULN_001"])

    def test_deterministic_patch_can_infer_zero_check_parameter_from_elements(self):
        source = """pragma solidity ^0.8.21;
contract T {
  address public weth;

  function setWethAddress(address _newWethAddress) public {
    weth = _newWethAddress;
  }
}
"""
        fixed, patches = apply_deterministic_patches(
            source,
            [
                {
                    "id": "VULN_002",
                    "type": "missing-zero-check",
                    "function": "setWethAddress(address)",
                    "elements": [
                        {"name": "_newWethAddress", "type": "variable", "line": "5"},
                    ],
                }
            ],
        )

        self.assertIn('require(_newWethAddress != address(0), "Zero address"); // FIX VULN_002', fixed)
        self.assertEqual([item["target_parameter"] for item in patches], ["_newWethAddress"])

    def test_deterministic_patch_expands_one_line_functions(self):
        source = """pragma solidity ^0.8.21;
contract T {
  address public gov;
  function setGov(address _gov) public onlyGov { gov = _gov; }
}
"""
        fixed, patches = apply_deterministic_patches(
            source,
            [
                {
                    "id": "VULN_003",
                    "type": "missing-zero-check",
                    "function": "setGov(address)",
                    "target_parameter": "_gov",
                }
            ],
        )

        self.assertIn("function setGov(address _gov) public onlyGov {\n", fixed)
        self.assertIn('    require(_gov != address(0), "Zero address"); // FIX VULN_003', fixed)
        self.assertIn("    gov = _gov;\n", fixed)
        self.assertEqual([item["id"] for item in patches], ["VULN_003"])

    def test_ignored_low_level_call_fallback_is_static_confirmed(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  function refund(address payable to) external {
    to.call{value: 1}("");
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unchecked-lowlevel"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["function"], "refund(address)")
        self.assertFalse(findings[0]["low_level_call_context"]["checked_return"])
        self.assertEqual(static_confirmed_findings(report)[0]["type"], "unchecked-lowlevel")

    def test_captured_low_level_success_never_checked_is_static_confirmed(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  function refund(address payable to) external {
    (bool ok, ) = to.call{value: 1}("");
    ok;
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unchecked-lowlevel"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["low_level_call_context"]["success_variable"], "ok")

    def test_unprotected_critical_update_detects_external_unlock_update(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;
  uint256 public unlockTime;

  constructor(uint256 initialUnlockTime) {
    owner = msg.sender;
    unlockTime = initialUnlockTime;
  }

  function extendLock(uint256 newUnlockTime) external {
    unlockTime = newUnlockTime;
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["function"], "extendLock(uint256)")
        self.assertEqual(findings[0]["target_parameter"], "unlockTime")
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_accepts_require_owner_guard(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;
  uint256 public unlockTime;

  function extendLock(uint256 newUnlockTime) external {
    require(msg.sender == owner, "not owner");
    unlockTime = newUnlockTime;
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]
        self.assertEqual(findings, [])

    def test_unprotected_critical_update_accepts_only_owner_modifier(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;
  uint256 public feeBps;

  modifier onlyOwner() {
    require(msg.sender == owner, "not owner");
    _;
  }

  function setFee(uint256 newFeeBps) external onlyOwner {
    feeBps = newFeeBps;
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]
        self.assertEqual(findings, [])

    def test_unprotected_critical_update_is_not_actionable_until_promoted(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;
  uint256 public unlockTime;

  function extendLock(uint256 newUnlockTime) external {
    unlockTime = newUnlockTime;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(len(review_findings), 1)
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_ignores_fee_paid_accumulator(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  uint256 public feePaid;

  function payFee() external payable {
    feePaid += msg.value;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(review_findings, [])
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_ignores_total_fees_collected_accumulator(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  uint256 public totalFeesCollected;

  function collectFee(uint256 fee) external {
    totalFeesCollected += fee;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(review_findings, [])
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_detects_protocol_fee_setter_for_review(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  uint256 public protocolFeeBps;

  function setProtocolFee(uint256 newFee) external {
    protocolFeeBps = newFee;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(len(review_findings), 1)
        self.assertEqual(review_findings[0]["function"], "setProtocolFee(uint256)")
        self.assertEqual(review_findings[0]["target_parameter"], "protocolFeeBps")
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_ignores_non_admin_like_fee_write(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  uint256 public protocolFeeBps;

  function quote(uint256 newFee) external {
    protocolFeeBps = newFee;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(review_findings, [])
        self.assertEqual(static_confirmed_findings(report), [])

    def test_unprotected_critical_update_ignores_user_scoped_delay_mapping(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  mapping(address => uint256) public userDelay;

  function setMyDelay(uint256 delay) external {
    userDelay[msg.sender] = delay;
  }
}
"""
        report = normalize_contract_source(source)
        review_findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "unprotected-critical-update"
        ]

        self.assertEqual(review_findings, [])
        self.assertEqual(static_confirmed_findings(report), [])

    def test_formal_and_static_fix_analyses_do_not_need_duplicate_ids(self):
        certora_confirmed = [
            {"id": "VULN_010", "rule": "auth_reverts_when_msg_sender_not_owner"},
            {"id": "VULN_001", "rule": "slither:unchecked-lowlevel"},
        ]
        formal_only = [
            vuln for vuln in certora_confirmed
            if not vuln["rule"].startswith("slither:")
        ]
        self.assertEqual([item["id"] for item in formal_only], ["VULN_010"])

    def test_arbitrary_send_fallback_requires_parameter_recipient(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public owner;

  function withdraw() external {
    payable(owner).transfer(address(this).balance);
  }

  function sweep(address payable to) external {
    to.transfer(address(this).balance);
  }
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
            path = handle.name

        try:
            report = normalize_slither_json({"results": {"detectors": []}}, path)
        finally:
            Path(path).unlink(missing_ok=True)

        arbitrary = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "arbitrary-send-eth"
        ]
        self.assertEqual(len(arbitrary), 1)
        self.assertEqual(arbitrary[0]["function"], "sweep(address)")
        self.assertEqual(arbitrary[0]["target_parameter"], "to")

    def test_arbitrary_send_fallback_ignores_erc20_transfer_parameter(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
  function transfer(address to, uint256 amount) external returns (bool);
}

contract T {
  function forwardERC20s(IERC20 token, uint256 amount) external {
    token.transfer(msg.sender, amount);
  }
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
            path = handle.name

        try:
            report = normalize_slither_json({"results": {"detectors": []}}, path)
        finally:
            Path(path).unlink(missing_ok=True)

        arbitrary = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "arbitrary-send-eth"
        ]
        self.assertEqual(arbitrary, [])

    def test_erc2771_multicall_fallback_detects_unguarded_delegatecall(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;

  function _msgSender() internal view returns (address sender) {
    if (msg.sender == trustedForwarder) {
      assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
    } else {
      return msg.sender;
    }
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
            path = handle.name

        try:
            report = normalize_slither_json({"results": {"detectors": []}}, path)
        finally:
            Path(path).unlink(missing_ok=True)

        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["function"], "multicall(bytes[])")
        self.assertEqual(static_confirmed_findings(report)[0]["type"], "erc2771-multicall-context")

    def test_erc2771_multicall_fallback_accepts_forwarder_guard(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;

  function _msgSender() internal view returns (address sender) {
    if (msg.sender == trustedForwarder) {
      assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
    } else {
      return msg.sender;
    }
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    require(msg.sender != trustedForwarder, "forwarded multicall disabled");
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as handle:
            handle.write(source)
            path = handle.name

        try:
            report = normalize_slither_json({"results": {"detectors": []}}, path)
        finally:
            Path(path).unlink(missing_ok=True)

        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(findings, [])

    def test_erc2771_multicall_detects_is_trusted_forwarder_variant(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address private immutable _forwarder;

  constructor(address forwarder_) {
    _forwarder = forwarder_;
  }

  function isTrustedForwarder(address forwarder) public view returns (bool) {
    return forwarder == _forwarder;
  }

  function _msgSender() internal view returns (address sender) {
    if (isTrustedForwarder(msg.sender)) {
      assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
    } else {
      return msg.sender;
    }
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["elements"][0]["name"], "_forwarder")

    def test_erc2771_multicall_accepts_is_trusted_forwarder_guard(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address private immutable _forwarder;

  function isTrustedForwarder(address forwarder) public view returns (bool) {
    return forwarder == _forwarder;
  }

  function _msgSender() internal view returns (address sender) {
    if (isTrustedForwarder(msg.sender)) {
      assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
    } else {
      return msg.sender;
    }
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    require(!isTrustedForwarder(msg.sender), "forwarded multicall disabled");
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(findings, [])

    def test_erc2771_multicall_accepts_different_forwarder_variable_guard(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address private immutable _forwarder;

  function _msgSender() internal view returns (address sender) {
    if (msg.sender == _forwarder) {
      assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
    } else {
      return msg.sender;
    }
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    require(msg.sender != _forwarder, "forwarded multicall disabled");
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(findings, [])

    def test_erc2771_multicall_detects_openzeppelin_context_inheritance(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/metatx/ERC2771Context.sol";

contract T is ERC2771Context {
  constructor(address forwarder) ERC2771Context(forwarder) {}

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "multicall failed");
      results[i] = result;
    }
  }
}
"""
        report = normalize_contract_source(source)
        findings = [
            item for item in report["vulnerabilidades"]
            if item["type"] == "erc2771-multicall-context"
        ]
        self.assertEqual(len(findings), 1)

    def test_patch_guard_allows_minimal_erc2771_multicall_guard(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;
  mapping(address => uint256) public balances;

  function transfer(address to, uint256 amount) public {
    require(balances[msg.sender] >= amount, "Saldo insuficiente");
    balances[to] += amount;
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "Multicall falhou");
      results[i] = result;
    }
  }
}
"""
        fixed = original.replace(
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n",
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n"
            "    require(msg.sender != trustedForwarder, \"forwarded multicall disabled\"); // FIX VULN_001\n",
        )
        result = analyze_patch(
            original,
            fixed,
            [
                {
                    "id": "VULN_001",
                    "type": "erc2771-multicall-context",
                    "function": "multicall(bytes[])",
                    "line": "12",
                }
            ],
            {"falhas": [{"id": "VULN_001", "linha": 12}]},
        )
        self.assertEqual(result["status"], "ok", result["issues"])
        self.assertFalse(result["should_block"])

    def test_patch_guard_blocks_unrelated_revert_string_change(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;
  mapping(address => uint256) public balances;

  function transfer(address to, uint256 amount) public {
    require(balances[msg.sender] >= amount, "Saldo insuficiente");
    balances[to] += amount;
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "Multicall falhou");
      results[i] = result;
    }
  }
}
"""
        fixed = original.replace(
            "Saldo insuficiente",
            "Insufficient balance",
        ).replace(
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n",
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n"
            "    require(msg.sender != trustedForwarder, \"forwarded multicall disabled\"); // FIX VULN_001\n",
        )
        result = analyze_patch(
            original,
            fixed,
            [{"id": "VULN_001", "function": "multicall(bytes[])", "line": "12"}],
            {"falhas": [{"id": "VULN_001", "linha": 12}]},
        )
        issue_types = {issue["type"] for issue in result["issues"]}
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["should_block"])
        self.assertIn("modified_string_literal", issue_types)

    def test_patch_guard_compact_report_keeps_blocking_context(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;

  function transfer(address to, uint256 amount) public {
    require(amount > 0, "Valor invalido");
    to;
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    data;
  }
}
"""
        fixed = original.replace(
            '"Valor invalido"',
            '"Invalid value"',
        ).replace(
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n",
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n"
            "    require(msg.sender != trustedForwarder, \"forwarded multicall disabled\"); // FIX VULN_001\n",
        )
        result = analyze_patch(
            original,
            fixed,
            [{"id": "VULN_001", "function": "multicall(bytes[])", "line": "11"}],
            {"falhas": [{"id": "VULN_001", "linha": 11}]},
        )
        compact = compact_patch_guard_report(result)

        self.assertEqual(compact["status"], "blocked")
        self.assertEqual(compact["blocking_issues"][0]["type"], "modified_string_literal")
        self.assertEqual(compact["blocking_issues"][0]["evidence"]["original"], "Valor invalido")
        self.assertTrue(compact["relevant_hunks"])

    def test_patch_guard_autorepair_restores_modified_original_strings(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;

  function transfer(address to, uint256 amount) public {
    require(amount > 0, "Valor invalido");
    to;
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
      (bool success, bytes memory result) = address(this).delegatecall(data[i]);
      require(success, "Multicall falhou");
      results[i] = result;
    }
  }
}
"""
        fixed = original.replace(
            '"Valor invalido"',
            '"Invalid value"',
        ).replace(
            '"Multicall falhou"',
            '"Multicall failed"',
        ).replace(
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n",
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n"
            "    require(msg.sender != trustedForwarder, \"forwarded multicall disabled\"); // FIX VULN_001\n",
        )
        finding = [{"id": "VULN_001", "function": "multicall(bytes[])", "line": "11"}]
        diagnosis = {"falhas": [{"id": "VULN_001", "linha": 11}]}
        result = analyze_patch(original, fixed, finding, diagnosis)
        repaired, corrections = repair_obvious_patch_guard_issues(original, fixed, result)
        repaired_result = analyze_patch(original, repaired, finding, diagnosis)

        self.assertEqual(len(corrections), 2)
        self.assertIn('"Valor invalido"', repaired)
        self.assertIn('"Multicall falhou"', repaired)
        self.assertIn('"forwarded multicall disabled"', repaired)
        self.assertFalse(repaired_result["should_block"], repaired_result["issues"])

    def test_patch_guard_blocks_public_signature_change(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  address public trustedForwarder;

  function transfer(address to, uint256 amount) public {
    to;
    amount;
  }

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    data;
  }
}
"""
        fixed = original.replace(
            "function transfer(address to, uint256 amount) public",
            "function transfer(address to, uint256 amount, bool force) public",
        )
        result = analyze_patch(
            original,
            fixed,
            [{"id": "VULN_001", "function": "multicall(bytes[])", "line": "11"}],
            {"falhas": [{"id": "VULN_001", "linha": 11}]},
        )
        issue_types = {issue["type"] for issue in result["issues"]}
        self.assertEqual(result["status"], "blocked")
        self.assertIn("public_external_signature_changed", issue_types)

    def test_patch_guard_warns_on_comment_change_outside_target(self):
        original = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract T {
  // keep accounting compatible
  address public trustedForwarder;

  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    data;
  }
}
"""
        fixed = original.replace(
            "// keep accounting compatible",
            "// changed broad accounting note",
        ).replace(
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n",
            "  function multicall(bytes[] calldata data) external returns (bytes[] memory results) {\n"
            "    require(msg.sender != trustedForwarder, \"forwarded multicall disabled\"); // FIX VULN_001\n",
        )
        result = analyze_patch(
            original,
            fixed,
            [{"id": "VULN_001", "function": "multicall(bytes[])", "line": "8"}],
            {"falhas": [{"id": "VULN_001", "linha": 8}]},
        )
        issue_types = {issue["type"] for issue in result["issues"]}
        self.assertEqual(result["status"], "warning", result["issues"])
        self.assertFalse(result["should_block"])
        self.assertIn("comment_changed_outside_target", issue_types)

    def test_methods_block_skips_struct_getters_and_keeps_constants(self):
        source = """pragma solidity ^0.8.21;
contract C {
  struct Campaign { address creator; uint256 goal; }
  uint256 public constant MAX_FEE = 1000;
  mapping(uint256 => Campaign) public campaigns;
  mapping(address => uint256) public balances;
  function updateFee(uint256 newFee) external {}
}
"""
        methods = build_methods_block(source)
        self.assertIn("function MAX_FEE() external returns(uint256) envfree;", methods)
        self.assertIn("function balances(address) external returns(uint256) envfree;", methods)
        self.assertIn("function updateFee(uint256 newFee) external;", methods)
        self.assertNotIn("returns(Campaign)", methods)
        self.assertNotIn("function constant()", methods)

    def test_methods_block_does_not_mark_environment_dependent_views_envfree(self):
        source = """pragma solidity ^0.8.21;
contract C {
  address public owner;
  uint256 public campaignCount;

  function createCampaign(uint256 goal, uint256 duration) external returns (uint256) {
    campaignCount++;
    owner = msg.sender;
    duration;
    return campaignCount + block.timestamp;
  }

  function timeLeft(uint256 deadline) external view returns (uint256) {
    if (block.timestamp >= deadline) {
      return 0;
    }
    return deadline - block.timestamp;
  }

  function isOwner() external view returns (bool) {
    return msg.sender == owner;
  }

  function total() external view returns (uint256) {
    return campaignCount;
  }
}
"""
        methods = build_methods_block(source)

        self.assertIn("function owner() external returns(address) envfree;", methods)
        self.assertIn("function campaignCount() external returns(uint256) envfree;", methods)
        self.assertIn("function createCampaign(uint256 goal, uint256 duration) external returns(uint256);", methods)
        self.assertIn("function timeLeft(uint256 deadline) external returns(uint256);", methods)
        self.assertIn("function isOwner() external returns(bool);", methods)
        self.assertIn("function total() external returns(uint256) envfree;", methods)
        self.assertNotIn("function timeLeft(uint256 deadline) external returns(uint256) envfree;", methods)
        self.assertNotIn("function isOwner() external returns(bool) envfree;", methods)

    def test_methods_block_removes_named_return_variables(self):
        source = """pragma solidity ^0.8.21;
contract C {
  function accountOf(address user) external view returns (uint256 deposited, uint256 withdrawn, uint256 rewardDebt, bool active) {
    user;
    return (0, 0, 0, false);
  }
}
"""
        methods = build_methods_block(source)

        self.assertIn(
            "function accountOf(address user) external returns(uint256, uint256, uint256, bool) envfree;",
            methods,
        )
        self.assertNotIn("deposited", methods)
        self.assertNotIn("withdrawn", methods)

    def test_methods_block_maps_contract_interface_params_to_address(self):
        source = """pragma solidity ^0.8.21;
interface IERC20 {}
contract C {
  function forwardERC20s(IERC20 token, uint256 amount) external {}
}
"""
        methods = build_methods_block(source)

        self.assertIn("function forwardERC20s(address token, uint256 amount) external;", methods)
        self.assertNotIn("IERC20", methods)

    def test_methods_block_maps_named_interface_return_to_address(self):
        source = """pragma solidity ^0.8.21;
interface IEscrow {}
contract C {
  function predictEscrow(address user) public view returns (IEscrow predicted) {
    user;
  }
}
"""
        methods = build_methods_block(source)

        self.assertIn("function predictEscrow(address user) external returns(address) envfree;", methods)
        self.assertNotIn("IEscrow predicted", methods)

    def test_methods_block_ignores_top_level_interface_methods(self):
        source = """pragma solidity ^0.8.21;
interface IERC20 {
  function transfer(address to, uint256 amount) external returns (bool);
}
contract C {
  address public owner;
  function setOwner(address newOwner) external {
    owner = newOwner;
  }
}
"""
        methods = build_methods_block(source)

        self.assertIn("function owner() external returns(address) envfree;", methods)
        self.assertIn("function setOwner(address newOwner) external;", methods)
        self.assertNotIn("transfer(address", methods)

    def test_deterministic_spec_generates_zero_address_rules(self):
        methods = """methods {
  function setGov(address _gov) external;
  function setPauseGuardian(address _pauseGuardian) external;
}"""
        spec = build_deterministic_spec(
            methods,
            [
                {
                    "id": "VULN_001",
                    "type": "missing-zero-check",
                    "function": "setGov(address)",
                    "rule_names": ["zero_address_reverts_setGov"],
                },
                {
                    "id": "VULN_002",
                    "type": "missing-zero-check",
                    "function": "setPauseGuardian(address)",
                    "rule_names": ["zero_address_reverts_setPauseGuardian"],
                },
            ],
        )

        self.assertIsNotNone(spec)
        self.assertIn("rule zero_address_reverts_setGov", spec)
        self.assertIn("setGov@withrevert(e, x);", spec)
        self.assertIn("setPauseGuardian@withrevert(e, x);", spec)

    def test_solc_remappings_reads_foundry_remappings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "lib" / "solmate" / "src").mkdir(parents=True)
            (root / "remappings.txt").write_text(
                "solmate/=lib/solmate/src/\ncore/=./src/\n",
                encoding="utf-8",
            )
            contract = root / "src" / "T.sol"
            contract.write_text(
                'pragma solidity ^0.8.19;\nimport {ERC20} from "solmate/tokens/ERC20.sol";\n',
                encoding="utf-8",
            )

            remaps = solc_remappings(contract)

        self.assertTrue(any(item.startswith("solmate/=") for item in remaps))
        self.assertFalse(any(item.startswith("core/=") for item in remaps))

    def test_spec_validator_does_not_add_envfree_to_every_returning_method(self):
        spec = """methods {
  function createCampaign(uint256 goal, uint256 duration) external returns(uint256);
  function owner() external returns(address) envfree;
}

rule smoke {
  assert true;
}
"""
        fixed, corrections = corrigir_spec(spec)

        self.assertIn("function createCampaign(uint256 goal, uint256 duration) external returns(uint256);", fixed)
        self.assertNotIn("createCampaign(uint256 goal, uint256 duration) external returns(uint256) envfree;", fixed)
        self.assertFalse(any("envfree adicionado" in item for item in corrections))

    def test_spec_validator_normalizes_solidity_types_inside_rules(self):
        spec = """methods {
  function notifyPartner(address target, bytes payload) external;
  function sweepTreasury(address to, uint256 amount) external;
}

rule cvl_types {
  env e;
  address payable to;
  bytes calldata payload;
  notifyPartner@withrevert(e, to, payload);
  assert lastReverted;
}
"""
        fixed, corrections = corrigir_spec(spec)

        self.assertIn("address to;", fixed)
        self.assertIn("bytes payload;", fixed)
        self.assertNotIn("address payable", fixed)
        self.assertNotIn("calldata", fixed)
        self.assertTrue(any("tipo Solidity normalizado" in item for item in corrections))

    def test_spec_validator_replaces_empty_hex_bytes_argument(self):
        spec = """methods {
  function notifyPartner(address target, bytes payload) external;
}

rule notifyPartnerZeroAddressCheck {
  env e;
  address target;
  require target == 0;
  notifyPartner@withrevert(e, target, 0x);
  assert lastReverted;
}
"""
        fixed, corrections = substituir_hex_vazio_em_calls(spec)

        self.assertIn("bytes payload;", fixed)
        self.assertIn("notifyPartner@withrevert(e, target, payload);", fixed)
        self.assertNotIn(", 0x)", fixed)
        self.assertTrue(any("0x substituido" in item for item in corrections))

    def test_import_context_detects_node_package_remapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contract = root / "contracts" / "C.sol"
            package = root / "node_modules" / "@openzeppelin"
            (root / "contracts").mkdir()
            package.mkdir(parents=True)
            contract.write_text(
                "pragma solidity ^0.8.0;\n"
                "import '@openzeppelin/contracts/access/Ownable.sol';\n"
                "contract C {}\n",
                encoding="utf-8",
            )

            self.assertTrue(has_imports(contract.read_text(encoding="utf-8")))
            self.assertEqual(packages_path(contract), root / "node_modules")
            self.assertEqual(solc_remappings(contract), [f"@openzeppelin={package}"])

    def test_invalid_envfree_certora_log_is_blocking(self):
        log = (
            "Results for all:\n"
            "Result for envfreeFuncsStaticCheck: envfreeFuncsStaticCheck: timeLeft(uint256): FAIL: "
            "Specification marks method C.timeLeft(uint256 id) returns (uint256) as 'envfree' "
            "but the method uses the following restricted environment properties [TIMESTAMP]\n"
            "CRITICAL: Function timeLeft(uint256) was declared `envfree` but depends on the environment."
        )

        self.assertTrue(has_certora_blocking_error(log))
        analysis = analyze_certora_errors(log)
        ids = {item["id"] for item in analysis["matches"]}
        self.assertIn("cvl_invalid_envfree", ids)

    def test_contract_name_mismatch_certora_log_is_blocking(self):
        log = (
            "Failed to find a contract named SimpleBank_FIXED in file "
            "/tmp/SimpleBank_FIXED.sol. Available contracts: /tmp/SimpleBank_FIXED.sol:SimpleBank"
        )
        analysis = analyze_certora_errors(log)
        ids = {item["id"] for item in analysis["matches"]}

        self.assertTrue(has_certora_blocking_error(log))
        self.assertIn("certora_contract_name_mismatch", ids)

    def test_extract_primary_contract_name_handles_fixed_filename_mismatch(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SimpleBank {
  address public owner;
}
"""
        self.assertEqual(extract_primary_contract_name(source, "SimpleBank_FIXED"), "SimpleBank")

    def test_evaluation_blocks_passed_comparison_with_invalid_certora_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "20260524_212214_CrowdfundingVault"
            run_dir.mkdir()
            (run_dir / "comparison_t1.json").write_text(
                json.dumps(
                    {
                        "resolvidas": [{"id": "VULN_001", "type": "tx-origin"}],
                        "persistentes": [],
                        "inconclusivas": [],
                        "taxa_resolucao": "1/1",
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "certora_fixed_t1.log").write_text(
                "Results for all:\n"
                "Result for envfreeFuncsStaticCheck: envfreeFuncsStaticCheck: timeLeft(uint256): FAIL: "
                "Specification marks method CrowdfundingVault.timeLeft(uint256 id) returns (uint256) "
                "as 'envfree' but the method uses the following restricted environment properties [TIMESTAMP]",
                encoding="utf-8",
            )

            row = summarize_run(run_dir)

        self.assertEqual(row["status"], "blocked:certora_fixed_t1")
        self.assertIn("cvl_invalid_envfree", row["blocked_reason"])
        self.assertIn("envfree", row["blocked_reason"])

    def test_toolchain_constraint_matching_for_solidity_08(self):
        source = "pragma solidity ^0.8.21; contract LocalTarget {}"
        self.assertEqual(extract_solidity_constraint(source), "^0.8.21")
        self.assertTrue(version_satisfies_constraint("0.8.21", "^0.8.21"))
        self.assertTrue(version_satisfies_constraint("0.8.26", "^0.8.21"))
        self.assertTrue(version_satisfies_constraint("0.8.21", ">=0.8.20 <0.9.0"))

    def test_evaluation_reports_patch_guard_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "20260524_160641_ERC2771MulticallVulnerable"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(
                json.dumps({"contract_path": "smart-audt/contracts/ERC2771MulticallVulnerable.sol"}),
                encoding="utf-8",
            )
            (run_dir / "etapa1_vulns.json").write_text(
                json.dumps({"vulnerabilidades": [{"id": "VULN_001"}]}),
                encoding="utf-8",
            )
            (run_dir / "formal_plan.json").write_text(
                json.dumps({"selected_rules": []}),
                encoding="utf-8",
            )
            (run_dir / "static_confirmed_findings.json").write_text(
                json.dumps({"vulnerabilidades": [{"id": "VULN_001"}]}),
                encoding="utf-8",
            )
            (run_dir / "analysis.json").write_text(
                json.dumps({"analises": [{"id": "VULN_001", "status": "confirmed_static"}]}),
                encoding="utf-8",
            )
            (run_dir / "toolchain_status.json").write_text(
                json.dumps({"ok": True}),
                encoding="utf-8",
            )
            (run_dir / "patch_guard_t0_status.json").write_text(
                json.dumps(
                    {
                        "stage": "patch_guard_t0",
                        "status": "blocked",
                        "reason": "Patch da LLM alterou elementos fora do escopo minimo permitido",
                    }
                ),
                encoding="utf-8",
            )

            row = summarize_run(run_dir)

        self.assertEqual(row["status"], "blocked:patch_guard_t0")
        self.assertEqual(row["confirmed"], 1)
        self.assertIn("escopo minimo", row["blocked_reason"])

    def test_evaluation_reports_generic_pipeline_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "20260525_003334_EnterpriseTreasury300"
            run_dir.mkdir()
            (run_dir / "analysis.json").write_text(
                json.dumps({"analises": [{"id": "VULN_001", "status": "confirmed"}]}),
                encoding="utf-8",
            )
            (run_dir / "llm_initial_diagnosis_status.json").write_text(
                json.dumps(
                    {
                        "stage": "llm_initial_diagnosis",
                        "status": "blocked",
                        "reason": "Falha ao consultar a LLM",
                    }
                ),
                encoding="utf-8",
            )

            row = summarize_run(run_dir)

        self.assertEqual(row["status"], "blocked:llm_initial_diagnosis")
        self.assertIn("LLM", row["blocked_reason"])

    def test_evaluation_reports_no_actionable_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "20260524_164422_VulnerableBankToken"
            run_dir.mkdir()
            (run_dir / "metadata.json").write_text(
                json.dumps({"contract_path": "smart-audt/contracts/VulnerableBankToken.sol"}),
                encoding="utf-8",
            )
            (run_dir / "etapa1_vulns.json").write_text(
                json.dumps(
                    {
                        "vulnerabilidades": [
                            {"id": "VULN_001", "type": "low-level-calls"},
                            {"id": "VULN_002", "type": "immutable-states"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "formal_plan.json").write_text(
                json.dumps({"selected_rules": []}),
                encoding="utf-8",
            )
            (run_dir / "static_confirmed_findings.json").write_text(
                json.dumps({"vulnerabilidades": []}),
                encoding="utf-8",
            )
            (run_dir / "toolchain_status.json").write_text(
                json.dumps({"ok": True}),
                encoding="utf-8",
            )

            row = summarize_run(run_dir)

        self.assertEqual(row["status"], "no_actionable_candidates")
        self.assertEqual(row["findings"], 2)
        self.assertEqual(row["selected"], 0)

    def test_contract_registry_separates_benchmarks_from_manual_examples(self):
        benchmark_names = set(default_benchmark_contracts())
        manual_names = set(contract_names(MANUAL))

        self.assertIn("SimpleBank", benchmark_names)
        self.assertIn("ERC2771MulticallVulnerable", benchmark_names)
        self.assertNotIn("SimpleBank_FIXED", benchmark_names)
        self.assertNotIn("SafeBankToken", benchmark_names)
        self.assertIn("SimpleBank_FIXED", manual_names)
        self.assertIn("SafeBankToken", manual_names)
        self.assertFalse(benchmark_names & manual_names)

    def test_contract_registry_covers_known_contract_files(self):
        registered_paths = {entry.path for entry in contract_entries()}
        actual_paths = {
            str(path.relative_to(ROOT))
            for path in (ROOT / "smart-audt" / "contracts").glob("*.sol")
        }
        groups = {entry.group for entry in contract_entries()}

        self.assertEqual(actual_paths, registered_paths)
        self.assertIn(BENCHMARK, groups)
        self.assertIn(EXPLORATORY, groups)
        self.assertIn(MANUAL, groups)
        self.assertIn(SCRATCH, groups)


_COUNTEREXAMPLE_SAMPLE_LOG = """
Results for all:
*---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------*
|Rule name                               |Verified     |Time (sec)|Description                                                 |Local vars                                        |
|----------------------------------------|-------------|----------|------------------------------------------------------------|--------------------------------------------------|
|zero_address_reverts                    |Not violated |0         |                                                            |no local variables                                |
|                                        |(unsat)      |          |                                                            |                                                  |
|unauthorized_recipient_reverts          |Violated     |2         |Assert message: lastReverted                                |King=10001                                        |
|                                        |(sat)        |          |                                                            |e.block.basefee=0                                 |
|                                        |             |          |                                                            |e.block.timestamp=0                               |
|                                        |             |          |                                                            |e.msg.sender=King                                 |
|                                        |             |          |                                                            |e.msg.value=0                                     |
|                                        |             |          |                                                            |to=0x2712                                         |
*---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------*
"""


class TestCertoraCounterexample(unittest.TestCase):
    def setUp(self):
        from core.certora_counterexample import (
            extract_counterexamples,
            format_counterexample_for_prompt,
        )
        self.extract = extract_counterexamples
        self.format = format_counterexample_for_prompt

    def test_extracts_violated_rule_vars(self):
        result = self.extract(_COUNTEREXAMPLE_SAMPLE_LOG)
        self.assertIn("unauthorized_recipient_reverts", result)
        cex = result["unauthorized_recipient_reverts"]
        self.assertIn("e.msg.sender", cex)
        self.assertEqual(cex["e.msg.sender"], "King")
        self.assertIn("to", cex)
        self.assertEqual(cex["to"], "0x2712")
        self.assertIn("_assert_message", cex)
        self.assertEqual(cex["_assert_message"], "lastReverted")

    def test_excludes_noise_vars(self):
        result = self.extract(_COUNTEREXAMPLE_SAMPLE_LOG)
        cex = result.get("unauthorized_recipient_reverts", {})
        self.assertNotIn("e.block.basefee", cex)
        self.assertNotIn("e.block.timestamp", cex)

    def test_excludes_not_violated_rules(self):
        result = self.extract(_COUNTEREXAMPLE_SAMPLE_LOG)
        self.assertNotIn("zero_address_reverts", result)

    def test_format_counterexample_for_prompt(self):
        counterexamples = self.extract(_COUNTEREXAMPLE_SAMPLE_LOG)
        text = self.format(counterexamples, ["unauthorized_recipient_reverts"])
        self.assertIn("CERTORA COUNTEREXAMPLES", text)
        self.assertIn("unauthorized_recipient_reverts", text)
        self.assertIn("REVERT", text)
        self.assertIn("to", text)
        self.assertIn("0x2712", text)

    def test_format_empty_counterexamples(self):
        text = self.format({}, ["some_rule"])
        self.assertEqual(text, "")

    def test_format_uses_all_counterexamples_when_no_match(self):
        counterexamples = self.extract(_COUNTEREXAMPLE_SAMPLE_LOG)
        text = self.format(counterexamples, ["nonexistent_rule"])
        self.assertIn("unauthorized_recipient_reverts", text)


class TestFixLibrary(unittest.TestCase):
    def test_save_and_load_pattern(self):
        import tempfile
        from unittest.mock import patch
        from core.fix_library import save_pattern, get_examples_for_prompt, LIBRARY_PATH

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / "fix_library.json"
            with patch("core.fix_library.LIBRARY_PATH", tmp_path):
                from core import fix_library
                orig_path = fix_library.LIBRARY_PATH
                fix_library.LIBRARY_PATH = tmp_path

                save_pattern(
                    vuln_type="arbitrary-send-eth",
                    repair_strategy="restrict_recipient",
                    function_signature="function claim(address payable to) external onlyOwner",
                    fix_snippet='require(to == msg.sender, "Unauthorized");',
                    contract_name="TestContract",
                    run_id="20260627_test",
                )
                result = get_examples_for_prompt(["arbitrary-send-eth"])
                fix_library.LIBRARY_PATH = orig_path

        self.assertIn("arbitrary-send-eth", result)
        self.assertIn("require(to == msg.sender", result)

    def test_get_examples_empty_library(self):
        import tempfile
        from core import fix_library

        orig_path = fix_library.LIBRARY_PATH
        with tempfile.TemporaryDirectory() as tmp:
            fix_library.LIBRARY_PATH = Path(tmp) / "nonexistent.json"
            result = fix_library.get_examples_for_prompt(["missing-zero-check"])
            fix_library.LIBRARY_PATH = orig_path

        self.assertEqual(result, "")

    def test_no_duplicate_patterns(self):
        import tempfile
        from core import fix_library

        with tempfile.TemporaryDirectory() as tmp:
            fix_library.LIBRARY_PATH = Path(tmp) / "lib.json"
            for _ in range(3):
                fix_library.save_pattern(
                    vuln_type="tx-origin",
                    repair_strategy="replace_tx_origin",
                    function_signature="modifier onlyOwner()",
                    fix_snippet='require(msg.sender == owner, "not owner");',
                    contract_name="Foo",
                    run_id="run1",
                )
            lib = fix_library.load_library()
            fix_library.LIBRARY_PATH = Path("/home/gflb/TesteCertora/runs/fix_library.json")

        self.assertEqual(len(lib["patterns"]), 1)


if __name__ == "__main__":
    unittest.main()
