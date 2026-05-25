"""Summarize pipeline run artifacts for evaluation reports."""

from __future__ import annotations

import json
from pathlib import Path

from core.certora_error_catalog import analyze_certora_errors


def _read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def _latest_run_for_contract(runs_root: Path, contract_name: str) -> Path | None:
    matches = sorted(runs_root.glob(f"*_{contract_name}"))
    return matches[-1] if matches else None


def _latest_status_file(run_dir: Path, pattern: str) -> dict:
    matches = sorted(run_dir.glob(pattern))
    if not matches:
        return {}
    return _read_json(matches[-1], {})


def _blocking_certora_logs(run_dir: Path) -> list[dict]:
    blockers = []
    for log_path in sorted(run_dir.glob("certora*.log")):
        log = log_path.read_text(encoding="utf-8", errors="replace")
        analysis = analyze_certora_errors(log)
        blocking_matches = [
            item for item in analysis["matches"]
            if item.get("severity") == "blocking"
        ]
        if blocking_matches:
            blockers.append(
                {
                    "log": log_path.name,
                    "stage": log_path.stem,
                    "matches": blocking_matches,
                }
            )
    return blockers


def _format_certora_blockers(blockers: list[dict]) -> str:
    if not blockers:
        return ""

    notes = []
    for blocker in blockers:
        ids = ", ".join(item["id"] for item in blocker["matches"])
        causes = "; ".join(item["cause"] for item in blocker["matches"])
        notes.append(f"{blocker['log']}: {ids} - {causes}")
    return " | ".join(notes)


def summarize_run(run_dir: Path) -> dict:
    metadata = _read_json(run_dir / "metadata.json", {})
    findings = _read_json(run_dir / "etapa1_vulns.json", {}).get("vulnerabilidades", [])
    plan = _read_json(run_dir / "formal_plan.json", {})
    static_findings = _read_json(run_dir / "static_confirmed_findings.json", {}).get("vulnerabilidades", [])
    analysis = _read_json(run_dir / "analysis.json", {}).get("analises", [])
    comparison = _read_json(run_dir / "comparison_t1.json", {})
    certora_status = _read_json(run_dir / "certora_status.json", {})
    patch_guard_status = _latest_status_file(run_dir, "patch_guard_t*_status.json")
    toolchain = _read_json(run_dir / "toolchain_status.json", {})
    certora_log_blockers = _blocking_certora_logs(run_dir)

    if certora_log_blockers:
        status = f"blocked:{certora_log_blockers[0]['stage']}"
    elif comparison:
        status = "passed" if not comparison.get("persistentes") and not comparison.get("inconclusivas") else "partial"
    elif certora_status:
        status = f"blocked:{certora_status.get('stage', 'certora')}"
    elif patch_guard_status:
        status = f"blocked:{patch_guard_status.get('stage', 'patch_guard')}"
    elif toolchain and not toolchain.get("ok", True):
        status = "blocked:toolchain"
    elif findings and not plan.get("selected_rules", []) and not static_findings:
        status = "no_actionable_candidates"
    elif analysis:
        confirmed = [item for item in analysis if item.get("status") == "confirmed"]
        status = "confirmed_without_fix" if confirmed else "no_confirmed_findings"
    else:
        status = "not_completed"

    return {
        "run": run_dir.name,
        "contract": run_dir.name.split("_", 2)[-1],
        "contract_path": metadata.get("contract_path", ""),
        "status": status,
        "findings": len(findings),
        "selected": len(plan.get("selected_rules", [])) + len(static_findings),
        "confirmed": sum(1 for item in analysis if item.get("status") in ("confirmed", "confirmed_static")),
        "resolved": len(comparison.get("resolvidas", [])),
        "persistent": len(comparison.get("persistentes", [])),
        "inconclusive": len(comparison.get("inconclusivas", [])),
        "rate": comparison.get("taxa_resolucao", ""),
        "resolved_types": sorted({item.get("type", "") for item in comparison.get("resolvidas", []) if item.get("type")}),
        "blocked_reason": (
            _format_certora_blockers(certora_log_blockers)
            or certora_status.get("reason", "")
            or patch_guard_status.get("reason", "")
        ),
    }


def summarize_contracts(runs_root: Path, contract_names: list[str]) -> list[dict]:
    rows = []
    for name in contract_names:
        run_dir = _latest_run_for_contract(runs_root, name)
        if run_dir:
            rows.append(summarize_run(run_dir))
    return rows


def render_markdown(rows: list[dict]) -> str:
    lines = [
        "# Evaluation Results",
        "",
        "Generated from the latest available run artifact for each selected contract.",
        "",
        "| Contract | Latest run | Status | Findings | Selected | Confirmed | Resolved | Rate | Notes |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]

    for row in rows:
        notes = ", ".join(row["resolved_types"]) if row["resolved_types"] else row["blocked_reason"]
        lines.append(
            f"| {row['contract']} | `{row['run']}` | {row['status']} | "
            f"{row['findings']} | {row['selected']} | {row['confirmed']} | "
            f"{row['resolved']} | {row['rate']} | {notes} |"
        )

    lines.extend(
        [
            "",
            "## Current Interpretation",
            "",
            "The pipeline is currently strongest for `missing-zero-check`, `tx-origin`, "
            "`suicidal`, and clear `arbitrary-send-eth` cases. Reentrancy and "
            "timestamp/block-number findings are preserved as static-review evidence "
            "instead of being sent to Certora. `unchecked-lowlevel` is handled as "
            "a static-confirmed Slither flow and validated by rerunning Slither. "
            "`erc2771-multicall-context` is now handled as a static-confirmed "
            "composition pattern because Slither reports only the low-level pieces. "
            "`unprotected-critical-update` remains exploratory/static-review until "
            "its name-based heuristic has stronger negative coverage.",
            "",
        ]
    )
    return "\n".join(lines)
