"""Slither + catalog pipeline with no LLM and no Certora.

Runs the deterministic half of the pipeline: Slither, normalization, catalog policy and the
mechanical patches, then re-runs Slither on the patched source to see what disappeared. It
imports nothing from ``llm/``, so it works without an API key and gives the baseline that the
full pipeline has to beat.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from core.deterministic_patch import apply_deterministic_patches
from core.run_store import copy_contract, create_run_dir, save_json, save_text, write_metadata
from core.slither_normalizer import normalize_slither_json
from core.toolchain import check_solidity_toolchain
from tools.slither_cli import SlitherRunError, run_slither_raw


def classify(finding: dict, entry: dict) -> str:
    """Which deterministic lane a finding falls in, by catalog policy alone."""
    if entry.get("reason") == "no catalog mapping yet":
        return "unmapped"
    if entry.get("static_confirmed"):
        return "static_confirmed"
    if entry.get("formalizable"):
        return "formalizable"
    return "triage_only"


def _key(finding: dict) -> tuple[str, str]:
    return finding.get("type", ""), finding.get("function", "")


def build_report(findings: list[dict], patches: list[dict], remaining: list[dict]) -> dict:
    from core.vulnerability_catalog import get_catalog_entry

    lanes = [classify(f, get_catalog_entry(f["type"])) for f in findings]
    patched_ids = {p["id"] for p in patches}
    remaining_keys = Counter(_key(f) for f in remaining)

    rows = []
    for finding, lane in zip(findings, lanes):
        resolved = finding["id"] in patched_ids and remaining_keys[_key(finding)] == 0
        rows.append(
            {
                "id": finding["id"],
                "type": finding["type"],
                "function": finding.get("function", ""),
                "line": finding.get("line", ""),
                "impact": finding.get("impact", ""),
                "lane": lane,
                "repair_strategy": finding.get("repair_strategy", ""),
                "patched": finding["id"] in patched_ids,
                "resolved_after_rerun": resolved,
            }
        )
    return {
        "total": len(rows),
        "lanes": dict(Counter(lanes)),
        "patched": len(patched_ids),
        "resolved_after_rerun": sum(row["resolved_after_rerun"] for row in rows),
        "findings": rows,
    }


def scoped_to_file(raw: dict, contract_path: Path) -> dict:
    """Keep only the detectors whose elements live in ``contract_path``.

    Slither analyzes everything the file imports, so each run also reports the imported
    contracts. Counting those per file recounts them for every importer, and after a patch
    it brings the unpatched original back through a cyclic import, so the fix looked
    unresolved. A detector with no source-mapped element is kept: there is nothing to scope by.
    """
    target = str(contract_path.resolve())

    def located_here(detector: dict) -> bool:
        names = [
            element.get("source_mapping", {}).get("filename_absolute")
            for element in detector.get("elements", [])
            if isinstance(element, dict)
        ]
        names = [name for name in names if name]
        return not names or target in names

    scoped = dict(raw)
    scoped["results"] = dict(raw.get("results", {}))
    scoped["results"]["detectors"] = [
        detector for detector in raw.get("results", {}).get("detectors", []) if located_here(detector)
    ]
    return scoped


def _findings_of_patched(original: Path, patched_source: str) -> list[dict]:
    """Re-run Slither on the patched source placed beside the original.

    Relative imports resolve against the file's own directory, so analyzing a copy kept in
    the run folder would report every contract with an import as "does not compile".
    """
    sibling = original.with_name(f"{original.stem}__static_fixed.sol")
    sibling.write_text(patched_source, encoding="utf-8")
    try:
        raw = scoped_to_file(run_slither_raw(str(sibling)), sibling)
        return normalize_slither_json(raw, str(sibling))["vulnerabilidades"]
    finally:
        sibling.unlink(missing_ok=True)


def with_plugin_findings(raw: dict, plugin_findings: list[dict]) -> dict:
    """``raw`` plus the project detectors' results, without mutating ``raw``."""
    merged = dict(raw)
    merged["results"] = dict(raw.get("results", {}))
    merged["results"]["detectors"] = list(raw.get("results", {}).get("detectors", [])) + plugin_findings
    return merged


def _plugin_findings(contract_path: str) -> list[dict]:
    """Findings of the project's own detectors; a plugin that cannot run never blocks the run."""
    from tools.slither_plugin_runner import run_unrestricted_write

    try:
        return run_unrestricted_write(contract_path)
    except Exception as exc:  # the plugin is additive evidence, not a required stage
        print(f"Project detectors skipped: {exc}")
        return []


def executar_static_only(contract_path: str, with_plugins: bool = False) -> dict | None:
    path = Path(contract_path)
    if not path.exists():
        print(f"Contract not found: {contract_path}")
        return None

    source = path.read_text(encoding="utf-8")
    repo_root = Path(__file__).resolve().parents[2]
    # Kept apart from runs/: the evaluation tooling takes the newest folder per contract name,
    # and a static-only run has none of the full pipeline's artifacts.
    run_dir = create_run_dir(contract_path, root=str(repo_root / "runs" / "static_only"))
    copy_contract(contract_path, run_dir)
    write_metadata(run_dir, contract_path, "none (static-only)")
    print(f"Run artifacts: {run_dir}")

    toolchain = check_solidity_toolchain(source)
    save_json(run_dir / "toolchain_status.json", toolchain)
    if not toolchain["ok"]:
        print(f"Toolchain preflight blocked: {toolchain['reason']}")
        return None

    try:
        raw = run_slither_raw(contract_path)
    except SlitherRunError as exc:
        print(f"Slither could not analyze the contract: {exc}")
        return None
    save_json(run_dir / "slither_raw.json", raw)
    if with_plugins:
        raw = with_plugin_findings(raw, _plugin_findings(contract_path))
    normalized = normalize_slither_json(scoped_to_file(raw, path), contract_path)
    save_json(run_dir / "slither_normalized.json", normalized)
    findings = normalized["vulnerabilidades"]

    patched_source, patches = apply_deterministic_patches(source, findings)
    remaining: list[dict] = []
    patch_compiles = True
    if patches:
        save_text(run_dir / f"{path.stem}_STATIC_FIXED.sol", patched_source)
        save_json(run_dir / "deterministic_patch.json", {"patches": patches})
        try:
            remaining = _findings_of_patched(path, patched_source)
        except SlitherRunError as exc:
            # A patch that does not compile resolves nothing; say so instead of crashing.
            print(f"Patched source does not compile, no patch counts as resolved: {exc}")
            patch_compiles = False

    report = build_report(findings, patches, remaining if patch_compiles else findings)
    report["patch_compiles"] = patch_compiles
    save_json(run_dir / "static_report.json", report)
    _print_summary(report)
    return report


def _print_summary(report: dict) -> None:
    lanes = report["lanes"]
    print(f"\nStatic-only: {report['total']} finding(s), no LLM, no Certora")
    for lane in ("formalizable", "static_confirmed", "triage_only", "unmapped"):
        print(f"  {lane:17} {lanes.get(lane, 0)}")
    print(
        f"  patched deterministically: {report['patched']}, "
        f"resolved after Slither rerun: {report['resolved_after_rerun']}"
    )
    for row in report["findings"]:
        if row["lane"] in ("formalizable", "static_confirmed"):
            print(f"  - {row['id']} {row['type']} {row['function']} ({row['lane']})")
