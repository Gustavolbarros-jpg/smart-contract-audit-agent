"""Deterministic check of the vulnerability catalog against every Slither detector.

No LLM is involved. Slither's own test corpus holds, for each detector, contracts that must
trigger it (``tests/e2e/detectors/test_data/<detector>/<solc>/*.sol``) together with a
crytic-compile archive of each, so no matching solc is needed. Each archive is analyzed, the
result goes through the same ``normalize_slither_json`` the pipeline uses, and the catalog
entry it lands on is checked.

Per detector the outcome is one of:

  ok               fired, survived normalization, has a catalog entry
  no-catalog       fired and normalized, but get_catalog_entry fell back to the default
  lost             fired in raw Slither output but is absent after normalization
  not-fired        every test contract analyzed, but this detector stayed silent
  analysis-failed  no test contract could be analyzed
  no-tests         the corpus has no archive for this detector

Get the corpus without cloning:
    curl -L https://codeload.github.com/crytic/slither/tar.gz/refs/tags/<version> -o s.tgz
    mkdir out && tar xzf s.tgz -C out --wildcards "*/tests/e2e/detectors/test_data/*"

Usage:
    python3 agent/verify_catalog.py --tests-dir out/slither-<version>/tests/e2e/detectors/test_data \
        [--out report.md] [--only check1,check2]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.slither_normalizer import normalize_slither_json
from core.spec_patterns import pattern_for_type
from core.vulnerability_catalog import CATALOG, get_catalog_entry

REQUIRED_KEYS = {"category", "formalizable", "property", "cvl_pattern", "repair_strategy"}


def list_detectors() -> list[dict]:
    result = subprocess.run(
        ["slither", "--list-detectors-json"], capture_output=True, text=True, timeout=60
    )
    return json.loads(result.stdout)


def run_slither(archive: Path) -> dict | None:
    try:
        result = subprocess.run(
            ["slither", str(archive), "--json", "-", "--no-fail-pedantic"],
            capture_output=True, text=True, timeout=120,
        )
        payload = json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    return payload if payload.get("success", True) else None


def source_beside(archive: Path) -> str:
    """``x.sol-0.4.25.zip`` was compiled from ``x.sol`` in the same directory."""
    name = archive.name.split(".sol-")[0] + ".sol"
    candidate = archive.with_name(name)
    return str(candidate) if candidate.exists() else ""


def catalog_issues(check: str) -> list[str]:
    """Problems with the entry itself, independent of any contract."""
    if check not in CATALOG:
        return []
    entry = CATALOG[check]
    issues = [f"missing key {key}" for key in sorted(REQUIRED_KEYS - entry.keys())]
    if entry.get("formalizable"):
        if not entry.get("property") or not entry.get("cvl_pattern"):
            issues.append("formalizable without property/cvl_pattern")
        if pattern_for_type(check) is None:
            issues.append("formalizable without a SPEC_PATTERNS entry")
    return issues


def verify(detector: dict, tests_dir: Path) -> dict:
    check = detector["check"]
    row = {"check": check, "impact": detector["impact"], "in_catalog": check in CATALOG,
           "issues": catalog_issues(check)}

    archives = sorted((tests_dir / check).glob("*/*.zip"))
    if not archives:
        return {**row, "status": "no-tests"}

    analyzed = False
    for archive in archives:
        payload = run_slither(archive)
        if payload is None:
            continue
        analyzed = True
        raw = {d["check"] for d in payload.get("results", {}).get("detectors", [])}
        if check not in raw:
            continue
        findings = normalize_slither_json(payload, source_beside(archive))["vulnerabilidades"]
        if not any(f["type"] == check for f in findings):
            return {**row, "status": "lost", "archive": archive.name}
        if get_catalog_entry(check).get("reason") == "no catalog mapping yet":
            return {**row, "status": "no-catalog", "archive": archive.name}
        return {**row, "status": "ok", "archive": archive.name}
    return {**row, "status": "not-fired" if analyzed else "analysis-failed"}


def render(rows: list[dict]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    lines = ["# Catalog verification (Slither test corpus, no LLM)", "",
             f"{len(rows)} detectors. " + ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())), "",
             "| detector | impact | status | in catalog | issues |", "|---|---|---|---|---|"]
    for row in sorted(rows, key=lambda r: (r["status"], r["check"])):
        lines.append(
            f"| {row['check']} | {row['impact']} | {row['status']} | "
            f"{'yes' if row['in_catalog'] else 'no'} | {'; '.join(row['issues'])} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--tests-dir", required=True, help="Slither tests/e2e/detectors/test_data")
    parser.add_argument("--out", help="write the markdown report here")
    parser.add_argument("--only", help="comma-separated detector names")
    args = parser.parse_args(argv)

    detectors = list_detectors()
    if args.only:
        wanted = set(args.only.split(","))
        detectors = [d for d in detectors if d["check"] in wanted]

    tests_dir = Path(args.tests_dir)
    with ThreadPoolExecutor(4) as pool:
        rows = list(pool.map(lambda d: verify(d, tests_dir), detectors))

    report = render(rows)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    print(report)
    return 1 if any(row["issues"] for row in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
