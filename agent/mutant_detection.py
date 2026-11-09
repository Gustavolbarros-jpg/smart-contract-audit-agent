"""Which injected defects does the static stack (Slither + project detectors) even see?

For every mutant of a contract, runs Slither (no LLM, no Certora) and compares its findings
with those of the unmutated contract. A mutant is *detected* when it adds a finding
(type, function) that the original does not have.

This bounds what ``generalization_probe.py`` can measure: a mutant that nothing detects never
reaches the repair stage, so it says nothing about whether the agent generalizes.

    SOLC_VERSION=0.8.21 python agent/mutant_detection.py smart-audt/contracts/DeFiVault_FIXED.sol
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from core.mutation import OPERATORS, mutate
from core.slither_normalizer import normalize_slither_json
from core.slither_scope import scoped_to_file, without_harness_contracts
from core.static_only import _plugin_findings, with_plugin_findings
from tools.slither_cli import SlitherRunError, run_slither_raw


def _finding_keys(path: Path, with_plugins: bool) -> Counter:
    raw = run_slither_raw(str(path))
    if with_plugins:
        raw = with_plugin_findings(raw, _plugin_findings(str(path)))
    normalized = normalize_slither_json(without_harness_contracts(scoped_to_file(raw, path)), str(path))
    return Counter((v.get("type", ""), v.get("function", "")) for v in normalized["vulnerabilidades"])


def _analyze(mutation, directory: Path, name: str, baseline: Counter, with_plugins: bool) -> dict:
    # One folder per mutant, so concurrent workers never share a file.
    directory.mkdir()
    target = directory / name
    target.write_text(mutation.source, encoding="utf-8")
    try:
        keys = _finding_keys(target, with_plugins)
    except SlitherRunError as exc:
        return {"label": mutation.label, "operator": mutation.operator, "status": "compile_error", "detail": str(exc)[:120]}
    added = sorted((keys - baseline).keys())
    return {
        "label": mutation.label,
        "operator": mutation.operator,
        "line": mutation.line,
        "status": "detected" if added else "missed",
        "added": [list(k) for k in added],
    }


def measure(contract: Path, with_plugins: bool, workers: int) -> dict:
    source = contract.read_text(encoding="utf-8")
    mutations = mutate(source, operators=OPERATORS, limit_per_operator=1000)
    baseline = _finding_keys(contract, with_plugins)

    with tempfile.TemporaryDirectory(dir=contract.parent) as workdir:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(_analyze, m, Path(workdir) / f"m{i}", contract.name, baseline, with_plugins)
                for i, m in enumerate(mutations)
            ]
            results = [f.result() for f in futures]

    by_operator: dict[str, Counter] = defaultdict(Counter)
    for item in results:
        by_operator[item["operator"]][item["status"]] += 1
    return {
        "contract": str(contract),
        "with_plugins": with_plugins,
        "baseline_findings": sorted([list(k) for k in baseline]),
        "by_operator": {op: dict(by_operator[op]) for op in OPERATORS if op in by_operator},
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("contract")
    parser.add_argument("--with-plugins", action="store_true", help="Also run the project's own detectors.")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--json", dest="json_out", default=None, help="Write the full result here.")
    args = parser.parse_args(argv)

    contract = Path(args.contract).resolve()
    if not contract.is_file():
        print(f"Contrato nao encontrado: {contract}")
        return 1

    report = measure(contract, args.with_plugins, args.workers)
    print(f"{'operador':<9}{'detectados':>11}{'perdidos':>10}{'nao compila':>13}")
    totals: Counter = Counter()
    for op, counts in report["by_operator"].items():
        totals.update(counts)
        print(f"{op:<9}{counts.get('detected', 0):>11}{counts.get('missed', 0):>10}{counts.get('compile_error', 0):>13}")
    print(f"{'total':<9}{totals['detected']:>11}{totals['missed']:>10}{totals['compile_error']:>13}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
