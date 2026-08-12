"""Measure whether the agent generalizes or replays stored fixes.

Takes an already-repaired contract, injects one defect at a time with the mutation
operators, runs the pipeline on each mutant, and classifies every produced fix against
``runs/fix_library.json``.

The mutants are held out by construction: ``fix_library.get_examples_for_prompt``
retrieves by exact ``vuln_type``, so an unseen class gets no examples and a fix for it
cannot have been copied.

What the numbers mean:

  novel   — the agent produced a fix whose structure is not in the library
  adapted — it instantiated a stored template with new identifiers
  copied  — it reproduced a stored snippet verbatim

Repairs that are all copied/adapted do not demonstrate generalization, however green
the benchmark looks. Needs GROQ_API_KEY and a real CERTORAKEY.

    python agent/generalization_probe.py smart-audt/contracts/DeFiVault_FIXED.sol
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from core.contract_context import extract_primary_contract_name
from core.generalization import classify_fix, report
from core.import_context import has_imports
from core.mutation import OPERATORS, mutate, summarize


def _library_patterns() -> list[dict]:
    path = REPO_ROOT / "runs" / "fix_library.json"
    if not path.is_file():
        return []
    return json.loads(path.read_text(encoding="utf-8")).get("patterns", [])


def _expected_fix_path(mutant_source: str, target: Path) -> Path:
    """Where executar_pipeline(..., copy_final=False) actually writes a success.

    Mirrors orchestrator.py's own caminho_fix_temp choice: with imports, next to the
    mutant file; without, under agent_outputs/ (relative to cwd, same as the pipeline
    itself resolves it). The probe's target file is never touched under
    copy_final=False, so reading it back for a diff — the previous approach — silently
    misreports every success as "no patch produced".
    """
    primary_name = extract_primary_contract_name(mutant_source, target.stem) or target.stem
    if has_imports(mutant_source):
        return target.parent / f"{primary_name}_AGENT_FIXED.sol"
    return Path("agent_outputs") / f"{primary_name}_FIXED.sol"


def _extract_fix_lines(original: str, fixed: str) -> str:
    """Lines present in the repaired source but not in the mutant."""
    before = set(line.strip() for line in original.splitlines())
    return " ".join(
        line.strip() for line in fixed.splitlines()
        if line.strip() and line.strip() not in before
    )


def run_probe(contract: Path, operators: tuple[str, ...], limit: int, dry_run: bool) -> int:
    source = contract.read_text(encoding="utf-8")
    mutations = mutate(source, operators=operators, limit_per_operator=limit)

    print(f"Contrato base : {contract}")
    print(f"Mutantes      : {len(mutations)} {summarize(mutations)}")
    print(f"Biblioteca    : {len(_library_patterns())} padrao(oes) armazenado(s)\n")

    if dry_run:
        for mutation in mutations:
            print(f"[{mutation.operator}] linha {mutation.line}: {mutation.description}")
            print(f"    {mutation.original}")
        return 0

    from orchestrator import executar_pipeline  # imported late: needs API credentials

    library = _library_patterns()
    verdicts = []
    repaired = failed = 0

    probe_tmp_root = REPO_ROOT / "runs" / "_probe_tmp"
    probe_tmp_root.mkdir(parents=True, exist_ok=True)

    for index, mutation in enumerate(mutations, start=1):
        print(f"\n=== [{index}/{len(mutations)}] {mutation.label}: {mutation.description}")
        with tempfile.TemporaryDirectory(dir=probe_tmp_root) as workdir:
            target = Path(workdir) / contract.name
            target.write_text(mutation.source, encoding="utf-8")

            fix_path = _expected_fix_path(mutation.source, target)
            fix_path.unlink(missing_ok=True)  # drop a previous mutant's leftover before running

            try:
                executar_pipeline(str(target), copy_final=False)
            except Exception as exc:  # a failing mutant is data, not a crash
                failed += 1
                print(f"    pipeline falhou: {type(exc).__name__}: {str(exc)[:160]}")
                continue

            if not fix_path.is_file():
                failed += 1
                print("    nenhum patch produzido")
                continue

            produced = fix_path.read_text(encoding="utf-8")
            fix_path.unlink()

        repaired += 1
        verdict = classify_fix(
            _extract_fix_lines(mutation.source, produced), library, vuln_type=mutation.expected_class
        )
        verdicts.append(verdict)
        print(f"    corrigido -> {verdict.kind} (sim={verdict.similarity})")

    summary = report(verdicts)
    print("\n" + "=" * 60)
    print(f"reparados      : {repaired}/{len(mutations)}  (falhas: {failed})")
    print(f"classificacao  : {summary['counts']}")
    print(f"taxa de novos  : {summary['novel_rate']}")
    print("=" * 60)
    print(
        "\nSem nenhum fix 'novel', o agente nao demonstrou capacidade de generalizar —\n"
        "apenas de reaplicar o que ja estava na biblioteca."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("contract", help="Repaired contract to mutate.")
    parser.add_argument("--operators", nargs="*", default=list(OPERATORS), choices=list(OPERATORS))
    parser.add_argument("--limit", type=int, default=2, help="Mutants per operator.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List the mutants without running the pipeline (needs no credentials).",
    )
    args = parser.parse_args(argv)

    contract = Path(args.contract).resolve()
    if not contract.is_file():
        print(f"Contrato nao encontrado: {contract}")
        return 1

    return run_probe(contract, tuple(args.operators), args.limit, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
