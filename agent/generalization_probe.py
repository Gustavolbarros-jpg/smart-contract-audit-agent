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

With ``--oracle-spec``, a repair is not taken at its word: the repaired contract is checked
against a spec frozen from the original by the local verifier (no cloud job, no quota), and
a rule that passed *without being reachable* counts as vacuous, not as a repair. That is
the success criterion of ``docs/experimento-generalizacao-pre-registro.md`` §4 -- "Slither
stopped reporting it" is a much weaker oracle than "the property still holds".

    python agent/generalization_probe.py smart-audt/contracts/DeFiVault_FIXED.sol
    python agent/generalization_probe.py smart-audt/contracts/DeFiVault_FIXED.sol \
        --oracle-spec specs/oracle/DeFiVault.spec
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
from tools.certora_cli import verify_locally


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


def _detectable_only(contract: Path, source: str, operators: tuple[str, ...], limit: int) -> list:
    """Mutants that the static stack flags, up to ``limit`` per operator.

    A mutant Slither cannot see never reaches the repair stage, so running it measures the
    detector, not the agent (see ``mutant_detection.py``).
    """
    from mutant_detection import measure

    everything = mutate(source, operators=operators, limit_per_operator=1000)
    report = measure(contract, with_plugins=True, workers=4)
    # measure() mutates with every operator; keep this call's operators in the same order.
    all_ops = mutate(source, operators=tuple(OPERATORS), limit_per_operator=1000)
    detected = {
        (m.operator, m.line, m.mutated)
        for m, r in zip(all_ops, report["results"])
        if r["status"] == "detected"
    }
    kept, per_operator = [], {}
    for mutation in everything:
        if (mutation.operator, mutation.line, mutation.mutated) not in detected:
            continue
        if per_operator.get(mutation.operator, 0) >= limit:
            continue
        per_operator[mutation.operator] = per_operator.get(mutation.operator, 0) + 1
        kept.append(mutation)
    return kept


def _oracle_check(
    fixed_path: Path, oracle_spec: Path, contract_name: str, timeout: int, log_path: Path | None
) -> dict:
    """O critério de sucesso do pré-registro, aplicado ao contrato reparado."""
    # Absoluto antes de trocar o cwd: sem imports o patch sai em `agent_outputs/`, que é
    # relativo ao cwd do processo, e o Prover deixaria de encontrar o arquivo.
    fixed_path = fixed_path.resolve()
    verdict = verify_locally(
        str(fixed_path),
        str(oracle_spec),
        contract_name=contract_name,
        timeout=timeout,
        log_path=str(log_path) if log_path else None,
        cwd=str(fixed_path.parent),
        allow_path=str(REPO_ROOT),
        msg="probe oracle",
    )
    if verdict.status == "verified" and verdict.vacuous_rules:
        status = "vacuous"
    else:
        status = verdict.status
    return {
        "status": status,
        "violated": verdict.violated_rules,
        "vacuous": verdict.vacuous_rules,
        "detail": verdict.detail[:200],
    }


def run_probe(
    contract: Path,
    operators: tuple[str, ...],
    limit: int,
    dry_run: bool,
    detectable_only: bool = False,
    oracle_spec: Path | None = None,
    oracle_timeout: int = 600,
    only_labels: set[str] | None = None,
) -> int:
    source = contract.read_text(encoding="utf-8")
    if detectable_only:
        mutations = _detectable_only(contract, source, operators, limit)
    else:
        mutations = mutate(source, operators=operators, limit_per_operator=limit)
    if only_labels:
        # A população mensurável do experimento: fora dela não existe critério de "reparado"
        # (docs/experimento-generalizacao-pre-registro.md §3).
        mutations = [
            m for m in mutations
            if m.label in only_labels or m.label.replace("@", "_at_") in only_labels
        ]

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

    oracle_counts: dict[str, int] = {}
    oracle_results: list[dict] = []
    oracle_dir = None
    if oracle_spec is not None:
        oracle_dir = REPO_ROOT / "runs" / f"probe_oracle_{contract.stem}"
        oracle_dir.mkdir(parents=True, exist_ok=True)
        print(f"Oraculo       : {oracle_spec} (logs em {oracle_dir})\n")

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
            oracle = None
            if oracle_spec is not None:
                primary = extract_primary_contract_name(mutation.source, contract.stem) or contract.stem
                oracle = _oracle_check(
                    fix_path, oracle_spec, primary, oracle_timeout,
                    oracle_dir / f"{mutation.label.replace('@', '_at_')}.log" if oracle_dir else None,
                )
            fix_path.unlink()

        repaired += 1
        verdict = classify_fix(
            _extract_fix_lines(mutation.source, produced), library, vuln_type=mutation.expected_class
        )
        verdicts.append(verdict)
        if oracle is None:
            print(f"    corrigido -> {verdict.kind} (sim={verdict.similarity})")
        else:
            oracle_counts[oracle["status"]] = oracle_counts.get(oracle["status"], 0) + 1
            oracle_results.append({"label": mutation.label, "classification": verdict.kind, **oracle})
            print(
                f"    corrigido -> {verdict.kind} (sim={verdict.similarity}) | "
                f"oraculo: {oracle['status']}"
                + (f" {oracle['violated'] or oracle['vacuous']}" if oracle["status"] != "verified" else "")
            )

    summary = report(verdicts)
    print("\n" + "=" * 60)
    print(f"reparados      : {repaired}/{len(mutations)}  (falhas: {failed})")
    print(f"classificacao  : {summary['counts']}")
    print(f"taxa de novos  : {summary['novel_rate']}")
    if oracle_spec is not None:
        confirmed = oracle_counts.get("verified", 0)
        print(f"oraculo        : {oracle_counts}")
        print(f"confirmados    : {confirmed}/{repaired} reparos passam a spec congelada sem vacuidade")
        (oracle_dir / "probe_oracle.json").write_text(
            json.dumps({"counts": oracle_counts, "results": oracle_results}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    print("=" * 60)
    novel = summary["counts"].get("novel", 0)
    if repaired == 0:
        print("\nNenhum mutante foi reparado: nada a concluir sobre generalizacao.")
    elif novel == 0:
        print(
            "\nSem nenhum fix 'novel', o agente nao demonstrou capacidade de generalizar —\n"
            "apenas de reaplicar o que ja estava na biblioteca."
        )
    else:
        print(
            f"\n{novel} de {repaired} fixes reparados sao 'novel'. Com {len(mutations) - repaired} mutantes\n"
            "sem reparo, a amostra so vale se as falhas nao forem de infraestrutura."
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
    parser.add_argument(
        "--detectable-only",
        action="store_true",
        help="Keep only mutants that Slither/plugins flag (runs the detection check first).",
    )
    parser.add_argument(
        "--oracle-spec",
        default=None,
        help="Spec CVL congelada: o reparo só conta se ela continuar valendo e não ficar vácua.",
    )
    parser.add_argument("--oracle-timeout", type=int, default=600)
    parser.add_argument(
        "--only-labels",
        default=None,
        help="Lista de labels (AOR@91,MD@78) ou um report.json do mutant_oracle: mede só esses mutantes.",
    )
    args = parser.parse_args(argv)

    contract = Path(args.contract).resolve()
    if not contract.is_file():
        print(f"Contrato nao encontrado: {contract}")
        return 1

    oracle_spec = None
    if args.oracle_spec:
        oracle_spec = Path(args.oracle_spec).resolve()
        if not oracle_spec.is_file():
            print(f"Spec de oraculo nao encontrada: {oracle_spec}")
            return 1

    only_labels = None
    if args.only_labels:
        candidate = Path(args.only_labels)
        if candidate.is_file():
            previous = json.loads(candidate.read_text(encoding="utf-8"))
            only_labels = {item["label"] for item in previous["mutants"] if item["status"] == "killed"}
        else:
            only_labels = {part.strip() for part in args.only_labels.split(",") if part.strip()}
        print(f"Populacao     : {len(only_labels)} label(s) selecionado(s)")

    # O limite por operador corta ANTES do filtro: com o default de 2, um label de linha
    # mais abaixo (MD@78) nunca entraria na lista para ser selecionado.
    limit = max(args.limit, 1000) if only_labels else args.limit

    return run_probe(
        contract,
        tuple(args.operators),
        limit,
        args.dry_run,
        args.detectable_only,
        oracle_spec,
        args.oracle_timeout,
        only_labels,
    )


if __name__ == "__main__":
    raise SystemExit(main())
