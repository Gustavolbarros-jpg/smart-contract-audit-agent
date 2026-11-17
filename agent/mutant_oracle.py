"""Quais defeitos injetados uma spec CVL congelada pega, sem job na nuvem e sem cota?

Para cada mutante de um contrato, roda o verificador local do Certora
(``--compilation_steps_only``) contra uma spec escrita a partir do ORIGINAL e faz uma única
pergunta: a regra continua valendo? Se não, o mutante foi **morto** pela spec.

Isto existe porque ``mutant_detection.py`` mediu que 36 dos 46 mutantes do DeFiVault não
produzem nenhum achado no Slither — AOR, BOR, UOR, EED e PKR têm detectabilidade zero. Um
defeito que o instrumento de medição não vê nunca chega ao estágio de reparo, então o
benchmark não cobra o agente por ele. O oráculo formal muda isso de graça: o veredito vem
do ``emv.jar`` local, em segundos, sem enviar job.

    SOLC_VERSION=0.8.21 python3 agent/mutant_oracle.py \
        smart-audt/contracts/DeFiVault_FIXED.sol \
        --spec runs/oracle_validation_20261116/_oracle_check.spec \
        --contract-name DeFiVault

O relatório vai para ``runs/<timestamp>_oracle_<Contrato>/``: um log do Prover por mutante,
o diff de cada mutante e um ``report.json``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from core.mutation import OPERATORS, mutate
from tools.certora_cli import verify_locally

# O veredito do Prover, traduzido para o vocabulário de mutação.
KILLED = "killed"        # Violated: a spec pegou o defeito
SURVIVED = "survived"    # Verified: a spec não fala sobre esse defeito
_STATUS = {"violated": KILLED, "verified": SURVIVED, "error": "error", "timeout": "timeout"}


def _inside_repo(path: Path) -> bool:
    # O Prover recusa fontes fora dos diretórios permitidos, e o permitido aqui é o repo.
    return REPO_ROOT == path or REPO_ROOT in path.parents


def _check_one(
    contract: Path,
    spec: Path,
    contract_name: str,
    run_dir: Path,
    label: str,
    source: str | None,
    index: int | None,
    timeout: int,
) -> dict:
    """Verifica o original (``source is None``) ou um mutante escrito ao lado dele."""
    target = contract
    if source is not None:
        # Ao lado do original, para os imports relativos continuarem resolvendo, e com um
        # nome por mutante, para dois workers nunca dividirem o mesmo arquivo.
        target = contract.with_name(f"{contract.stem}__oracle{index}.sol")
        target.write_text(source, encoding="utf-8")

    log_path = run_dir / f"{label}.log"
    started = time.time()
    try:
        verdict = verify_locally(
            str(target),
            str(spec),
            contract_name=contract_name,
            timeout=timeout,
            log_path=str(log_path),
            cwd=str(run_dir),
            allow_path=str(REPO_ROOT),
        )
    finally:
        if source is not None:
            target.unlink(missing_ok=True)

    return {
        "label": label,
        "status": _STATUS.get(verdict.status, verdict.status),
        "prover_status": verdict.status,
        "rules": verdict.rules,
        "violated": verdict.violated_rules,
        "detail": verdict.detail[:300],
        "seconds": round(time.time() - started, 1),
        "log": log_path.name,
    }


def _diff_line(mutation) -> str:
    return (
        f"{mutation.label} ({mutation.operator}) linha {mutation.line}\n"
        f"- {mutation.original.strip()}\n"
        f"+ {mutation.mutated.strip()}\n"
    )


def run(
    contract: Path,
    spec: Path,
    contract_name: str,
    operators: tuple[str, ...],
    limit_per_operator: int,
    max_mutants: int | None,
    timeout: int,
    run_dir: Path,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    source = contract.read_text(encoding="utf-8")
    mutations = mutate(source, operators=operators, limit_per_operator=limit_per_operator)
    if max_mutants is not None:
        mutations = mutations[:max_mutants]

    baseline = _check_one(contract, spec, contract_name, run_dir, "original", None, None, timeout)
    print(f"original: {baseline['prover_status']} ({baseline['seconds']}s) — {baseline['detail'][:80]}")

    report = {
        "contract": str(contract),
        "spec": str(spec),
        "contract_name": contract_name,
        "operators": list(operators),
        "baseline": baseline,
        "mutants": [],
        "started": datetime.now().isoformat(timespec="seconds"),
    }
    if baseline["prover_status"] != "verified":
        # Um oráculo cuja linha de base não passa não distingue nada: qualquer mutante
        # apareceria morto pelo mesmo motivo que o original.
        report["aborted"] = "a spec não verifica no contrato original"
        return report

    diffs = run_dir / "mutants.diff"
    for index, mutation in enumerate(mutations):
        result = _check_one(
            contract, spec, contract_name, run_dir, mutation.label.replace("@", "_at_"),
            mutation.source, index, timeout,
        )
        result.update(
            operator=mutation.operator,
            line=mutation.line,
            expected_class=mutation.expected_class,
            description=mutation.description,
        )
        report["mutants"].append(result)
        with diffs.open("a", encoding="utf-8") as handle:
            handle.write(_diff_line(mutation))
        print(
            f"[{index + 1}/{len(mutations)}] {mutation.label:<12} {mutation.operator:<4} "
            f"{result['status']:<9} {result['seconds']:>5}s {result['detail'][:60]}"
        )

    by_operator: dict[str, Counter] = defaultdict(Counter)
    for item in report["mutants"]:
        by_operator[item["operator"]][item["status"]] += 1
    report["by_operator"] = {op: dict(by_operator[op]) for op in OPERATORS if op in by_operator}
    report["totals"] = dict(sum(by_operator.values(), Counter()))
    report["finished"] = datetime.now().isoformat(timespec="seconds")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("contract")
    parser.add_argument("--spec", required=True, help="Spec CVL escrita a partir do original.")
    parser.add_argument("--contract-name", default=None, help="Nome do contrato dentro do .sol.")
    parser.add_argument("--operators", default=",".join(OPERATORS))
    parser.add_argument("--limit-per-operator", type=int, default=1000)
    parser.add_argument("--max-mutants", type=int, default=None)
    parser.add_argument("--timeout", type=int, default=300, help="Segundos por verificação.")
    parser.add_argument("--run-dir", default=None, help="Padrão: runs/<timestamp>_oracle_<Contrato>.")
    args = parser.parse_args(argv)

    contract = Path(args.contract).resolve()
    spec = Path(args.spec).resolve()
    if not contract.is_file():
        print(f"Contrato nao encontrado: {contract}")
        return 1
    if not spec.is_file():
        print(f"Spec nao encontrada: {spec}")
        return 1
    for path in (contract, spec):
        if not _inside_repo(path):
            print(f"Fora do repo, o Prover vai recusar: {path}")
            return 1

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.run_dir).resolve() if args.run_dir else REPO_ROOT / "runs" / f"{stamp}_oracle_{contract.stem}"
    operators = tuple(op.strip().upper() for op in args.operators.split(",") if op.strip())

    report = run(
        contract, spec, args.contract_name or contract.stem, operators,
        args.limit_per_operator, args.max_mutants, args.timeout, run_dir,
    )
    (run_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    if report.get("aborted"):
        print(f"\nAbortado: {report['aborted']}  (veja {run_dir / 'original.log'})")
        return 2

    print(f"\n{'operador':<10}{'mortos':>8}{'sobrevivem':>12}{'erro':>7}{'timeout':>9}")
    for op, counts in report["by_operator"].items():
        print(f"{op:<10}{counts.get(KILLED, 0):>8}{counts.get(SURVIVED, 0):>12}"
              f"{counts.get('error', 0):>7}{counts.get('timeout', 0):>9}")
    totals = report["totals"]
    print(f"{'total':<10}{totals.get(KILLED, 0):>8}{totals.get(SURVIVED, 0):>12}"
          f"{totals.get('error', 0):>7}{totals.get('timeout', 0):>9}")
    print(f"\nRelatorio: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
