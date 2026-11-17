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

Com ``--repair static``, cada mutante passa primeiro pela trilha determinística inteira
(Slither -> catálogo -> patch mecânico, sem LLM e sem cota) e o oráculo cobra o resultado:
é o braço A2 de ``docs/experimento-generalizacao-pre-registro.md``. Um reparo só conta se
todas as regras continuarem valendo **e** nenhuma delas ficar vácua — a regra que passa por
ter deixado de ser alcançável é o reparo que reverte sempre, não um reparo.

    SOLC_VERSION=0.8.21 python3 agent/mutant_oracle.py <contrato> --spec <spec> \
        --repair static --only-from runs/<varredura>/report.json

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

from core.deterministic_patch import apply_deterministic_patches
from core.mutation import OPERATORS, mutate
from core.slither_normalizer import normalize_slither_json
from core.slither_scope import scoped_to_file, without_harness_contracts
from core.static_only import _plugin_findings, with_plugin_findings
from tools.certora_cli import verify_locally
from tools.slither_cli import SlitherRunError, run_slither_raw

# O veredito do Prover, traduzido para o vocabulário de mutação.
KILLED = "killed"        # Violated: a spec pegou o defeito
SURVIVED = "survived"    # Verified: a spec não fala sobre esse defeito
VACUOUS = "vacuous"      # Verified, mas alguma regra deixou de ser alcançável
_STATUS = {"violated": KILLED, "verified": SURVIVED, "error": "error", "timeout": "timeout"}

# Com --repair, o vocabulário é o do experimento: o mutante entra morto e a pergunta é se o
# reparo o ressuscita sem trapacear (critério de §4 do pré-registro).
REPAIRED = "repaired"
NOT_REPAIRED = "not_repaired"
_REPAIR_STATUS = {"verified": REPAIRED, "violated": NOT_REPAIRED, "error": "error", "timeout": "timeout"}


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

    status = _STATUS.get(verdict.status, verdict.status)
    if status == SURVIVED and verdict.vacuous_rules:
        # Passou sem ser exercitado: o mutante tornou a regra inalcançável (um PKR que
        # tira `payable`, por exemplo). Não é sobrevivência honesta nem morte.
        status = VACUOUS

    return {
        "label": label,
        "status": status,
        "vacuous": verdict.vacuous_rules,
        "prover_status": verdict.status,
        "rules": verdict.rules,
        "violated": verdict.violated_rules,
        "detail": verdict.detail[:300],
        "seconds": round(time.time() - started, 1),
        "log": log_path.name,
    }


def _static_repair(
    source: str, mutant_path: Path, with_plugins: bool = True
) -> tuple[str, list[dict], list[dict]]:
    """A trilha determinística inteira: Slither -> catálogo -> patch mecânico.

    Nenhuma LLM, nenhuma cota. É o braço A2 do pré-registro, e também a linha de base
    contra a qual o braço só-LLM tem de ser lido.
    """
    raw = run_slither_raw(str(mutant_path))
    if with_plugins:
        raw = with_plugin_findings(raw, _plugin_findings(str(mutant_path)))
    normalized = normalize_slither_json(
        without_harness_contracts(scoped_to_file(raw, mutant_path)), str(mutant_path)
    )
    findings = normalized["vulnerabilidades"]
    patched, patches = apply_deterministic_patches(source, findings)
    return patched, patches, findings


def _repair_and_check(
    contract: Path,
    spec: Path,
    contract_name: str,
    run_dir: Path,
    label: str,
    mutation,
    index: int,
    timeout: int,
) -> dict:
    """Aplica a trilha determinística no mutante e cobra o resultado do oráculo."""
    target = contract.with_name(f"{contract.stem}__oracle{index}.sol")
    target.write_text(mutation.source, encoding="utf-8")
    try:
        try:
            patched, patches, findings = _static_repair(mutation.source, target)
        except SlitherRunError as exc:
            return {
                "label": label, "status": "compile_error", "patches": [], "findings": 0,
                "detail": str(exc)[:200], "seconds": 0.0, "log": "",
            }
        target.write_text(patched, encoding="utf-8")

        log_path = run_dir / f"{label}__repaired.log"
        started = time.time()
        verdict = verify_locally(
            str(target), str(spec), contract_name=contract_name, timeout=timeout,
            log_path=str(log_path), cwd=str(run_dir), allow_path=str(REPO_ROOT),
        )
    finally:
        target.unlink(missing_ok=True)

    status = _REPAIR_STATUS.get(verdict.status, verdict.status)
    if status == REPAIRED and verdict.vacuous_rules:
        # Reparo degenerado: a regra passou porque deixou de ser alcançável.
        status = VACUOUS
    return {
        "label": label,
        "status": status,
        "prover_status": verdict.status,
        "patches": [item.get("type") for item in patches],
        "patched_ids": [item.get("id") for item in patches],
        "findings": len(findings),
        "violated": verdict.violated_rules,
        "vacuous": verdict.vacuous_rules,
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
    repair: str = "none",
    only_labels: set[str] | None = None,
) -> dict:
    run_dir.mkdir(parents=True, exist_ok=True)
    source = contract.read_text(encoding="utf-8")
    mutations = mutate(source, operators=operators, limit_per_operator=limit_per_operator)
    if only_labels:
        # O braço de reparo só é medido onde o mutante entra morto: fora de E1 não existe
        # critério de "reparado" (pré-registro §3).
        mutations = [m for m in mutations if m.label in only_labels or m.label.replace("@", "_at_") in only_labels]
    if max_mutants is not None:
        mutations = mutations[:max_mutants]

    baseline = _check_one(contract, spec, contract_name, run_dir, "original", None, None, timeout)
    print(f"original: {baseline['prover_status']} ({baseline['seconds']}s) — {baseline['detail'][:80]}")

    report = {
        "contract": str(contract),
        "spec": str(spec),
        "contract_name": contract_name,
        "operators": list(operators),
        "repair": repair,
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
        label = mutation.label.replace("@", "_at_")
        if repair == "static":
            result = _repair_and_check(
                contract, spec, contract_name, run_dir, label, mutation, index, timeout
            )
        else:
            result = _check_one(
                contract, spec, contract_name, run_dir, label, mutation.source, index, timeout
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
        patched = ",".join(filter(None, result.get("patches") or [])) if repair != "none" else ""
        print(
            f"[{index + 1}/{len(mutations)}] {mutation.label:<12} {mutation.operator:<4} "
            f"{result['status']:<13} {result['seconds']:>5}s "
            f"{('patch=' + patched + ' ') if patched else ''}{result['detail'][:50]}"
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
    parser.add_argument(
        "--repair",
        choices=("none", "static"),
        default="none",
        help="none: mede o mutante cru (braços A0/A1). static: aplica a trilha determinística antes (braço A2).",
    )
    parser.add_argument(
        "--only-from",
        default=None,
        help="report.json de uma varredura anterior: mede só os mutantes que o oráculo matou lá.",
    )
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

    only_labels = None
    if args.only_from:
        previous = json.loads(Path(args.only_from).read_text(encoding="utf-8"))
        only_labels = {item["label"] for item in previous["mutants"] if item["status"] == KILLED}
        print(f"Medindo só os {len(only_labels)} mutantes que o oraculo matou em {args.only_from}")

    report = run(
        contract, spec, args.contract_name or contract.stem, operators,
        args.limit_per_operator, args.max_mutants, args.timeout, run_dir,
        args.repair, only_labels,
    )
    (run_dir / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    if report.get("aborted"):
        print(f"\nAbortado: {report['aborted']}  (veja {run_dir / 'original.log'})")
        return 2

    first, second = (REPAIRED, NOT_REPAIRED) if args.repair != "none" else (KILLED, SURVIVED)
    print(f"\n{'operador':<10}{first:>14}{second:>14}{'vacuo':>7}{'erro':>7}{'timeout':>9}{'nao compila':>13}")
    for op, counts in report["by_operator"].items():
        print(f"{op:<10}{counts.get(first, 0):>14}{counts.get(second, 0):>14}"
              f"{counts.get(VACUOUS, 0):>7}{counts.get('error', 0):>7}{counts.get('timeout', 0):>9}"
              f"{counts.get('compile_error', 0):>13}")
    totals = report["totals"]
    print(f"{'total':<10}{totals.get(first, 0):>14}{totals.get(second, 0):>14}"
          f"{totals.get(VACUOUS, 0):>7}{totals.get('error', 0):>7}{totals.get('timeout', 0):>9}"
          f"{totals.get('compile_error', 0):>13}")
    print(f"\nRelatorio: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
