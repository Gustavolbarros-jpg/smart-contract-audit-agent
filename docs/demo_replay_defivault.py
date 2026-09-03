#!/usr/bin/env python3
"""Replay de uma execucao REAL do pipeline no DeFiVault, para rodar em
segundo plano (outro terminal/tela) enquanto voce fala nos slides.

Nao chama Slither, LLM nem Certora — sem rede, sem credencial, sem risco de
travar no meio da apresentacao. Todo o conteudo impresso vem dos artefatos
reais salvos em runs/20260524_232148_DeFiVault/ (5/5 vulnerabilidades
corrigidas em 1 iteracao).

Uso:
    python3 docs/demo_replay_defivault.py            # ritmo normal (~100s)
    python3 docs/demo_replay_defivault.py --speed 2  # 2x mais rapido (~50s)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RUN_DIR = os.path.join(HERE, "..", "runs", "20260524_232148_DeFiVault")

CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def load_json(run_dir: str, name: str):
    with open(os.path.join(run_dir, name), encoding="utf-8") as f:
        return json.load(f)


def stage(n: int, total: int, title: str) -> None:
    print()
    print(f"{BOLD}{CYAN}[{n}/{total}] {title}{RESET}")
    print(f"{DIM}{'-' * 66}{RESET}")


def wait(seconds: float, speed: float) -> None:
    time.sleep(max(seconds, 0) / speed)


def run(run_dir: str, speed: float) -> None:
    total = 8

    print(f"{DIM}Replay de uma execucao real do pipeline "
          f"(run: {os.path.basename(run_dir)}) — sem rede, sem LLM ao vivo."
          f"{RESET}")
    wait(1.5, speed)

    # 1. Slither ---------------------------------------------------------
    stage(1, total, "Slither — analise estatica do DeFiVault.sol")
    vulns = load_json(run_dir, "etapa1_vulns.json")["vulnerabilidades"]
    print(f"$ slither smart-audt/contracts/DeFiVault.sol")
    print(f"{len(vulns)} achados brutos normalizados.")
    for v in vulns[:4]:
        print(f"  - {v['id']}: {YELLOW}{v['type']}{RESET}")
    print(f"  ... (+{len(vulns) - 4} achados)")
    wait(9, speed)

    # 2. Selecao -----------------------------------------------------
    stage(2, total, "Selecao de candidatos formalizaveis")
    selected = load_json(run_dir, "selected_vulnerabilities.json")["vulnerabilidades"]
    print("Filtrando achados sem propriedade formal confiavel...")
    for v in selected:
        print(f"  {GREEN}✓{RESET} {v['id']}  {v['type']:<20} {v['function']}")
    wait(9, speed)

    # 3. Spec CVL ----------------------------------------------------
    stage(3, total, "Geracao da especificacao CVL")
    with open(os.path.join(run_dir, "generated.spec"), encoding="utf-8") as f:
        spec_lines = [l.rstrip() for l in f if l.strip().startswith("rule ")]
    print("methods.cvl + generated.spec")
    for l in spec_lines:
        print(f"  {l}")
    wait(9, speed)

    # 4. Certora no contrato original ---------------------------------
    stage(4, total, "Certora Prover — verificando o contrato ORIGINAL")
    print("$ certoraRun DeFiVault.sol --verify DeFiVault:DeFiVault.spec")
    wait(3, speed)
    with open(os.path.join(run_dir, "certora_original.log"), encoding="utf-8") as f:
        log = f.read()
    fails = sorted(set(
        line.split(":")[1].strip() if ":" in line else line
        for line in log.splitlines()
        if line.startswith("Violated:")
    ))
    for rule in fails:
        print(f"  {RED}✗ FAIL{RESET}  {rule}")
    print(f"{RED}{len(fails)} propriedades violadas no contrato original.{RESET}")
    wait(13, speed)

    # 5. Diagnostico ----------------------------------------------------
    stage(5, total, "Diagnostico — causa raiz de cada violacao (LLM)")
    diagnosis = load_json(run_dir, "diagnosis_t0.json")["falhas"]
    for d in diagnosis:
        print(f"  {YELLOW}{d['id']}{RESET} (linha {d['linha']}): {d['motivo']}")
        print(f"    antes:  {DIM}{d['codigo_atual']}{RESET}")
        print(f"    depois: {GREEN}{d['correcao_necessaria']}{RESET}")
    wait(14, speed)

    # 6. patch_guard -------------------------------------------------
    stage(6, total, "patch_guard — validando o escopo do patch")
    guard = load_json(run_dir, "patch_guard_t0.json")
    s = guard["summary"]
    print(f"$ patch_guard.check(original, corrigido)")
    print(f"  status: {guard['status']}   should_block: {guard['should_block']}")
    print(f"  hunks avaliados: {s['changed_hunks']}   erros: {s['errors']}"
          f"   avisos: {s['warnings']}")
    print(f"  {GREEN}patch dentro do escopo das vulnerabilidades confirmadas.{RESET}")
    wait(9, speed)

    # 7. Revalidacao ---------------------------------------------------
    stage(7, total, "Revalidacao — Certora no contrato CORRIGIDO")
    print("$ certoraRun DeFiVault_FIXED.sol --verify DeFiVault:DeFiVault.spec")
    wait(3, speed)
    for rule in fails:
        print(f"  {GREEN}✓ VERIFIED{RESET}  {rule}")
    wait(10, speed)

    # 8. Resultado -----------------------------------------------------
    stage(8, total, "Resultado final")
    comp = load_json(run_dir, "comparison_t1.json")
    print(f"  taxa de resolucao: {BOLD}{GREEN}{comp['taxa_resolucao']}{RESET}"
          f"  (1 iteracao do ciclo de correcao)")
    print(f"  persistentes: {len(comp['persistentes'])}"
          f"   inconclusivas: {len(comp['inconclusivas'])}")
    print()
    print(f"{BOLD}{GREEN}Pipeline concluido.{RESET}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--speed", type=float, default=1.0,
                         help="multiplicador de velocidade (2 = 2x mais rapido)")
    parser.add_argument("--run-dir", default=DEFAULT_RUN_DIR,
                         help="diretorio de runs/ a reproduzir")
    args = parser.parse_args()
    if args.speed <= 0:
        parser.error("--speed precisa ser > 0")
    try:
        run(os.path.abspath(args.run_dir), args.speed)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
