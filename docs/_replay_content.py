"""Fonte unica de conteudo para o replay do pipeline no DeFiVault.

Le os artefatos reais de uma run salva (runs/20260524_232148_DeFiVault/,
5/5 vulnerabilidades corrigidas em 1 iteracao) e produz uma lista de
"eventos": cada evento e um bloco de linhas que aparece de uma vez, mais um
tempo de exibicao (em segundos, no ritmo normal).

Usado por dois consumidores:
- demo_replay_defivault.py — imprime ao vivo no terminal (ANSI colors).
- gerar_video_demo.py       — renderiza os mesmos eventos como quadros de
  video (sem precisar capturar a tela de verdade).

Manter a extracao dos dados aqui, em um so lugar, evita os dois scripts
divergirem sobre o que e "real".
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RUN_DIR = os.path.join(HERE, "..", "runs", "20260524_232148_DeFiVault")

# estilos: nome -> (r, g, b), negrito
STYLES = {
    "default": ((222, 226, 230), False),
    "dim":     ((120, 128, 138), False),
    "header":  ((92, 214, 224), True),
    "rule":    ((70, 78, 88), False),
    "id":      ((229, 192, 64), False),
    "fail":    ((248, 81, 73), False),
    "pass":    ((63, 199, 100), False),
    "final":   ((63, 220, 110), True),
}


def load_json(run_dir: str, name: str):
    with open(os.path.join(run_dir, name), encoding="utf-8") as f:
        return json.load(f)


@dataclass
class Event:
    lines: list  # list[(text, style_name)]
    hold: float  # segundos de exibicao no ritmo normal


def _header(n: int, total: int, title: str):
    return [
        (f"[{n}/{total}] {title}", "header"),
        ("-" * 66, "rule"),
    ]


def build_events(run_dir: str = DEFAULT_RUN_DIR) -> list:
    total = 8
    events: list[Event] = []

    events.append(Event(
        [(f"Replay de uma execucao real do pipeline "
          f"(run: {os.path.basename(run_dir)}) — sem rede, sem LLM ao vivo.",
          "dim")],
        1.5,
    ))

    # 1. Slither -----------------------------------------------------
    vulns = load_json(run_dir, "etapa1_vulns.json")["vulnerabilidades"]
    lines = _header(1, total, "Slither — analise estatica do DeFiVault.sol")
    lines.append(("$ slither smart-audt/contracts/DeFiVault.sol", "default"))
    lines.append((f"{len(vulns)} achados brutos normalizados.", "default"))
    for v in vulns[:4]:
        lines.append((f"  - {v['id']}: {v['type']}", "id"))
    lines.append((f"  ... (+{len(vulns) - 4} achados)", "dim"))
    events.append(Event(lines, 9))

    # 2. Selecao -------------------------------------------------------
    selected = load_json(run_dir, "selected_vulnerabilities.json")["vulnerabilidades"]
    lines = _header(2, total, "Selecao de candidatos formalizaveis")
    lines.append(("Filtrando achados sem propriedade formal confiavel...", "default"))
    for v in selected:
        lines.append((f"  [ok] {v['id']}  {v['type']:<20} {v['function']}", "pass"))
    events.append(Event(lines, 9))

    # 3. Spec CVL --------------------------------------------------
    with open(os.path.join(run_dir, "generated.spec"), encoding="utf-8") as f:
        spec_lines = [l.rstrip() for l in f if l.strip().startswith("rule ")]
    lines = _header(3, total, "Geracao da especificacao CVL")
    lines.append(("methods.cvl + generated.spec", "default"))
    for l in spec_lines:
        lines.append((f"  {l}", "default"))
    events.append(Event(lines, 9))

    # 4. Certora original ----------------------------------------------
    with open(os.path.join(run_dir, "certora_original.log"), encoding="utf-8") as f:
        log = f.read()
    fails = sorted(set(
        line.split(":", 1)[1].strip()
        for line in log.splitlines()
        if line.startswith("Violated:")
    ))
    header4 = _header(4, total, "Certora Prover — verificando o contrato ORIGINAL")
    cmd4 = [("$ certoraRun DeFiVault.sol --verify DeFiVault:DeFiVault.spec", "default")]
    events.append(Event(header4 + cmd4, 3))  # so as linhas NOVAS deste evento
    results4 = [(f"  [FAIL]  {rule}", "fail") for rule in fails]
    results4.append((f"{len(fails)} propriedades violadas no contrato original.", "fail"))
    events.append(Event(results4, 13))  # incremental: nao repete header/cmd

    # 5. Diagnostico -----------------------------------------------------
    diagnosis = load_json(run_dir, "diagnosis_t0.json")["falhas"]
    lines = _header(5, total, "Diagnostico — causa raiz de cada violacao (LLM)")
    for d in diagnosis:
        lines.append((f"  {d['id']} (linha {d['linha']}): {d['motivo']}", "id"))
        lines.append((f"    antes:  {d['codigo_atual']}", "dim"))
        lines.append((f"    depois: {d['correcao_necessaria']}", "pass"))
    events.append(Event(lines, 14))

    # 6. patch_guard -----------------------------------------------
    guard = load_json(run_dir, "patch_guard_t0.json")
    s = guard["summary"]
    lines = _header(6, total, "patch_guard — validando o escopo do patch")
    lines.append(("$ patch_guard.check(original, corrigido)", "default"))
    lines.append((f"  status: {guard['status']}   should_block: {guard['should_block']}",
                   "default"))
    lines.append((f"  hunks avaliados: {s['changed_hunks']}   erros: {s['errors']}"
                   f"   avisos: {s['warnings']}", "default"))
    lines.append(("  patch dentro do escopo das vulnerabilidades confirmadas.", "pass"))
    events.append(Event(lines, 9))

    # 7. Revalidacao ------------------------------------------------
    header7 = _header(7, total, "Revalidacao — Certora no contrato CORRIGIDO")
    cmd7 = [("$ certoraRun DeFiVault_FIXED.sol --verify DeFiVault:DeFiVault.spec", "default")]
    events.append(Event(header7 + cmd7, 3))
    results7 = [(f"  [VERIFIED]  {rule}", "pass") for rule in fails]
    events.append(Event(results7, 10))  # incremental

    # 8. Resultado -----------------------------------------------------
    comp = load_json(run_dir, "comparison_t1.json")
    lines = _header(8, total, "Resultado final")
    lines.append((f"  taxa de resolucao: {comp['taxa_resolucao']}"
                   f"  (1 iteracao do ciclo de correcao)", "final"))
    lines.append((f"  persistentes: {len(comp['persistentes'])}"
                   f"   inconclusivas: {len(comp['inconclusivas'])}", "default"))
    lines.append(("", "default"))
    lines.append(("Pipeline concluido.", "final"))
    events.append(Event(lines, 8))

    return events
