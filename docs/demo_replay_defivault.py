#!/usr/bin/env python3
"""Replay de uma execucao REAL do pipeline no DeFiVault, para rodar em
segundo plano (outro terminal/tela) enquanto voce fala nos slides.

Nao chama Slither, LLM nem Certora — sem rede, sem credencial, sem risco de
travar no meio da apresentacao. Todo o conteudo impresso vem dos artefatos
reais salvos em runs/20260524_232148_DeFiVault/ (5/5 vulnerabilidades
corrigidas em 1 iteracao) — a mesma fonte usada por gerar_video_demo.py
(ver docs/_replay_content.py).

Uso:
    python3 docs/demo_replay_defivault.py            # ritmo normal (~88s)
    python3 docs/demo_replay_defivault.py --speed 2  # 2x mais rapido
"""
from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _replay_content as rc  # noqa: E402

ANSI = {
    "default": "\033[0m",
    "dim": "\033[2m",
    "header": "\033[1m\033[96m",
    "rule": "\033[2m",
    "id": "\033[93m",
    "fail": "\033[91m",
    "pass": "\033[92m",
    "final": "\033[1m\033[92m",
}
RESET = "\033[0m"


def run(run_dir: str, speed: float) -> None:
    events = rc.build_events(run_dir)
    for event in events:
        print()
        for text, style in event.lines:
            print(f"{ANSI.get(style, '')}{text}{RESET}")
        time.sleep(max(event.hold, 0) / speed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--speed", type=float, default=1.0,
                         help="multiplicador de velocidade (2 = 2x mais rapido)")
    parser.add_argument("--run-dir", default=rc.DEFAULT_RUN_DIR,
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
