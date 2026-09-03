#!/usr/bin/env python3
"""Gera um .srt com o timing exato de cada trecho (abertura + 10 cenas da
demo) e queima (burn-in) no video final — texto embutido na imagem, funciona
em qualquer player sem precisar de faixa de legenda separada.

Uso:
    python3 docs/queimar_legendas.py \
        docs/apresentacao-2min-final.mp4 \
        SEU_INTRO.mp4 \
        audio1.ogg audio2.ogg ... audio10.ogg \
        -o docs/apresentacao-2min-final-legendado.mp4
"""
from __future__ import annotations

import argparse
import os
import subprocess

INTRO_TEXT = [
    "Olá! Meu nome é Gustavo Ferreira Leite de Barros, sou estudante do "
    "Centro de Informática da Universidade Federal de Pernambuco.",
    "Minha pesquisa investiga como tornar contratos inteligentes mais "
    "seguros combinando inteligência artificial e verificação formal.",
    "Em vez de só explicar, vou mostrar a ferramenta rodando de verdade "
    "em um contrato real.",
]

DEMO_TEXT = [
    "Primeiro, o Slither examina o contrato inteiro e aponta os pontos "
    "suspeitos: controle de acesso, endereços não validados, chamadas "
    "externas arriscadas.",
    "Nem todo achado vira correção. Só os que dá pra provar "
    "matematicamente passam pra próxima etapa — cinco, neste contrato.",
    "Essas cinco propriedades viram uma especificação formal, na "
    "linguagem CVL, que o Certora Prover consegue verificar.",
    "Agora o Certora Prover analisa o contrato original.",
    "E aqui está: as cinco propriedades realmente falham. Não é "
    "suposição — é prova matemática de que o contrato tem essas brechas.",
    "Com a violação confirmada, a IA entra: lê a causa raiz de cada uma "
    "e propõe a correção exata — trocar tx.origin por msg.sender, "
    "validar endereço zero, e assim por diante.",
    "Antes de aceitar, um guardrail confere se o patch mexeu só no "
    "necessário. Nada de reescrever o contrato inteiro.",
    "O contrato corrigido volta pro Certora.",
    "Dessa vez, as cinco propriedades passam. Verificadas "
    "matematicamente, não só testadas.",
    "Cinco de cinco corrigidas, em uma única iteração. Essa é a "
    "ferramenta: ela gera a correção e prova que funciona. Obrigado!",
]


def ffprobe_duration(path: str) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", path],
        capture_output=True, text=True, check=True,
    )
    return float(out.stdout.strip())


def srt_timestamp(seconds: float) -> str:
    ms = round(seconds * 1000)
    h, ms = divmod(ms, 3_600_000)
    m, ms = divmod(ms, 60_000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def build_srt(intro_video: str, audio_files: list, gap: float, srt_path: str) -> None:
    entries = []  # (start, end, text)

    intro_dur = ffprobe_duration(intro_video)
    weights = [len(t) for t in INTRO_TEXT]
    total_w = sum(weights)
    t = 0.0
    for text, w in zip(INTRO_TEXT, weights):
        dur = intro_dur * w / total_w
        entries.append((t, t + dur, text))
        t += dur

    t = intro_dur
    for text, f in zip(DEMO_TEXT, audio_files):
        dur = ffprobe_duration(f)
        entries.append((t, t + dur, text))
        t += dur + gap

    with open(srt_path, "w", encoding="utf-8") as fh:
        for i, (start, end, text) in enumerate(entries, 1):
            fh.write(f"{i}\n{srt_timestamp(start)} --> {srt_timestamp(end)}\n{text}\n\n")


def burn_in(video: str, srt_path: str, out_path: str) -> None:
    # caminho do .srt precisa ser escapado pro filtro subtitles= do ffmpeg
    escaped = srt_path.replace("\\", "\\\\").replace(":", "\\:")
    style = (
        "FontName=DejaVu Sans,FontSize=13,PrimaryColour=&H00FFFFFF,"
        "OutlineColour=&H00000000,BorderStyle=1,Outline=2,Shadow=0,"
        "MarginV=30"
    )
    subprocess.run(
        [
            "ffmpeg", "-y", "-i", video,
            "-vf", f"subtitles={escaped}:force_style='{style}'",
            "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
            "-profile:v", "baseline", "-level", "3.0", "-pix_fmt", "yuv420p",
            "-c:a", "copy",
            out_path,
        ],
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("video", help="video final ja montado (abertura + demo)")
    parser.add_argument("intro_video", help="seu clipe de camera (so pra saber a duracao da abertura)")
    parser.add_argument("audio_files", nargs=10, help="os 10 audios da demo, na mesma ordem de sempre")
    parser.add_argument("-o", "--output",
                         default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               "apresentacao-2min-final-legendado.mp4"))
    parser.add_argument("--gap", type=float, default=0.2)
    parser.add_argument("--srt", default=None, help="onde salvar o .srt (default: ao lado da saida)")
    args = parser.parse_args()

    srt_path = args.srt or (os.path.splitext(args.output)[0] + ".srt")
    build_srt(args.intro_video, args.audio_files, args.gap, srt_path)
    print(f"OK: {srt_path}")
    burn_in(args.video, srt_path, args.output)
    print(f"OK: {args.output}")


if __name__ == "__main__":
    main()
