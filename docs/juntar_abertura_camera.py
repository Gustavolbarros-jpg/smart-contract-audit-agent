#!/usr/bin/env python3
"""Concatena seu clipe de camera (abertura, com audio proprio) na frente
do video do terminal (ja com a narracao dos outros 10 trechos colada).

Passo a passo completo:

1. Grave 10 audios curtos (Slither, Selecao, Spec CVL, Certora original,
   Violacoes, Diagnostico, patch_guard, Certora revalida, Verificado,
   Fechamento — ver docs/apresentacao-2min-roteiro-20260831.md).
2. Junte-os no video do terminal (sem card, 88.5s):
     python3 docs/juntar_partes_audio.py --intro-seconds 0 \
         parte1.m4a parte2.m4a ... parte10.m4a -o demo_com_audio.mp4
3. Grave a si mesmo (webcam/celular, com audio junto) falando a
   introducao — vira 1 arquivo de video so.
4. python3 docs/juntar_abertura_camera.py abertura.mp4 demo_com_audio.mp4 -o final.mp4

Os dois clipes podem ter resolucao/fps/codec diferentes — este script
normaliza os dois pro mesmo formato (1280x720, 8fps, mesma taxa de audio)
antes de concatenar, entao nao precisa se preocupar em gravar "do jeito
certo".
"""
from __future__ import annotations

import argparse
import os
import subprocess

WIDTH, HEIGHT, FPS = 1280, 720, 8


def build(intro: str, demo: str, out_path: str) -> None:
    for f in (intro, demo):
        if not os.path.isfile(f):
            raise SystemExit(f"Arquivo nao encontrado: {f}")

    # escala mantendo proporcao + preenche com preto (letterbox/pillarbox)
    # ate 1280x720, pra funcionar com qualquer orientacao/resolucao de
    # celular ou webcam.
    scale_pad = (
        f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,"
        f"pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2,setsar=1,fps={FPS}"
    )
    filter_complex = (
        f"[0:v]{scale_pad}[v0];"
        f"[1:v]{scale_pad}[v1];"
        f"[0:a]aformat=sample_rates=44100:channel_layouts=mono[a0];"
        f"[1:a]aformat=sample_rates=44100:channel_layouts=mono[a1];"
        f"[v0][a0][v1][a1]concat=n=2:v=1:a=1[v][a]"
    )

    cmd = [
        "ffmpeg", "-y",
        "-i", intro, "-i", demo,
        "-filter_complex", filter_complex,
        "-map", "[v]", "-map", "[a]",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
        "-profile:v", "baseline", "-level", "3.0", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "160k",
        out_path,
    ]
    subprocess.run(cmd, check=True)
    print(f"OK: {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("intro", help="seu clipe de camera (video+audio), a abertura")
    parser.add_argument("demo", help="video do terminal ja com a narracao colada (saida de juntar_partes_audio.py)")
    parser.add_argument("-o", "--output",
                         default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               "apresentacao-2min-final.mp4"))
    args = parser.parse_args()
    build(args.intro, args.demo, args.output)


if __name__ == "__main__":
    main()
