#!/usr/bin/env python3
"""Gera o video da demo com a duracao de cada cena batendo exatamente com
o audio gravado pra ela — sem sobreposicao entre trechos, sem deriva de
sincronia, sem precisar congelar o ultimo quadro no final. Substitui o
combo gerar_video_demo.py + juntar_partes_audio.py quando voce ja tem os
10 audios gravados: aqui a cena dura o tempo que a narracao precisar, em
vez do audio ter que caber no tempo fixo da cena.

Uso:
    python3 docs/gerar_video_sincronizado.py \
        audio1.ogg audio2.ogg audio3.ogg audio4.ogg audio5.ogg \
        audio6.ogg audio7.ogg audio8.ogg audio9.ogg audio10.ogg \
        -o docs/demo_com_audio.mp4

Ordem dos 10 audios = Parte 1 do roteiro (Slither, Selecao, Spec CVL,
Certora original, Violacoes, Diagnostico, patch_guard, Certora revalida,
Verificado, Fechamento).
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _replay_content as rc  # noqa: E402
from gerar_video_demo import (  # noqa: E402
    FONT_BOLD, FONT_REGULAR, FONT_SIZE, render_frame,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def ffprobe_duration(path: str) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", path],
        capture_output=True, text=True, check=True,
    )
    return float(out.stdout.strip())


def build(audio_files: list, out_path: str, gap: float, run_dir: str, fps: int) -> None:
    events = rc.build_events(run_dir)
    demo_events = events[1:]  # os 10 trechos narraveis (pula a linha "Replay de...")
    if len(audio_files) != len(demo_events):
        raise SystemExit(
            f"Esperava {len(demo_events)} arquivos de audio (um por trecho "
            f"do roteiro), recebi {len(audio_files)}."
        )
    for f in audio_files:
        if not os.path.isfile(f):
            raise SystemExit(f"Arquivo nao encontrado: {f}")

    durations = [ffprobe_duration(f) for f in audio_files]
    font_r = ImageFont.truetype(FONT_REGULAR, FONT_SIZE)
    font_b = ImageFont.truetype(FONT_BOLD, FONT_SIZE)

    workdir = tempfile.mkdtemp(prefix="defivault_sync_")
    try:
        # silencio de folga entre cenas, gerado uma vez e reaproveitado
        # (caminho absoluto, pra nao depender de como o concat demuxer
        # resolve relativos).
        silence_path = os.path.join(workdir, "silence.wav")
        if gap > 0:
            subprocess.run(
                ["ffmpeg", "-y", "-f", "lavfi",
                 "-i", f"anullsrc=r=44100:cl=mono:d={gap:.3f}",
                 silence_path],
                check=True, capture_output=True,
            )

        frames_txt = os.path.join(workdir, "frames.txt")
        silence_txt = os.path.join(workdir, "silence.txt")
        scrollback: list = list(events[0].lines)  # a linha "Replay de..." abre a 1a cena

        with open(frames_txt, "w", encoding="utf-8") as ff, \
             open(silence_txt, "w", encoding="utf-8") as sf:
            last_frame = None
            for i, (event, dur) in enumerate(zip(demo_events, durations)):
                scrollback.extend(event.lines)
                frame_path = os.path.join(workdir, f"frame_{i:03d}.png")
                render_frame(scrollback, font_r, font_b, frame_path)
                hold = dur + gap
                ff.write(f"file '{frame_path}'\nduration {hold:.3f}\n")
                sf.write(f"file '{os.path.abspath(audio_files[i])}'\n")
                if gap > 0:
                    sf.write(f"file '{silence_path}'\n")
                last_frame = frame_path
            if last_frame:
                ff.write(f"file '{last_frame}'\n")

        video_path = os.path.join(workdir, "video.mp4")
        subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", frames_txt,
             "-vf", f"fps={fps},format=yuv420p",
             "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
             "-profile:v", "baseline", "-level", "3.0",
             video_path],
            check=True,
        )

        audio_path = os.path.join(workdir, "audio.m4a")
        subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", silence_txt,
             "-c:a", "aac", "-b:a", "160k", audio_path],
            check=True, cwd=workdir,
        )

        subprocess.run(
            ["ffmpeg", "-y", "-i", video_path, "-i", audio_path,
             "-map", "0:v", "-map", "1:a", "-c", "copy",
             "-shortest", out_path],
            check=True,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    total = sum(durations) + gap * len(durations)
    print(f"OK: {out_path} (~{total:.1f}s, cada cena dura audio+{gap:.1f}s de folga)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("audio_files", nargs="+")
    parser.add_argument("-o", "--output",
                         default=os.path.join(HERE, "demo_com_audio.mp4"))
    parser.add_argument("--gap", type=float, default=0.2,
                         help="folga (s) no fim de cada cena antes de trocar pra proxima")
    parser.add_argument("--run-dir", default=rc.DEFAULT_RUN_DIR)
    parser.add_argument("--fps", type=int, default=8)
    args = parser.parse_args()
    build(args.audio_files, args.output, args.gap, os.path.abspath(args.run_dir), args.fps)


if __name__ == "__main__":
    main()
