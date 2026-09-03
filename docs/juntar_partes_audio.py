#!/usr/bin/env python3
"""Junta varios arquivos de audio curtos (um por trecho do roteiro) no
video final, cada um encaixado no timestamp certo — sem precisar gravar
tudo numa tomada so.

A ordem e a mesma dos 11 trechos do roteiro
(docs/apresentacao-2min-roteiro-20260831.md, Parte 1):

  1. card de abertura     [0:00]
  2. Slither               [0:21]
  3. Selecao                [0:30]
  4. Spec CVL                [0:39]
  5. Certora no original      [0:48]
  6. Violacoes (FAIL)          [0:51]
  7. Diagnostico                 [1:04]
  8. patch_guard                  [1:18]
  9. Certora revalida               [1:27]
 10. Verificado (VERIFIED)           [1:30]
 11. Fechamento                        [1:40]

Uso:
    python3 docs/juntar_partes_audio.py \
        01_abertura.m4a 02_slither.m4a 03_selecao.m4a 04_spec.m4a \
        05_certora_original.m4a 06_violacoes.m4a 07_diagnostico.m4a \
        08_patch_guard.m4a 09_certora_revalida.m4a 10_verificado.m4a \
        11_fechamento.m4a \
        -o final.mp4

Cada clipe entra no timestamp do trecho correspondente; nao precisa durar
exatamente o hold do trecho — se for mais curto, sobra silencio ate o
proximo; se for mais longo, ele so continua tocando por cima da cena
seguinte (sem cortar).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _replay_content as rc  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VIDEO = os.path.join(HERE, "apresentacao-2min-tela.mp4")


def segment_starts(run_dir: str, speed: float, intro_seconds: float) -> list:
    """Replica exatamente a linha do tempo usada por gerar_video_demo.py."""
    events = rc.build_events(run_dir)
    starts = []
    t = 0.0
    if intro_seconds > 0:
        starts.append(t)
        t += intro_seconds / speed

    # o 1o evento (linha "Replay de uma execucao real...") nao tem trecho de
    # fala proprio no roteiro — some dentro do inicio da narracao do Slither.
    t += events[0].hold / speed
    for event in events[1:]:
        starts.append(t)
        t += event.hold / speed
    return starts


def ffprobe_duration(path: str) -> float:
    out = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration",
         "-of", "default=noprint_wrappers=1:nokey=1", path],
        capture_output=True, text=True, check=True,
    )
    return float(out.stdout.strip())


def resolve_starts(target_starts: list, durations: list, gap: float) -> list:
    """Empurra o inicio de cada trecho pra frente se o anterior invadiu o
    tempo dele, com uma folga minima (`gap`) entre um e o proximo. Nunca
    adianta um trecho pra antes do timestamp alvo — so atrasa quando
    necessario."""
    resolved = []
    prev_end = None
    for target, dur in zip(target_starts, durations):
        start = target if prev_end is None else max(target, prev_end + gap)
        resolved.append(start)
        prev_end = start + dur
    return resolved


def build(video: str, audio_files: list, out_path: str, speed: float,
          intro_seconds: float, run_dir: str, gap: float) -> None:
    target_starts = segment_starts(run_dir, speed, intro_seconds)
    if len(audio_files) != len(target_starts):
        raise SystemExit(
            f"Esperava {len(target_starts)} arquivos de audio (um por trecho "
            f"do roteiro), recebi {len(audio_files)}. Timestamps esperados: "
            + ", ".join(f"{s:.1f}s" for s in target_starts)
        )
    for f in audio_files:
        if not os.path.isfile(f):
            raise SystemExit(f"Arquivo nao encontrado: {f}")

    durations = [ffprobe_duration(f) for f in audio_files]
    starts = resolve_starts(target_starts, durations, gap)
    pushed = [(t, s) for t, s in zip(target_starts, starts) if s - t > 0.05]
    if pushed:
        detail = ", ".join(f"{t:.1f}s→{s:.1f}s" for t, s in pushed)
        print(f"aviso: {len(pushed)} trecho(s) atrasado(s) pra nao sobrepor "
              f"o anterior (folga {gap:.2f}s): {detail}")

    video_duration = ffprobe_duration(video)
    audio_ends = [start + dur for start, dur in zip(starts, durations)]
    out_duration = max(video_duration, *audio_ends)
    pad_needed = out_duration - video_duration
    if pad_needed > 0.05:
        print(f"aviso: audio passa {pad_needed:.1f}s do fim do video "
              f"({video_duration:.1f}s) — congelando o ultimo quadro pra nao cortar.")

    cmd = ["ffmpeg", "-y", "-i", video]
    for f in audio_files:
        cmd += ["-i", f]

    filter_parts = [
        f"[0:v]tpad=stop_mode=clone:stop_duration={max(pad_needed, 0):.3f}[v]"
    ]
    mix_labels = []
    for idx, start in enumerate(starts):
        ms = round(start * 1000)
        in_idx = idx + 1  # input 0 e o video
        filter_parts.append(f"[{in_idx}:a]adelay={ms}|{ms}[a{idx}]")
        mix_labels.append(f"[a{idx}]")
    filter_parts.append(
        f"{''.join(mix_labels)}amix=inputs={len(mix_labels)}:"
        f"duration=longest:dropout_transition=0:normalize=0,apad[aout]"
    )
    filter_complex = ";".join(filter_parts)

    cmd += [
        "-filter_complex", filter_complex,
        "-map", "[v]", "-map", "[aout]",
        "-t", f"{out_duration:.3f}",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
        "-profile:v", "baseline", "-level", "3.0", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "160k",
        out_path,
    ]
    subprocess.run(cmd, check=True)
    print(f"OK: {out_path} ({out_duration:.1f}s)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("audio_files", nargs="+", help="11 arquivos de audio, na ordem do roteiro")
    parser.add_argument("-o", "--output", default=os.path.join(HERE, "apresentacao-2min-final.mp4"))
    parser.add_argument("--video", default=DEFAULT_VIDEO)
    parser.add_argument("--speed", type=float, default=1.0,
                         help="tem que bater com o --speed usado em gerar_video_demo.py")
    parser.add_argument("--intro-seconds", type=float, default=0.0,
                         help="0 = video sem card (abertura e um clipe de camera a parte, ver juntar_abertura_camera.py)")
    parser.add_argument("--run-dir", default=rc.DEFAULT_RUN_DIR)
    parser.add_argument("--gap", type=float, default=0.2,
                         help="folga minima (s) entre o fim de um trecho e o inicio do proximo")
    args = parser.parse_args()
    build(args.video, args.audio_files, args.output, args.speed,
          args.intro_seconds, os.path.abspath(args.run_dir), args.gap)


if __name__ == "__main__":
    main()
