#!/usr/bin/env python3
"""Gera um video (sem audio) do replay do pipeline no DeFiVault, sem
precisar capturar a tela de verdade — renderiza cada quadro a partir dos
mesmos dados reais que docs/demo_replay_defivault.py imprime no terminal
(ver docs/_replay_content.py).

Uso:
    python3 docs/gerar_video_demo.py
    python3 docs/gerar_video_demo.py --speed 2       # 2x mais rapido
    python3 docs/gerar_video_demo.py -o video.mp4

Depois, grave sua narracao separadamente e junte com:
    docs/juntar_video_audio.sh docs/apresentacao-2min-tela.mp4 audio.m4a final.mp4
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _replay_content as rc  # noqa: E402

WIDTH, HEIGHT = 1280, 720
TOP_BAR = 44
PAD_X = 28
PAD_TOP = 18
LINE_HEIGHT = 25
FONT_SIZE = 17
BG = (14, 16, 20)
BAR_BG = (24, 27, 33)
DOT_COLORS = [(248, 81, 73), (251, 189, 63), (63, 199, 100)]
TITLE_COLOR = (150, 158, 168)

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
FONT_REGULAR = os.path.join(FONT_DIR, "DejaVuSansMono.ttf")
FONT_BOLD = os.path.join(FONT_DIR, "DejaVuSansMono-Bold.ttf")


def wrap_line(text: str, font: ImageFont.FreeTypeFont, max_width: int) -> list:
    if font.getlength(text) <= max_width:
        return [text]
    words = text.split(" ")
    lines, cur = [], ""
    for w in words:
        trial = (cur + " " + w).strip()
        if font.getlength(trial) <= max_width or not cur:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def render_frame(scrollback: list, font_r, font_b, path: str) -> None:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, WIDTH, TOP_BAR], fill=BAR_BG)
    for i, color in enumerate(DOT_COLORS):
        cx = 24 + i * 22
        draw.ellipse([cx - 6, TOP_BAR // 2 - 6, cx + 6, TOP_BAR // 2 + 6], fill=color)
    draw.text((WIDTH // 2, TOP_BAR // 2), "demo_replay_defivault.py",
               font=font_r, fill=TITLE_COLOR, anchor="mm")

    max_width = WIDTH - 2 * PAD_X
    wrapped: list = []
    for text, style in scrollback:
        color, bold = rc.STYLES[style]
        font = font_b if bold else font_r
        for sub in wrap_line(text, font, max_width) or [""]:
            wrapped.append((sub, color, font))

    visible_rows = (HEIGHT - TOP_BAR - PAD_TOP) // LINE_HEIGHT
    visible = wrapped[-visible_rows:]

    y = TOP_BAR + PAD_TOP
    for text, color, font in visible:
        draw.text((PAD_X, y), text, font=font, fill=color)
        y += LINE_HEIGHT

    img.save(path)


def build_video(run_dir: str, speed: float, out_path: str, fps: int) -> None:
    events = rc.build_events(run_dir)
    font_r = ImageFont.truetype(FONT_REGULAR, FONT_SIZE)
    font_b = ImageFont.truetype(FONT_BOLD, FONT_SIZE)

    workdir = tempfile.mkdtemp(prefix="defivault_video_")
    concat_path = os.path.join(workdir, "frames.txt")
    scrollback: list = []

    try:
        with open(concat_path, "w", encoding="utf-8") as concat_f:
            last_frame_path = None
            for i, event in enumerate(events):
                scrollback.extend(event.lines)
                frame_path = os.path.join(workdir, f"frame_{i:03d}.png")
                render_frame(scrollback, font_r, font_b, frame_path)
                duration = max(event.hold / speed, 1.0 / fps)
                concat_f.write(f"file '{frame_path}'\n")
                concat_f.write(f"duration {duration:.3f}\n")
                last_frame_path = frame_path
            # o demuxer concat ignora a duration do ultimo item; repete-se
            # o ultimo frame para ele nao sumir 1 frame antes do fim.
            if last_frame_path:
                concat_f.write(f"file '{last_frame_path}'\n")

        subprocess.run(
            [
                "ffmpeg", "-y",
                "-f", "concat", "-safe", "0", "-i", concat_path,
                "-vf", f"fps={fps},format=yuv420p",
                "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                out_path,
            ],
            check=True,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"OK: {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--speed", type=float, default=1.0,
                         help="multiplicador de velocidade (2 = 2x mais rapido)")
    parser.add_argument("--run-dir", default=rc.DEFAULT_RUN_DIR)
    parser.add_argument("-o", "--output",
                         default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                               "apresentacao-2min-tela.mp4"))
    parser.add_argument("--fps", type=int, default=8,
                         help="fps do video de saida (o conteudo e mudanca de tela, nao precisa de mais)")
    args = parser.parse_args()
    if args.speed <= 0:
        parser.error("--speed precisa ser > 0")
    build_video(os.path.abspath(args.run_dir), args.speed, args.output, args.fps)


if __name__ == "__main__":
    main()
