#!/usr/bin/env python3
"""Renderiza um relatorio Markdown do projeto em PDF, pronto para enviar.

Uso:
    python3 docs/gerar_relatorio_pdf.py docs/relatorio-final-pibic-20261123.md
    -> escreve docs/relatorio-final-pibic-20261123.pdf

    python3 docs/gerar_relatorio_pdf.py <entrada.md> <saida.pdf>

Reaproveita apenas reportlab, como os outros geradores em docs/: sem rede, sem
LaTeX, sem pandoc. A identidade visual (acento, rodape, tabelas) segue
gerar_saldo_projeto.py, e as fontes DejaVu entram no lugar das Helvetica base
porque o texto usa setas, >= e aspas tipograficas.

Subconjunto de Markdown coberto, que e o usado nos relatorios do projeto:
titulo (#), secoes (##, ###), paragrafos, listas com "-" e "1.", citacao (>),
tabelas com alinhamento, regua (---), blocos cercados por ``` e, em linha,
**negrito**, *italico* e `codigo`.
"""
from __future__ import annotations

import os
import re
import sys

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

HERE = os.path.dirname(os.path.abspath(__file__))

INK = colors.HexColor("#1c2333")
ACCENT = colors.HexColor("#2f6f4f")
ACCENT_SOFT = colors.HexColor("#e7f0ea")
MUTED = colors.HexColor("#5b6472")
LINE = colors.HexColor("#d7dcd9")
CODE_BG = colors.HexColor("#f3f5f4")

MARGIN = 2 * cm
CONTENT_W = A4[0] - 2 * MARGIN

FONT_DIR = "/usr/share/fonts/truetype/dejavu"
SANS, SANS_B, SANS_I, SANS_BI, MONO = "DJSans", "DJSans-B", "DJSans-I", "DJSans-BI", "DJMono"


def register_fonts() -> None:
    """Usa DejaVu quando disponivel; cai para as Helvetica base se nao estiver."""
    global SANS, SANS_B, SANS_I, SANS_BI, MONO
    faces = {
        SANS: "DejaVuSans.ttf",
        SANS_B: "DejaVuSans-Bold.ttf",
        SANS_I: "DejaVuSans-Oblique.ttf",
        SANS_BI: "DejaVuSans-BoldOblique.ttf",
        MONO: "DejaVuSansMono.ttf",
    }
    if not all(os.path.exists(os.path.join(FONT_DIR, f)) for f in faces.values()):
        SANS, SANS_B, SANS_I, SANS_BI, MONO = (
            "Helvetica", "Helvetica-Bold", "Helvetica-Oblique",
            "Helvetica-BoldOblique", "Courier",
        )
        return
    for name, fn in faces.items():
        pdfmetrics.registerFont(TTFont(name, os.path.join(FONT_DIR, fn)))
    pdfmetrics.registerFontFamily(
        SANS, normal=SANS, bold=SANS_B, italic=SANS_I, boldItalic=SANS_BI)


def styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle(
            "title", fontName=SANS_B, fontSize=19, leading=24, textColor=INK,
            spaceAfter=12, keepWithNext=1),
        "meta": ParagraphStyle(
            "meta", fontName=SANS, fontSize=9.6, leading=14, textColor=INK,
            spaceAfter=1.5),
        "h2": ParagraphStyle(
            "h2", fontName=SANS_B, fontSize=14, leading=18, textColor=ACCENT,
            spaceBefore=18, spaceAfter=8, keepWithNext=1),
        "h3": ParagraphStyle(
            "h3", fontName=SANS_B, fontSize=11.2, leading=15, textColor=INK,
            spaceBefore=13, spaceAfter=6, keepWithNext=1),
        "body": ParagraphStyle(
            "body", fontName=SANS, fontSize=9.9, leading=14.6, textColor=INK,
            spaceAfter=9, alignment=4, firstLineIndent=0),
        "quote": ParagraphStyle(
            "quote", fontName=SANS_I, fontSize=9.2, leading=13.4, textColor=MUTED,
            spaceAfter=9, leftIndent=10, borderPadding=0),
        "bullet": ParagraphStyle(
            "bullet", fontName=SANS, fontSize=9.9, leading=14.2, textColor=INK,
            spaceAfter=5, leftIndent=16, bulletIndent=3, alignment=4),
        "numbered": ParagraphStyle(
            "numbered", fontName=SANS, fontSize=9.9, leading=14.2, textColor=INK,
            spaceAfter=5, leftIndent=19, bulletIndent=0, alignment=4),
        "code": ParagraphStyle(
            "code", fontName=MONO, fontSize=8.2, leading=11.4, textColor=INK,
            backColor=CODE_BG, borderPadding=7, spaceAfter=9),
        "th": ParagraphStyle(
            "th", fontName=SANS_B, fontSize=8.8, leading=11.6, textColor=colors.white),
        "td": ParagraphStyle(
            "td", fontName=SANS, fontSize=8.8, leading=11.8, textColor=INK),
    }


# ---------------------------------------------------------------------------
# Markdown em linha
# ---------------------------------------------------------------------------

def esc(txt: str) -> str:
    return (txt.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("\\\\", "\\"))


def inline(txt: str) -> str:
    """**negrito**, *italico* e `codigo` -> marcacao do Paragraph."""
    out = []
    for part in re.split(r"(`[^`]+`)", txt):
        if len(part) > 1 and part.startswith("`") and part.endswith("`"):
            out.append(
                f'<font face="{MONO}" size="8.6">{esc(part[1:-1])}</font>')
            continue
        s = esc(part)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        s = re.sub(r"(?<![\*\w])\*([^*\n]+?)\*(?!\*)", r"<i>\1</i>", s)
        out.append(s)
    return "".join(out)


# ---------------------------------------------------------------------------
# Tabelas
# ---------------------------------------------------------------------------

def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_sep_row(line: str) -> bool:
    cells = split_row(line)
    return bool(cells) and all(re.fullmatch(r":?-{2,}:?", c) for c in cells)


def alignments(sep: str) -> list[str]:
    out = []
    for c in split_row(sep):
        if c.endswith(":") and c.startswith(":"):
            out.append("CENTER")
        elif c.endswith(":"):
            out.append("RIGHT")
        else:
            out.append("LEFT")
    return out


def widths_for(rows: list[list[str]]) -> list[float]:
    """Larguras proporcionais ao conteudo, com piso para a coluna estreita."""
    ncols = len(rows[0])
    weight = []
    for i in range(ncols):
        longest = max(len(r[i]) if i < len(r) else 0 for r in rows)
        weight.append(max(longest, 6))
    total = float(sum(weight))
    floor = 1.5 * cm
    w = [max(floor, CONTENT_W * x / total) for x in weight]
    extra = sum(w) - CONTENT_W
    if extra > 0:  # o piso estourou a largura: devolve o excesso aos maiores
        folgas = [max(0.0, x - floor) for x in w]
        folga_total = sum(folgas) or 1.0
        w = [x - extra * f / folga_total for x, f in zip(w, folgas)]
    return w


def build_table(block: list[str], S: dict[str, ParagraphStyle]) -> Table:
    header = split_row(block[0])
    align = alignments(block[1])
    body = [split_row(ln) for ln in block[2:]]
    rows = [header] + body
    # O alinhamento tem de estar no estilo do Paragraph: a celula e preenchida
    # inteira por ele, entao o comando ALIGN da Table nao moveria o texto.
    codigo = {"LEFT": 0, "CENTER": 1, "RIGHT": 2}
    por_coluna = {}
    for nome in ("th", "td"):
        por_coluna[nome] = [
            S[nome] if a == "LEFT" else ParagraphStyle(
                f"{nome}-{a}", parent=S[nome], alignment=codigo[a])
            for a in align
        ]
    data = [[Paragraph(inline(c), por_coluna["th"][j]) for j, c in enumerate(header)]]
    for r in body:
        r = r + [""] * (len(header) - len(r))
        data.append([Paragraph(inline(c), por_coluna["td"][j]) for j, c in enumerate(r)])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#fafbfa")]),
    ]
    t = Table(data, colWidths=widths_for(rows), hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return t


# ---------------------------------------------------------------------------
# Documento
# ---------------------------------------------------------------------------

def chrome_factory(rodape: str):
    def chrome(canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(ACCENT)
        canvas.rect(0, h - 0.42 * cm, w, 0.42 * cm, stroke=0, fill=1)
        canvas.setFillColor(MUTED)
        canvas.setFont(SANS, 7.8)
        canvas.drawString(MARGIN, 1.1 * cm, rodape)
        canvas.drawRightString(w - MARGIN, 1.1 * cm, f"página {doc.page}")
        canvas.restoreState()
    return chrome


def flowables(md: str, S: dict[str, ParagraphStyle]) -> tuple[list, str]:
    linhas = md.split("\n")
    story: list = []
    titulo = ""
    i = 0
    front = True  # bloco de metadados do topo: cada linha e um paragrafo
    buf: list[str] = []
    kind = "body"

    def flush():
        nonlocal buf, kind
        if not buf:
            return
        texto = " ".join(x.strip() for x in buf).strip()
        if texto:
            if kind == "bullet":
                story.append(Paragraph(inline(texto), S["bullet"], bulletText="•"))
            elif kind.startswith("num:"):
                story.append(Paragraph(inline(texto), S["numbered"],
                                       bulletText=kind.split(":", 1)[1]))
            elif kind == "quote":
                story.append(Paragraph(inline(texto), S["quote"]))
            else:
                story.append(Paragraph(inline(texto), S[kind]))
        buf, kind = [], "body"

    while i < len(linhas):
        ln = linhas[i]
        bare = ln.strip()

        if bare.startswith("```"):           # bloco de codigo
            flush()
            i += 1
            code = []
            while i < len(linhas) and not linhas[i].strip().startswith("```"):
                code.append(linhas[i])
                i += 1
            i += 1
            story.append(Preformatted("\n".join(code), S["code"]))
            continue

        if not bare:                          # linha vazia fecha o paragrafo
            flush()
            i += 1
            continue

        if re.fullmatch(r"-{3,}|\*{3,}", bare):   # regua
            flush()
            front = False
            story.append(Spacer(1, 2))
            story.append(HRFlowable(width="100%", thickness=0.6, color=LINE,
                                    spaceAfter=10))
            i += 1
            continue

        if bare.startswith("|") and i + 1 < len(linhas) and is_sep_row(linhas[i + 1]):
            flush()
            block = [bare, linhas[i + 1].strip()]
            i += 2
            while i < len(linhas) and linhas[i].strip().startswith("|"):
                block.append(linhas[i].strip())
                i += 1
            story.append(build_table(block, S))
            story.append(Spacer(1, 11))
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", bare)
        if m:
            flush()
            nivel, texto = len(m.group(1)), m.group(2)
            if nivel == 1:
                titulo = re.sub(r"[*`]", "", texto)
                story.append(Paragraph(inline(texto), S["title"]))
            else:
                story.append(Paragraph(inline(texto), S["h2" if nivel == 2 else "h3"]))
            i += 1
            continue

        if bare.startswith(">"):
            flush()
            quote = []
            while i < len(linhas) and linhas[i].strip().startswith(">"):
                quote.append(linhas[i].strip().lstrip(">").strip())
                i += 1
            story.append(Paragraph(inline(" ".join(quote)), S["quote"]))
            continue

        m = re.match(r"^[-*]\s+(.*)$", bare)
        if m:
            flush()
            buf, kind = [m.group(1)], "bullet"
            i += 1
            continue

        m = re.match(r"^(\d+)\.\s+(.*)$", bare)
        if m:
            flush()
            buf, kind = [m.group(2)], f"num:{m.group(1)}."
            i += 1
            continue

        if front and buf == []:               # metadados: um paragrafo por linha
            story.append(Paragraph(inline(bare), S["meta"]))
            i += 1
            continue

        buf.append(bare)                      # continuacao de paragrafo/item
        i += 1

    flush()
    return story, titulo


def build(entrada: str, saida: str) -> str:
    register_fonts()
    S = styles()
    md = open(entrada, encoding="utf-8").read()
    story, titulo = flowables(md, S)
    doc = SimpleDocTemplate(
        saida, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.9 * cm, bottomMargin=1.9 * cm,
        title=titulo or os.path.basename(entrada),
        author="Gustavo Ferreira Leite de Barros — CIn/UFPE",
    )
    rodape = "Pipeline de Auditoria Automatizada — CIn/UFPE"
    doc.build(story, onFirstPage=chrome_factory(rodape),
              onLaterPages=chrome_factory(rodape))
    return saida


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    entrada = argv[1]
    saida = argv[2] if len(argv) > 2 else os.path.splitext(entrada)[0] + ".pdf"
    build(entrada, saida)
    print(f"OK: {saida} ({os.path.getsize(saida) / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
