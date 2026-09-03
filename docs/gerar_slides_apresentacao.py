#!/usr/bin/env python3
"""Gera o PDF de slides para a apresentacao de 2 minutos do pipeline.

Uso:
    python3 docs/gerar_slides_apresentacao.py
    -> escreve docs/apresentacao-2min-slides.pdf

Reaproveita apenas reportlab (ja usado no ambiente do projeto), sem
dependencia de rede ou de LaTeX/pandoc.
"""
from __future__ import annotations

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PDF = os.path.join(HERE, "apresentacao-2min-slides.pdf")

PAGE_SIZE = (13.333 * inch, 7.5 * inch)  # 16:9, como um slide de verdade
MARGIN = 0.7 * inch

INK = colors.HexColor("#1c2333")
ACCENT = colors.HexColor("#2f6f4f")
ACCENT_SOFT = colors.HexColor("#e7f0ea")
MUTED = colors.HexColor("#5b6472")
CODE_BG = colors.HexColor("#f3f5f4")
BAD = colors.HexColor("#a13d3d")
GOOD = colors.HexColor("#2f6f4f")

styles = {
    "title": ParagraphStyle(
        "title", fontName="Helvetica-Bold", fontSize=34, leading=40,
        textColor=INK, spaceAfter=10,
    ),
    "subtitle": ParagraphStyle(
        "subtitle", fontName="Helvetica", fontSize=16, leading=22,
        textColor=MUTED, spaceAfter=4,
    ),
    "heading": ParagraphStyle(
        "heading", fontName="Helvetica-Bold", fontSize=24, leading=28,
        textColor=INK, spaceAfter=14,
    ),
    "kicker": ParagraphStyle(
        "kicker", fontName="Helvetica-Bold", fontSize=12, leading=14,
        textColor=ACCENT, spaceAfter=6,
    ),
    "body": ParagraphStyle(
        "body", fontName="Helvetica", fontSize=15.5, leading=22,
        textColor=INK, spaceAfter=10, alignment=TA_LEFT,
    ),
    "bullet": ParagraphStyle(
        "bullet", fontName="Helvetica", fontSize=15.5, leading=21,
        textColor=INK, spaceAfter=9, leftIndent=14, bulletIndent=0,
    ),
    "caption": ParagraphStyle(
        "caption", fontName="Helvetica-Oblique", fontSize=12, leading=16,
        textColor=MUTED, spaceBefore=6,
    ),
    "code_label": ParagraphStyle(
        "code_label", fontName="Helvetica-Bold", fontSize=11.5, leading=14,
        spaceAfter=4,
    ),
    "code": ParagraphStyle(
        "code", fontName="Courier", fontSize=10, leading=13.5,
        textColor=INK, backColor=CODE_BG, borderPadding=8,
    ),
    "table_header": ParagraphStyle(
        "table_header", fontName="Helvetica-Bold", fontSize=12,
        textColor=colors.white,
    ),
    "table_cell": ParagraphStyle(
        "table_cell", fontName="Helvetica", fontSize=12, textColor=INK,
    ),
    "footer": ParagraphStyle(
        "footer", fontName="Helvetica", fontSize=9, textColor=MUTED,
    ),
}

SLIDE_COUNTER = {"n": 0, "total": 9}


def draw_chrome(canvas, doc):
    """Barra de acento + rodape, desenhados em toda pagina."""
    canvas.saveState()
    w, h = PAGE_SIZE
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 0.16 * inch, w, 0.16 * inch, stroke=0, fill=1)

    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 9)
    canvas.drawString(MARGIN, 0.38 * inch,
                       "Pipeline de Auditoria Automatizada — CIn/UFPE")
    SLIDE_COUNTER["n"] += 1
    canvas.drawRightString(
        w - MARGIN, 0.38 * inch,
        f"{SLIDE_COUNTER['n']} / {SLIDE_COUNTER['total']}",
    )
    canvas.restoreState()


def new_doc():
    doc = BaseDocTemplate(
        OUTPUT_PDF,
        pagesize=PAGE_SIZE,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
    )
    frame = Frame(
        MARGIN, 0.6 * inch,
        PAGE_SIZE[0] - 2 * MARGIN, PAGE_SIZE[1] - 1.2 * inch,
        id="slide",
    )
    doc.addPageTemplates([PageTemplate(id="slide", frames=[frame], onPage=draw_chrome)])
    return doc


def bullets(items):
    return [Paragraph(f"•&nbsp;&nbsp;{t}", styles["bullet"]) for t in items]


def code_pair(label_before, code_before, label_after, code_after, width):
    def cell(label, code, color):
        return [
            Paragraph(label, ParagraphStyle(
                "lbl", parent=styles["code_label"], textColor=color)),
            Preformatted(code, styles["code"]),
        ]

    t = Table(
        [[cell(label_before, code_before, BAD), cell(label_after, code_after, GOOD)]],
        colWidths=[width / 2 - 8, width / 2 - 8],
    )
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (0, 0), 16),
        ("LEFTPADDING", (1, 0), (1, 0), 16),
    ]))
    return t


# ---------------------------------------------------------------------------
# Slides
# ---------------------------------------------------------------------------

def slide_title(story):
    story.append(Spacer(1, 1.2 * inch))
    story.append(Paragraph("SEGURANÇA DE CONTRATOS INTELIGENTES", styles["kicker"]))
    story.append(Paragraph(
        "IA + Verificação Formal para Auditoria e Correção Automática",
        styles["title"]))
    story.append(Spacer(1, 0.25 * inch))
    story.append(Paragraph(
        "Gustavo Ferreira Leite de Barros — Centro de Informática, UFPE",
        styles["subtitle"]))
    story.append(Paragraph(
        "Pipeline: Slither → LLM → Certora Prover → diagnóstico → correção → "
        "revalidação", styles["subtitle"]))
    story.append(PageBreak())


def slide_problem(story):
    story.append(Paragraph("O PROBLEMA", styles["kicker"]))
    story.append(Paragraph("Contratos que movem dinheiro, e podem falhar", styles["heading"]))
    story.append(Spacer(1, 6))
    for t in bullets([
        "Contratos inteligentes automatizam transferências financeiras sem "
        "intermediário — uma falha no código pode ser explorada e causar "
        "prejuízo financeiro real.",
        "Desenvolvedores também otimizam contratos para reduzir o custo de "
        "gás — mas alterar o código pode mudar seu comportamento original "
        "ou introduzir novas vulnerabilidades.",
        "Testes tradicionais só cobrem alguns exemplos: não provam que o "
        "contrato está correto para todos os casos possíveis.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_pipeline(story):
    story.append(Paragraph("A SOLUÇÃO", styles["kicker"]))
    story.append(Paragraph("Uma pipeline automática de análise e correção", styles["heading"]))
    story.append(Spacer(1, 10))

    stages = ["Slither", "LLM", "Spec CVL", "Certora\nProver", "Diagnóstico", "Correção", "Revalidação"]
    cells = []
    for i, s in enumerate(stages):
        cells.append(Paragraph(s.replace("\n", "<br/>"), ParagraphStyle(
            "stage", fontName="Helvetica-Bold", fontSize=12.5, leading=15,
            textColor=colors.white, alignment=1)))
    t = Table([cells], colWidths=[(PAGE_SIZE[0] - 2 * MARGIN) / len(stages)] * len(stages),
               rowHeights=[0.9 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, colors.white),
        ("INNERGRID", (0, 0), (-1, -1), 1.5, colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        "A IA não corrige \"no chute\": ela opera dentro de um pipeline com "
        "análise estática, verificação formal e um ciclo de revalidação.",
        styles["body"]))
    story.append(PageBreak())


def slide_detection(story):
    story.append(Paragraph("COMO FUNCIONA — DETECÇÃO", styles["kicker"]))
    story.append(Paragraph("Slither + LLM", styles["heading"]))
    story.append(Spacer(1, 6))
    for t in bullets([
        "O <b>Slither</b> examina o código estaticamente e aponta possíveis "
        "vulnerabilidades (controle de acesso, endereços não validados, "
        "chamadas externas inseguras, entre outras).",
        "Um modelo de <b>IA (Llama 3.3 70B)</b> interpreta esses achados, "
        "identifica quais são relevantes para o contrato e ajuda a criar "
        "propriedades de segurança formalizáveis.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_formal(story):
    story.append(Paragraph("COMO FUNCIONA — VERIFICAÇÃO FORMAL", styles["kicker"]))
    story.append(Paragraph("Certora Prover: prova, não amostra", styles["heading"]))
    story.append(Spacer(1, 6))
    for t in bullets([
        "As propriedades viram uma <b>especificação CVL</b> e são analisadas "
        "pelo Certora Prover.",
        "Diferente de testes tradicionais, que avaliam alguns exemplos, a "
        "verificação formal analisa <b>matematicamente</b> todos os "
        "comportamentos possíveis do contrato.",
        "Quando uma propriedade é violada, a ferramenta devolve um "
        "<b>contraexemplo</b> concreto — a entrada exata que quebra a "
        "garantia.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_loop(story):
    story.append(Paragraph("CICLO DE CORREÇÃO", styles["kicker"]))
    story.append(Paragraph("Diagnóstico → correção → revalidação", styles["heading"]))
    story.append(Spacer(1, 6))
    for t in bullets([
        "Com o contraexemplo em mãos, a IA diagnostica a causa raiz da "
        "falha e produz uma versão corrigida do contrato.",
        "A correção <b>não é aceita de imediato</b>: o contrato corrigido "
        "passa de novo pelo Slither e pelo Certora.",
        "Se a violação persistir, o sistema tenta de novo (até 3 vezes) — "
        "um ciclo automático e verificável, não um patch \"no chute\".",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_case_study(story):
    story.append(Paragraph("ESTUDO DE CASO", styles["kicker"]))
    story.append(Paragraph("DeFiVault — cofre de finanças descentralizadas", styles["heading"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Contrato pequeno (187 linhas) com controle de acesso, endereços "
        "não validados, transferência insegura e risco de reentrância.",
        styles["caption"]))
    story.append(Spacer(1, 10))

    width = PAGE_SIZE[0] - 2 * MARGIN
    story.append(code_pair(
        "ANTES — tx.origin como autorização",
        'modifier onlyOwner() {\n'
        '    require(tx.origin == owner,\n'
        '        "not owner");\n'
        '    _;\n'
        '}',
        "DEPOIS — msg.sender (correto)",
        'modifier onlyOwner() {\n'
        '    require(msg.sender == owner,\n'
        '        "not owner");\n'
        '    _;\n'
        '}',
        width,
    ))
    story.append(Spacer(1, 10))
    story.append(code_pair(
        "ANTES — endereço zero aceito",
        'function transferOwnership(\n'
        '    address newOwner\n'
        ') external onlyOwner {\n'
        '    pendingOwner = newOwner;\n'
        '}',
        "DEPOIS — validação adicionada",
        'function transferOwnership(\n'
        '    address newOwner\n'
        ') external onlyOwner {\n'
        '    require(newOwner != address(0));\n'
        '    pendingOwner = newOwner;\n'
        '}',
        width,
    ))
    story.append(PageBreak())


def slide_results(story):
    story.append(Paragraph("RESULTADO", styles["kicker"]))
    story.append(Paragraph("5 violações confirmadas → 5 corrigidas, em 1 iteração", styles["heading"]))
    story.append(Spacer(1, 10))

    header = [Paragraph(h, styles["table_header"]) for h in
              ["ID", "Tipo", "Função", "Status"]]
    rows = [
        ["VULN_003", "missing-zero-check", "transferOwnership", "Resolvido"],
        ["VULN_004", "missing-zero-check", "emergencyWithdraw", "Resolvido"],
        ["VULN_011", "tx-origin", "onlyOwner", "Resolvido"],
        ["VULN_012", "suicidal", "destroy", "Resolvido"],
        ["VULN_013", "arbitrary-send-eth", "emergencyWithdraw", "Resolvido"],
    ]
    data = [header]
    for r in rows:
        data.append([Paragraph(c, styles["table_cell"]) for c in r[:-1]] + [
            Paragraph(f'<font color="#2f6f4f"><b>{r[-1]}</b></font>', styles["table_cell"])
        ])

    t = Table(data, colWidths=[1.3 * inch, 2.3 * inch, 2.6 * inch, 1.6 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("BACKGROUND", (0, 1), (-1, -1), ACCENT_SOFT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ACCENT_SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Correção aplicada em <b>withdraw</b> e <b>claimReward</b>: padrão "
        "checks-effects-interactions (estado atualizado antes da chamada "
        "externa), reduzindo a superfície de reentrância — hardening "
        "adicional além das 5 regras verificadas no Certora.",
        styles["caption"]))
    story.append(PageBreak())


def slide_closing(story):
    story.append(Paragraph("DIFERENCIAL", styles["kicker"]))
    story.append(Paragraph("Geração + prova, não geração sozinha", styles["heading"]))
    story.append(Spacer(1, 6))
    for t in bullets([
        "O diferencial é combinar a <b>capacidade de geração</b> da IA com "
        "as <b>evidências da verificação formal</b>.",
        "Objetivo: tornar a auditoria de contratos inteligentes mais "
        "automática, segura e confiável — não substituir a auditoria "
        "humana, mas reduzir o trabalho repetitivo.",
        "A correção só é aceita depois de confirmada matematicamente, e "
        "ainda passa por um guardrail de minimalidade antes da "
        "revalidação.",
    ]):
        story.append(t)
    story.append(Spacer(1, 20))
    story.append(Paragraph("Obrigado!", ParagraphStyle(
        "thanks", fontName="Helvetica-Bold", fontSize=22, textColor=ACCENT)))


def build():
    doc = new_doc()
    story = []
    slide_title(story)
    slide_problem(story)
    slide_pipeline(story)
    slide_detection(story)
    slide_formal(story)
    slide_loop(story)
    slide_case_study(story)
    slide_results(story)
    slide_closing(story)
    doc.build(story)
    print(f"OK: {OUTPUT_PDF}")


if __name__ == "__main__":
    build()
