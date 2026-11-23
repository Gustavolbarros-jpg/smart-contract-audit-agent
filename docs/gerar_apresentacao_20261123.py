#!/usr/bin/env python3
"""Gera o PDF da apresentacao atualizada (snapshot de 23/11/2026).

Uso:
    python3 docs/gerar_apresentacao_20261123.py
    -> escreve docs/apresentacao-20261123-slides.pdf

Nao substitui docs/apresentacao-2min-slides.pdf (08/10/2026): reaproveita os
estilos e os slides daquele gerador, troca o slide de deteccao (o modelo mudou)
e acrescenta quatro slides com o que foi medido em 17 e 18/11 — o oraculo formal
local e o propositor de propriedades.

Fontes DejaVu no lugar das Helvetica base, como em gerar_relatorio_pdf.py, para
que setas e aspas tipograficas tenham glifo de verdade.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, Spacer, Table, TableStyle

import gerar_slides_apresentacao as base
from gerar_relatorio_pdf import register_fonts

OUTPUT_PDF = os.path.join(HERE, "apresentacao-20261123-slides.pdf")


def usar_dejavu() -> None:
    """Troca as Helvetica base pelas DejaVu em todos os estilos herdados."""
    register_fonts()
    import gerar_relatorio_pdf as r

    if r.SANS == "Helvetica":  # DejaVu ausente: fica tudo como estava
        return
    troca = {
        "Helvetica": r.SANS,
        "Helvetica-Bold": r.SANS_B,
        "Helvetica-Oblique": r.SANS_I,
        "Helvetica-BoldOblique": r.SANS_BI,
        "Courier": r.MONO,
    }
    for estilo in base.styles.values():
        estilo.fontName = troca.get(estilo.fontName, estilo.fontName)
    return


def tabela(story, linhas, larguras, destaque_ultima=True):
    """Tabela no estilo do deck: cabecalho em verde, zebra clara."""
    forte = ParagraphStyle("td_forte", parent=base.styles["table_cell"],
                           fontName=base.styles["table_header"].fontName)
    data = [[Paragraph(c, base.styles["table_header"]) for c in linhas[0]]]
    for i, ln in enumerate(linhas[1:], start=1):
        # a ultima linha e o placar que importa: vai em negrito, nao so colorida
        estilo = forte if (destaque_ultima and i == len(linhas) - 1) else base.styles["table_cell"]
        data.append([Paragraph(c, estilo) for c in ln])
    t = Table(data, colWidths=larguras, hAlign="LEFT")
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), base.ACCENT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, base.ACCENT_SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]
    if destaque_ultima:
        cmds.append(("BACKGROUND", (0, len(data) - 1), (-1, len(data) - 1),
                     base.ACCENT_SOFT))
    t.setStyle(TableStyle(cmds))
    story.append(t)
    return t


WIDTH = base.PAGE_SIZE[0] - 2 * base.MARGIN


# ---------------------------------------------------------------------------
# Slides novos e revisados
# ---------------------------------------------------------------------------

def slide_deteccao(story):
    """Substitui base.slide_detection: o modelo em uso mudou."""
    story.append(Paragraph("COMO FUNCIONA — DETECÇÃO", base.styles["kicker"]))
    story.append(Paragraph("Slither + LLM, cada um no seu papel", base.styles["heading"]))
    story.append(Spacer(1, 6))
    for t in base.bullets([
        "O <b>Slither</b> examina o código estaticamente e aponta possíveis "
        "vulnerabilidades (controle de acesso, endereços não validados, "
        "chamadas externas inseguras, entre outras).",
        "Um <b>LLM</b> (hoje <i>gpt-oss-120b</i>, via Groq) interpreta esses "
        "achados, decide quais são formalizáveis e escreve as propriedades — "
        "mas o que é decidível sintaticamente fica com validadores "
        "determinísticos, não com o modelo.",
        "O catálogo cobre os <b>99 detectores</b> do Slither 0.11.3, e um teste "
        "falha se uma versão nova trouxer detector desconhecido.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_limite_instrumento(story):
    story.append(Paragraph("O PROBLEMA SEGUINTE", base.styles["kicker"]))
    story.append(Paragraph("Quem mede o medidor?", base.styles["heading"]))
    story.append(Spacer(1, 6))
    for t in base.bullets([
        "Toda taxa de \"resolveu X de Y\" era medida pelo <b>mesmo</b> "
        "instrumento que encontra o defeito: o Slither.",
        "Teste: a partir do contrato já corrigido, <b>46 mutantes</b> com um "
        "defeito injetado cada (operadores de mutação da literatura).",
        "O Slither, com o detector próprio incluído, produz achado de segurança "
        "novo em <b>9 deles</b>. Troca de operador aritmético, de comparação, "
        "remoção de evento e troca de <font face='Courier'>payable</font>: "
        "detectabilidade <b>zero</b>.",
        "Um defeito que o instrumento não vê nunca chega ao reparo — e nunca é "
        "cobrado do agente.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_oraculo(story):
    story.append(Paragraph("RESULTADO — 17/11/2026", base.styles["kicker"]))
    story.append(Paragraph("Um oráculo formal que não custa cota",
                           base.styles["heading"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<font face='Courier'>certoraRun --compilation_steps_only</font> para "
        "<b>antes de enviar</b> o job, não antes de verificar: o verificador roda "
        "na máquina e imprime veredito real. Zero cota de nuvem.",
        base.styles["body"]))
    story.append(Spacer(1, 8))
    tabela(story, [
        ["Instrumento", "Mutantes pegos (de 44 que compilam)", "Cota"],
        ["Slither + detector próprio", "9 (20%)", "—"],
        ["Especificação congelada, 19 regras", "18 (41%)", "zero"],
        ["Slither + oráculo formal", "24 (54%)", "zero"],
    ], [4.6 * inch, 4.4 * inch, 1.6 * inch])
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "As 19 regras foram escritas <b>antes</b> de qualquer mutante existir, "
        "verificam no contrato correto e nenhuma é vácua. Os instrumentos são "
        "complementares: 15 defeitos só o oráculo mata, 6 só o Slither vê.",
        base.styles["caption"]))
    story.append(PageBreak())


def slide_propositor(story):
    story.append(Paragraph("RESULTADO — 18/11/2026", base.styles["kicker"]))
    story.append(Paragraph("As propriedades escritas pela própria máquina",
                           base.styles["heading"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "Especificação à mão não escala. O propositor lê o código fonte e emite "
        "CVL <b>sem detector e sem LLM</b>, em seis formas — crédito, débito, "
        "portão de identidade, os <font face='Courier'>require</font> do próprio "
        "contrato, e duas de <i>liveness</i>.",
        base.styles["body"]))
    story.append(Spacer(1, 8))
    tabela(story, [
        ["Instrumento", "Mutantes pegos (de 44)"],
        ["Slither com plugins", "9 (20%)"],
        ["Especificação escrita à mão, 19 regras", "18 (41%)"],
        ["Especificação gerada, 28 regras (só safety)", "27 (61%)"],
        ["Especificação gerada, 45 regras (com liveness)", "32 (72%)"],
        ["Slither + especificação gerada", "33 (75%)"],
    ], [7.0 * inch, 3.6 * inch])
    story.append(Spacer(1, 12))
    story.append(Paragraph(
        "As 45 regras verificam no contrato correto e <b>nenhuma é vácua</b>: a "
        "cobertura não foi comprada com alarme falso. Descontando 2 mutantes "
        "equivalentes, são <b>33 de 42 defeitos reais (79%)</b>.",
        base.styles["caption"]))
    story.append(PageBreak())


def slide_proximos(story):
    story.append(Paragraph("O QUE AINDA NÃO ESTÁ RESOLVIDO", base.styles["kicker"]))
    story.append(Paragraph("O teto é a origem do diagnóstico",
                           base.styles["heading"]))
    story.append(Spacer(1, 6))
    for t in base.bullets([
        "O reparo ainda parte de um achado do Slither: só <b>3 dos 46</b> "
        "mutantes são alcançáveis pela trilha de correção. Nos outros não existe "
        "achado para diagnosticar.",
        "Nesses 3, a LLM repara <b>3 de 3</b> com confirmação formal — mas "
        "<b>empata</b> com a trilha determinística, porque a população não tem "
        "nenhuma classe fora da biblioteca de moldes. Generalização segue em "
        "aberto, e o experimento está pré-registrado.",
        "Próximo passo sem ambiguidade: <b>diagnosticar a partir do "
        "contraexemplo do oráculo</b>, não só do achado estático.",
        "No corpus real, dois bloqueios medidos: <b>358</b> invariantes "
        "declarados como <font face='Courier'>revert CustomError()</font> "
        "(contra 632 <font face='Courier'>require</font>) e <b>24%</b> das "
        "funções externas descartadas por parâmetro <i>struct</i>.",
    ]):
        story.append(t)
    story.append(PageBreak())


def slide_fechamento(story):
    story.append(Paragraph("DIFERENCIAL", base.styles["kicker"]))
    story.append(Paragraph("Geração + prova, não geração sozinha",
                           base.styles["heading"]))
    story.append(Spacer(1, 6))
    for t in base.bullets([
        "A correção só é aceita depois de confirmada matematicamente, e ainda "
        "passa por um guardrail de minimalidade antes da revalidação.",
        "A salvaguarda formal <b>não depende mais de um catálogo mantido à "
        "mão</b>: as propriedades saem do próprio código fonte.",
        "E o custo deixou de ser barreira — a verificação que sustenta esses "
        "números roda localmente, com <b>zero cota de nuvem</b>.",
    ]):
        story.append(t)
    story.append(Spacer(1, 16))
    story.append(Paragraph("Obrigado!", ParagraphStyle(
        "thanks", fontName=base.styles["heading"].fontName, fontSize=22,
        textColor=base.ACCENT)))


def build():
    usar_dejavu()
    base.OUTPUT_PDF = OUTPUT_PDF
    base.SLIDE_COUNTER["n"] = 0
    base.SLIDE_COUNTER["total"] = 13

    doc = base.new_doc()
    story: list = []
    base.slide_title(story)
    base.slide_problem(story)
    base.slide_pipeline(story)
    slide_deteccao(story)
    base.slide_formal(story)
    base.slide_loop(story)
    base.slide_case_study(story)
    base.slide_results(story)
    slide_limite_instrumento(story)
    slide_oraculo(story)
    slide_propositor(story)
    slide_proximos(story)
    slide_fechamento(story)
    doc.build(story)
    print(f"OK: {OUTPUT_PDF} ({os.path.getsize(OUTPUT_PDF) / 1024:.0f} KB)")


if __name__ == "__main__":
    build()
