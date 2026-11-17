#!/usr/bin/env python3
"""Gera o PDF de saldo do projeto: o percurso e onde o pipeline esta hoje.

Uso:
    python3 docs/gerar_saldo_projeto.py
    -> escreve docs/saldo-projeto-<data>.pdf

Reaproveita apenas reportlab, como docs/gerar_slides_apresentacao.py.
Sem rede, sem LaTeX, sem pandoc.

Todos os numeros foram medidos no repositorio em 2026-11-12, nao estimados.
O historico de fases vem de `git log`; as metricas de execucao, de runs/.
"""
from __future__ import annotations

import datetime
import os

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = datetime.date(2026, 11, 12)
OUTPUT_PDF = os.path.join(HERE, f"saldo-projeto-{DATA:%Y%m%d}.pdf")

INK = colors.HexColor("#1c2333")
ACCENT = colors.HexColor("#2f6f4f")
ACCENT_SOFT = colors.HexColor("#e7f0ea")
MUTED = colors.HexColor("#5b6472")
CODE_BG = colors.HexColor("#f3f5f4")
LINE = colors.HexColor("#d4dad6")

S = {
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=23,
                            leading=27, textColor=INK, spaceAfter=3),
    "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=11,
                               leading=15, textColor=MUTED, spaceAfter=16),
    "h": ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=14.5,
                        leading=18, textColor=INK, spaceBefore=15, spaceAfter=7),
    "kicker": ParagraphStyle("kicker", fontName="Helvetica-Bold", fontSize=8.5,
                             leading=11, textColor=ACCENT, spaceAfter=5),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10.3,
                           leading=15, textColor=INK, spaceAfter=7),
    "bullet": ParagraphStyle("bullet", fontName="Helvetica", fontSize=10.3,
                             leading=14.5, textColor=INK, spaceAfter=5,
                             leftIndent=12, bulletIndent=2),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8.6, leading=12,
                           textColor=INK, backColor=CODE_BG, borderPadding=7,
                           spaceBefore=4, spaceAfter=9),
    "cap": ParagraphStyle("cap", fontName="Helvetica-Oblique", fontSize=8.8,
                          leading=12, textColor=MUTED, spaceBefore=3,
                          spaceAfter=10),
    "kpi_n": ParagraphStyle("kpi_n", fontName="Helvetica-Bold", fontSize=20,
                            leading=23, textColor=ACCENT, alignment=1),
    "kpi_l": ParagraphStyle("kpi_l", fontName="Helvetica", fontSize=8,
                            leading=10.5, textColor=MUTED, alignment=1),
    "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=9.2,
                         leading=12, textColor=colors.white),
    "td": ParagraphStyle("td", fontName="Helvetica", fontSize=9.4, leading=12.5,
                         textColor=INK),
}


def chrome(canvas, doc):
    canvas.saveState()
    w, h = A4
    canvas.setFillColor(ACCENT)
    canvas.rect(0, h - 0.42 * cm, w, 0.42 * cm, stroke=0, fill=1)
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 7.8)
    canvas.drawString(2 * cm, 1.1 * cm,
                      "Pipeline de Auditoria Automatizada — CIn/UFPE")
    canvas.drawRightString(w - 2 * cm, 1.1 * cm, f"página {doc.page}")
    canvas.restoreState()


def tabela(linhas, larguras, destaque=None):
    data = [[Paragraph(c, S["th"]) for c in linhas[0]]]
    for ln in linhas[1:]:
        data.append([Paragraph(c, S["td"]) for c in ln])
    cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, LINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.white, colors.HexColor("#fafbfa")]),
    ]
    for i, cor in (destaque or {}).items():
        cmds.append(("BACKGROUND", (0, i), (-1, i), cor))
    t = Table(data, colWidths=larguras, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle(cmds))
    return t


def kpis(itens):
    data = [[Paragraph(n, S["kpi_n"]) for n, _ in itens],
            [Paragraph(l, S["kpi_l"]) for _, l in itens]]
    w = (A4[0] - 4 * cm) / len(itens)
    t = Table(data, colWidths=[w] * len(itens), hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), ACCENT_SOFT),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("LINEAFTER", (0, 0), (-2, -1), 0.7, colors.white),
    ]))
    return t


def build():
    doc = SimpleDocTemplate(
        OUTPUT_PDF, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.9 * cm, bottomMargin=1.9 * cm,
        title="Saldo do Projeto — Pipeline de Auditoria Automatizada",
        author="Gustavo Stive — CIn/UFPE",
    )
    f = []
    P = lambda t, s="body": Paragraph(t, S[s])
    B = lambda t: Paragraph(t, S["bullet"], bulletText="\u2022")
    C = lambda t: f"<font face='Courier'>{t}</font>"

    # ---------------- página 1 ----------------
    f.append(P("Saldo do Projeto", "title"))
    f.append(P("Pipeline de auditoria automatizada de contratos Solidity "
               f"&nbsp;·&nbsp; situação em {DATA:%d/%m/%Y} &nbsp;·&nbsp; branch "
               + C("analysis/catalog-coverage"), "subtitle"))

    f.append(kpis([("71", "commits em<br/>8 meses"),
                   ("17.292", "linhas de Python<br/>rastreadas"),
                   ("126", "contratos<br/>testados"),
                   ("105", "classes no<br/>catálogo"),
                   ("307", "testes de<br/>regressão")]))
    f.append(Spacer(1, 0.45 * cm))

    f.append(P("Quais contratos, de verdade", "h"))
    f.append(P("Os 126 contratos não são equivalentes entre si, e a distinção "
               "importa: mais da metade são provas de conceito didáticas, não "
               "código que foi para produção. O número defensável de código real "
               "auditado é <b>17</b>."))
    f.append(tabela([
        ["Origem", "Contratos", "O que é"],
        ["Code4rena + Solmate", "<b>17</b>",
         "Codebases reais que passaram por auditoria pública: Inverse, Maia, "
         "Escher, Caviar, Astaria, Forgotten Runes, Solmate"],
        ["DeFiVulnLabs", "56",
         "PoCs didáticos de vulnerabilidade, de repositório público. Úteis como "
         "corpus de classes, não como evidência de código de produção"],
        ["Benchmark próprio", "53",
         "Contratos sintéticos escritos para o projeto, com vulnerabilidade conhecida"],
    ], [4.2 * cm, 2.2 * cm, 10.6 * cm]))
    f.append(P("Medido cruzando os nomes dos diretórios em " + C("runs/") + " e "
               + C("runs/static_only/") + " contra a árvore "
               + C("smart-audt/contracts/real/") + ", ignorando cópias em "
               + C("out/") + ".", "cap"))

    f.append(P("O que as execuções produziram", "h"))
    f.append(tabela([
        ["Métrica", "Valor", "Leitura honesta"],
        ["Execuções completas registradas", "389",
         "Inclui reexecuções do mesmo contrato e tentativas sucessivas"],
        ["Chegaram ao comparativo final", "119",
         "As demais pararam antes por decisão do próprio pipeline — em geral "
         "<i>no actionable candidates</i>, que é o resultado correto, não falha"],
        ["Comparativo com 100% resolvido", "<b>105</b>",
         "De 119. Conta achados que o próprio pipeline confirmou, "
         "predominantemente de classes mecânicas"],
        ["Suíte de regressão", "307 + 1",
         "307 passam, 1 é pulada, 69 subtestes, em cerca de 16 segundos"],
    ], [5.4 * cm, 2.4 * cm, 9.2 * cm]))

    f.append(PageBreak())

    # ---------------- página 2: percurso ----------------
    f.append(P("O caminho até aqui", "h"))
    f.append(P("Oito meses de trabalho, de 04/03 a 09/11 de 2026, em 71 commits. "
               "As fases abaixo foram extraídas do histórico do repositório, não "
               "reconstruídas de memória."))
    f.append(tabela([
        ["Fase", "Período", "O que foi entregue"],
        ["1. Fundação", "mar · 13 commits",
         "Pipeline inicial ponta a ponta, agente, prompts de sistema, primeiro "
         "validador de spec CVL, contratos de benchmark. Releases v1.0 e v1.1"],
        ["2. Guardrails", "mai · 8 commits",
         "<i>Patch guard</i> de diff mínimo; tratamento de " + C("envfree") +
         " inválido; bloqueio de avaliação sobre log inválido do Certora; "
         "diagnóstico determinístico para classes conhecidas"],
        ["3. Aprendizado", "jun–jul · 7 commits",
         "Parser de contraexemplo do Certora, biblioteca de correções, laço de "
         "retentativa mais esperto; diagnóstico generalizado além dos "
         "dicionários por detector; <i>parsing</i> com tree-sitter"],
        ["4. Medição", "ago–set · 7 commits",
         "O probe de generalização passou a executar de fato; roteiro e gerador "
         "de slides da apresentação de 2 minutos (PR #1)"],
        ["5. Escala e código real", "nov · <b>36 commits</b>",
         "Catálogo cobrindo todo detector Slither de impacto Low ou maior; modo "
         + C("--static-only") + "; detector próprio; oito classes com reparo "
         "mecânico; dezenas de correções para rodar em projetos Foundry reais"],
    ], [3.5 * cm, 2.9 * cm, 10.6 * cm], destaque={5: ACCENT_SOFT}))

    f.append(PageBreak())

    # ---------------- página 3: componentes ----------------
    f.append(P("O que foi construído", "h"))
    f.append(P("Os componentes que existem hoje, e que não vieram de biblioteca "
               "pronta:"))
    f.append(tabela([
        ["Componente", "Escala", "Função"],
        ["Catálogo de vulnerabilidades", "105 classes",
         "Decide a trilha de cada achado: 6 formalizáveis no Certora, "
         "5 confirmadas estaticamente, o restante em triagem"],
        ["Normalizador do Slither", "—",
         "Converte a saída bruta em classes estáveis, com heurísticas próprias "
         "para falsos positivos (chamadas de interface, " + C("safeTransfer") +
         ", <i>selfdestruct</i> interno)"],
        ["Reparo determinístico", "<b>8 classes</b>",
         C("missing-zero-check") + ", " + C("tx-origin") + ", " + C("suicidal") +
         ", " + C("unchecked-lowlevel") + ", " + C("unchecked-send") + ", "
         + C("unchecked-transfer") + ", " + C("arbitrary-send-erc20") + ", "
         + C("unrestricted-write")],
        ["Detector próprio", "557 linhas",
         "Plugin Slither " + C("unrestricted-write") + ", para escritas "
         "privilegiadas sem guarda — classe que o Slither não cobre"],
        ["Patch guard", "—",
         "Barra correção não mínima: assinatura pública alterada, literal de "
         "string mexido, variável de estado removida"],
        ["Geração e reparo de CVL", "—",
         "Spec determinística para padrões mecânicos, mais um reparador que "
         "conserta erros recorrentes de sintaxe CVL antes de chamar o Prover"],
        ["Probe de generalização", "8 operadores",
         "Injeta defeitos (AOR, BOR, UOR, EED, MD, PKR, FVR, FXR) e mede se o "
         "agente repara, copia ou falha"],
        ["Suíte de regressão", "4.300 linhas",
         "307 testes em 14 arquivos, executando em cerca de 16 segundos"],
    ], [4.3 * cm, 2.3 * cm, 10.4 * cm]))

    f.append(PageBreak())

    # ---------------- página 4: independência ----------------
    f.append(P("O resultado novo: independência de prompt", "kicker"))
    f.append(P("A detecção não depende do LLM, e isso agora está medido", "h"))
    f.append(P("A crítica usual a trabalhos de auditoria com LLM é a "
               "reprodutibilidade: se o resultado muda quando o prompt muda, a "
               "medida não vale. O modo " + C("--static-only") + " deste pipeline "
               "executa Slither, o catálogo e as correções determinísticas "
               "<b>sem nenhuma chamada de LLM</b>. Para comprovar que o LLM não "
               "está no caminho, o mesmo contrato foi executado três vezes, e na "
               "terceira com credencial e modelo propositalmente inválidos:"))
    f.append(P("SOLC_VERSION=0.8.21 \\<br/>"
               "AUDIT_LLM_MODEL=modelo-inexistente-xyz \\<br/>"
               "GROQ_API_KEY=chave-invalida \\<br/>"
               "python3 agent/main.py --contract .../SimpleBank.sol \\<br/>"
               "&nbsp;&nbsp;--static-only --with-plugins", "code"))
    f.append(P("<b>Resultado:</b> as três execuções produziram arquivos idênticos "
               "byte a byte — " + C("slither_raw.json") + ", "
               + C("slither_normalized.json") + ", "
               + C("deterministic_patch.json") + ", " + C("static_report.json")
               + " e o " + C(".sol") + " corrigido. A única diferença em qualquer "
               "arquivo foi o campo " + C("created_at") + " do "
               + C("metadata.json") + ". Com a chave quebrada, o pipeline detectou "
               "as mesmas 12 vulnerabilidades e corrigiu as mesmas 4."))
    f.append(tabela([
        ["Isso demonstra", "Isso não demonstra"],
        ["Que a detecção e parte da correção são reprodutíveis e independem de "
         "modelo, de prompt e de temperatura.",
         "Que as correções sejam boas. Reprodutível não é sinônimo de correto."],
        ["Que o resultado pode ser reexecutado ao vivo, sem credencial e sem "
         "custo, por quem quiser conferir.",
         "Que o pipeline generalize. A generalização do LLM continua "
         "<b>não demonstrada</b>."],
    ], [8.5 * cm, 8.5 * cm]))
    f.append(P("Atenção ao apresentar: no último probe de mutação, os 13 reparos "
               "medidos foram <b>todos</b> determinísticos (11 de "
               + C("unrestricted-write") + ", 2 de " + C("tx-origin") + "). Isso "
               "sustenta a independência de prompt e, ao mesmo tempo, é exatamente "
               "o motivo pelo qual a generalização do LLM não está provada. São "
               "duas conclusões distintas da mesma evidência; a banca vai separar, "
               "e é melhor separar primeiro.", "cap"))

    f.append(PageBreak())

    # ---------------- página 5: lote e pendências ----------------
    f.append(P("Lote de código de produção", "h"))
    f.append(P("Seis contratos de codebases reais executados no pipeline completo "
               "em 09/11/2026, com Certora e LLM:"))
    f.append(tabela([
        ["Contrato", "Projeto", "Situação"],
        ["SimpleERC20Escrow", "Inverse",
         "<b>Resolvido 2/2</b>, aprovado pelo Certora na segunda tentativa"],
        ["Initializable", "Escher",
         "Sem achado real: eram 2 falsos positivos do normalizador, já corrigidos"],
        ["GovTokenEscrow", "Inverse",
         "A spec compila e o Certora confirma 4 achados; parou no erro 400 do Groq"],
        ["OpenEdition", "Escher",
         "Correção do " + C("owner() envfree") + " escrita, não verificada"],
        ["TalosBaseStrategy", "Maia",
         "O LLM removeu funções públicas; barrado pelo <i>patch guard</i>, "
         "corretamente"],
        ["GovernorBravoDelegateMaia", "Maia",
         "<i>Stack too deep</i>: limite de compilação, sem solução no momento"],
    ], [4.3 * cm, 2.1 * cm, 10.6 * cm], destaque={1: ACCENT_SOFT}))
    f.append(P("Saldo do lote: 1 de 6 fechado de ponta a ponta. Mas 5 correções "
               "reais de infraestrutura ficaram no código, e 4 destes contratos "
               "agora chegam mais longe no pipeline do que chegavam antes.", "cap"))

    f.append(P("O que está em aberto", "h"))
    f.append(B("<b>Generalização do LLM não demonstrada.</b> Todos os reparos "
               "medidos até agora foram determinísticos. É a lacuna científica "
               "principal."))
    f.append(B("<b>38 arquivos de produção falham no Slither</b> — cerca de um "
               "quarto dos candidatos reais. Nunca investigados."))
    f.append(B("<b>Cota diária do Groq esgotada</b> para "
               + C("openai/gpt-oss-120b") + ", o que bloqueia as reexecuções com "
               "LLM. O modo " + C("--static-only") + " não depende de cota e "
               "segue disponível."))
    f.append(B("<b>13 contratos nunca chegaram ao Certora</b>, por erro de "
               "compilação ou de geração de spec."))
    f.append(B("<b>Sete commits locais sem push</b> na branch, PR #2 contra "
               + C("develop") + " ainda não atualizado."))

    f.append(P("Higiene do repositório", "h"))
    f.append(P("Em 11/11 o repositório foi limpo: a raiz saiu de 186 para 12 "
               "entradas e o tamanho de 4,5 GB para 2,5 GB, removendo 179 "
               "diretórios de artefato do Certora e 218 MB de cache — nada "
               "rastreado pelo git. As 15 execuções citadas como evidência nos "
               "relatórios foram conferidas uma a uma e todas continuam presentes. "
               "O projeto em si são <b>171 arquivos rastreados</b>."))

    doc.build(f, onFirstPage=chrome, onLaterPages=chrome)
    print(f"escrito: {OUTPUT_PDF}")


if __name__ == "__main__":
    build()
