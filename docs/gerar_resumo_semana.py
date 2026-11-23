#!/usr/bin/env python3
"""Gera o PDF de resumo semanal, no formato de envio por e-mail.

Uso:
    python3 docs/gerar_resumo_semana.py
    -> escreve docs/resumo-semana-<data>.pdf

Reaproveita o estilo e os componentes de gerar_saldo_projeto.py, para que os
dois documentos saiam com a mesma identidade visual.
"""
from __future__ import annotations

import datetime
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from gerar_saldo_projeto import ACCENT_SOFT, S, chrome, kpis, tabela

MESES = ("janeiro", "fevereiro", "março", "abril", "maio", "junho",
         "julho", "agosto", "setembro", "outubro", "novembro", "dezembro")

DATA = datetime.date(2026, 11, 13)
INICIO = datetime.date(2026, 11, 9)
OUTPUT_PDF = os.path.join(HERE, f"resumo-semana-{DATA:%Y%m%d}.pdf")


def build():
    doc = SimpleDocTemplate(
        OUTPUT_PDF, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=1.9 * cm, bottomMargin=1.9 * cm,
        title=f"Resumo da semana — {INICIO:%d/%m} a {DATA:%d/%m/%Y}",
        author="Gustavo Stive — CIn/UFPE",
    )
    f = []
    P = lambda t, s="body": Paragraph(t, S[s])
    B = lambda t: Paragraph(t, S["bullet"], bulletText="\u2022")
    C = lambda t: f"<font face='Courier'>{t}</font>"

    f.append(P("Resumo da Semana", "title"))
    f.append(P(f"Pipeline de auditoria automatizada de contratos Solidity "
               f"&nbsp;·&nbsp; {INICIO:%d} a {DATA:%d} de {MESES[DATA.month - 1]} de {DATA.year} "
               "&nbsp;·&nbsp; Gustavo Stive, CIn/UFPE", "subtitle"))

    f.append(P("O projeto desenvolve um pipeline que detecta vulnerabilidades em "
               "contratos Solidity com o Slither, decide por um catálogo próprio "
               "como tratar cada classe, gera especificação formal em CVL, verifica "
               "com o Certora Prover, corrige o código e revalida a correção."))

    f.append(Spacer(1, 0.2 * cm))
    f.append(kpis([("7", "commits"),
                   ("+393", "linhas"),
                   ("6", "contratos reais<br/>no pipeline"),
                   ("307", "testes<br/>passando")]))
    f.append(Spacer(1, 0.45 * cm))

    f.append(P("O resultado que muda a apresentação", "kicker"))
    f.append(P("A detecção não depende do LLM — agora medido", "h"))
    f.append(P("A crítica mais comum a trabalhos de auditoria com modelos de "
               "linguagem é a reprodutibilidade: se o resultado muda quando o "
               "prompt muda, a medida não se sustenta. O pipeline tem um modo "
               + C("--static-only") + " que executa o Slither, o catálogo e as "
               "correções determinísticas <b>sem nenhuma chamada ao LLM</b>. Para "
               "comprovar que o modelo não participa desse caminho, o mesmo "
               "contrato foi executado três vezes, sendo a terceira com credencial "
               "e modelo propositalmente inválidos:"))
    f.append(P("AUDIT_LLM_MODEL=modelo-inexistente-xyz \\<br/>"
               "GROQ_API_KEY=chave-invalida \\<br/>"
               "python3 agent/main.py --contract .../SimpleBank.sol \\<br/>"
               "&nbsp;&nbsp;--static-only --with-plugins", "code"))
    f.append(P("<b>As três execuções produziram arquivos idênticos byte a byte.</b> "
               "A única diferença em qualquer arquivo gerado foi o campo "
               + C("created_at") + " do " + C("metadata.json") + ". Mesmo com a "
               "chave quebrada, o pipeline detectou as mesmas 12 vulnerabilidades "
               "e corrigiu as mesmas 4. O resultado pode ser reproduzido ao vivo, "
               "em segundos, sem credencial e sem custo."))
    f.append(P("Ressalva que pretendo apresentar junto: isso demonstra "
               "reprodutibilidade, não qualidade. E não demonstra generalização — "
               "no último experimento de mutação, os 13 reparos medidos foram todos "
               "determinísticos, nenhum vindo do LLM. São duas conclusões distintas "
               "da mesma evidência.", "cap"))

    f.append(PageBreak())

    f.append(P("A evolução real do pipeline", "kicker"))
    f.append(P("O que mudou, medido sobre a mesma entrada", "h"))
    f.append(P("Contar commits e linhas não mede evolução. Para medir de fato, "
               "apliquei o catálogo <i>de cada época</i> ao mesmo conjunto de "
               "<b>8.867 achados reais</b>, extraídos de 500 execuções "
               "registradas no repositório. Mesma entrada, pipelines diferentes:"))
    f.append(tabela([
        ["Marco", "Catálogo", "Achados que sabia classificar", "Reparo sem LLM"],
        ["12/03", "não existia", "0%", "—"],
        ["27/05", "16 classes", "37,0%", "<b>0%</b>"],
        ["03/08", "18 classes", "41,1%", "6,7%"],
        ["03/09", "18 classes", "41,1%", "6,7%"],
        ["09/11", "<b>105 classes</b>", "<b>100%</b>", "<b>14,9%</b>"],
    ], [2.2 * cm, 3.4 * cm, 6.6 * cm, 4.8 * cm], destaque={5: ACCENT_SOFT}))
    f.append(Spacer(1, 0.3 * cm))

    f.append(P("A leitura honesta desses números", "h"))
    f.append(B("<b>Classificar não é automatizar.</b> Dos 8.867 achados, 83% são "
               "encaminhados para revisão humana, 11,3% para o Certora e 5,8% "
               "para confirmação estática. Ter trilha decidida para tudo significa "
               "não ter mais achado órfão: em maio, 59% caíam em "
               "<i>não sei o que fazer com isso</i>."))
    f.append(B("<b>Os 14,9% estavam com o denominador errado.</b> Sobre o total "
               "parece pouco. Mas dos achados que o pipeline encaminha para "
               "tratamento automático, <b>87% são corrigidos sem modelo de "
               "linguagem nenhum</b>."))
    f.append(B("<b>De junho a setembro a capacidade não evoluiu.</b> Os números de "
               "03/08 e 03/09 são idênticos. O trabalho do período — tree-sitter, "
               "parser de contraexemplo, biblioteca de correções — melhorou a "
               "infraestrutura sem ampliar a cobertura. É um fato do histórico, "
               "não uma omissão."))
    f.append(B("<b>80% da saída bruta do Slither é ruído</b> "
               "(" + C("naming-convention") + ", " + C("solc-version") + ", "
               + C("too-many-digits") + "); apenas 20% é categoria segurança. O "
               "trabalho central do catálogo não é corrigir, é separar o que "
               "importa — e essa triagem é, em si, uma contribuição."))

    f.append(PageBreak())

    f.append(P("Como as duas coisas foram construídas", "kicker"))
    f.append(P("A independência não é acidente, é arquitetura", "h"))
    f.append(P("O catálogo de 105 classes decide, para cada achado, qual trilha "
               "seguir. As classes mecânicas — aquelas em que a correção é uma "
               "inserção previsível, como um " + C("require") + " de endereço "
               "não-nulo, ou a troca de " + C("tx.origin") + " por "
               + C("msg.sender") + " — seguem um caminho que vai do detector ao "
               "código corrigido <b>sem passar pelo modelo de linguagem</b>. São "
               "oito classes hoje. O LLM só entra onde a correção exige julgamento "
               "sobre a intenção do contrato."))
    f.append(P("O modo " + C("--static-only") + " não cria essa propriedade: ele "
               "apenas expõe esse caminho como um modo de execução, o que torna a "
               "independência <b>verificável por terceiros</b>, em vez de uma "
               "afirmação de projeto."))

    f.append(P("A regra que adicionamos ao Slither", "h"))
    f.append(P("Dos <b>99 detectores nativos</b> do Slither 0.11.3, nenhum cobre "
               "escrita desprotegida em estado privilegiado; o mais próximo, "
               + C("events-access") + ", apenas verifica a emissão de eventos. O "
               "pipeline aproximava essa classe por heurística de nome, confiando "
               "em variáveis chamadas " + C("owner") + " ou " + C("admin") + " — o "
               "que produz falso positivo e falso negativo com igual facilidade."))
    f.append(P("No lugar dela foi escrito um detector de <b>552 linhas</b> sobre a "
               "representação intermediária do Slither (SlithIR), que decide pela "
               "forma como o próprio contrato trata cada variável, não pelo nome "
               "que ela recebeu:"))
    f.append(tabela([
        ["Categoria inferida", "Como o detector decide"],
        ["Autoridade",
         "A variável é comparada com quem chama (" + C("msg.sender == X") + "), ou "
         "é um mapa indexado pelo chamador cujo valor booleano libera a execução "
         "(" + C("require(admin[msg.sender])") + ")"],
        ["Destino de fundos",
         "É um endereço que recebe ether, por " + C("transfer") + ", " + C("send")
         + " ou " + C("call") + " com valor"],
        ["Parâmetro administrativo",
         "Toda outra função que escreve nela tem guarda de chamador, ou é o construtor"],
    ], [4.6 * cm, 12.4 * cm]))
    f.append(Spacer(1, 0.35 * cm))
    f.append(P("Uma função é reportada quando é pública ou externa, altera estado, "
               "não tem verificação de chamador em <i>nenhum</i> caminho — corpo, "
               "modificadores ou funções internas que ela chama — e sobrescreve uma "
               "dessas variáveis. Escritas indexadas pelo próprio chamador "
               "(" + C("balances[msg.sender] = ...") + ") e atualizações do tipo "
               + C("total += x") + " nunca são reportadas."))
    f.append(P("Duas decisões de engenharia que valem menção. O detector é "
               "registrado numa <b>instância privada</b> do Slither, nunca no "
               "registro global, de modo que uma execução normal da ferramenta "
               "continua inalterada. E a classe foi declarada como impacto alto e "
               "confiança média, deliberadamente: inferir pelo uso acerta mais que "
               "a heurística de nome, mas ainda não é prova."))
    f.append(P("A classe também ganhou reparo mecânico nesta semana: quando o "
               "contrato possui exatamente um modificador de identidade, esse "
               "modificador é restaurado na função desprotegida. Validado em "
               "mutantes reais de dois contratos.", "cap"))

    f.append(PageBreak())
    f.append(P("O que foi feito nesta semana", "h"))
    f.append(tabela([
        ["Frente", "Entrega"],
        ["Reparo mecânico de escrita desprotegida",
         "A classe " + C("unrestricted-write") + ", detectada por um plugin Slither "
         "próprio, passou a ser corrigida automaticamente pela restauração do "
         "modificador de identidade do contrato. Validado em mutantes reais"],
        ["Medição de detectabilidade",
         "Novo módulo que mede, só com análise estática, quais defeitos injetados "
         "são de fato visíveis. Revelou que apenas 9 de 46 mutantes eram "
         "detectáveis — resultados anteriores mediam o instrumento, não o agente"],
        ["Correção de quatro bloqueios em código real",
         "Sintaxe CVL inválida gerada pelo LLM, tipos de interface na spec, "
         "falsos positivos do normalizador e o " + C("owner()") + " herdado sem "
         "declaração " + C("envfree")],
        ["Contagem honesta de resolução",
         "A reanálise pós-correção não executava os detectores próprios, então um "
         "achado de plugin era contado como resolvido sem ter sido. Corrigido, "
         "com teste de regressão"],
        ["Lote de código de produção",
         "Seis contratos de codebases auditadas publicamente (Inverse, Escher, "
         "Maia) executados no pipeline completo"],
        ["Documentação e higiene",
         "Guia de projeto para retomada de contexto; raiz do repositório reduzida "
         "de 186 para 12 entradas, sem remover nada versionado nem nenhuma das 15 "
         "execuções citadas como evidência"],
    ], [5.0 * cm, 12.0 * cm]))

    f.append(P("O lote de produção, sem maquiagem", "h"))
    f.append(tabela([
        ["Contrato", "Projeto", "Situação"],
        ["SimpleERC20Escrow", "Inverse",
         "<b>Resolvido 2/2</b>, aprovado pelo Certora"],
        ["Initializable", "Escher",
         "Sem achado real: eram dois falsos positivos, já corrigidos"],
        ["GovTokenEscrow", "Inverse",
         "A spec compila e o Certora confirma 4 achados; parou em erro da API do LLM"],
        ["OpenEdition", "Escher",
         "Correção escrita, não verificada: cota diária da API esgotou"],
        ["TalosBaseStrategy", "Maia",
         "O LLM removeu funções públicas; o <i>patch guard</i> barrou, corretamente"],
        ["GovernorBravoDelegateMaia", "Maia",
         "<i>Stack too deep</i>: limite do compilador, sem solução no momento"],
    ], [4.3 * cm, 2.1 * cm, 10.6 * cm], destaque={1: ACCENT_SOFT}))
    f.append(P("Um de seis fechado de ponta a ponta. Prefiro apresentar assim, com "
               "os cinco casos em aberto, porque cada um aponta uma limitação "
               "diferente e específica — e quatro deles avançam mais no pipeline do "
               "que avançavam antes desta semana.", "cap"))

    f.append(PageBreak())
    f.append(P("O que proponho apresentar", "h"))
    f.append(B("<b>A reprodutibilidade, demonstrada ao vivo.</b> Executar o "
               "pipeline com a chave de API inválida e mostrar que a saída é a "
               "mesma. É rápido, não custa nada e responde de antemão à pergunta "
               "mais provável da banca."))
    f.append(B("<b>A arquitetura em camadas:</b> o que é determinístico, o que "
               "depende do modelo, e por que essa separação é deliberada."))
    f.append(B("<b>O caso " + C("unrestricted-write") + ":</b> uma classe que o "
               "Slither não cobre, detectada por plugin próprio e corrigida "
               "mecanicamente — do detector ao reparo validado."))
    f.append(B("<b>Os limites, nomeados:</b> a generalização do modelo ainda não "
               "está demonstrada, e um quarto dos arquivos de produção sequer "
               "compila na análise. São resultados, não omissões."))

    f.append(P("Próximos passos", "h"))
    f.append(B("Reexecutar os três contratos bloqueados quando a cota da API "
               "restabelecer."))
    f.append(B("Investigar os 38 arquivos de produção em que a análise estática "
               "falha — cerca de um quarto dos candidatos reais."))
    f.append(B("Medir, sobre todo o corpus, qual proporção das correções dispensa "
               "o modelo de linguagem. Essa medição não depende de cota de API e é "
               "o número que melhor sustenta a contribuição do trabalho."))

    doc.build(f, onFirstPage=chrome, onLaterPages=chrome)
    print(f"escrito: {OUTPUT_PDF}")


if __name__ == "__main__":
    build()
