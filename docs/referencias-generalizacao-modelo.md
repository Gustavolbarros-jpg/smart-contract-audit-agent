# Referências-base para generalização do modelo de IA

Os três artigos abaixo (recebidos como PDFs no WhatsApp — `3765753`, `3765751`, `3764867`) são todos da revista **ACM Transactions on Software Engineering and Methodology (TOSEM)**, publicados em 2025–2026. Todos tratam de análise de smart contracts com LLMs, e cada um cobre um ângulo diferente que podemos usar para generalizar o pipeline (hoje baseado em diagnósticos determinísticos por detector do Slither).

## 1. CodeXplain — "From Cryptic to Clear: Training on LLM Explanations to Detect Smart Contract Vulnerabilities"

- **Link:** https://dl.acm.org/doi/10.1145/3765753
- **Autores:** Yizhou Chen, Zeyu Sun, Guoqing Wang, Qing-Lin Liang, Xiao Yu, Dan Hao
- **Resultado:** F1 de 94,12% e acurácia de 93,88% em 3.544 contratos reais, superando 16 métodos estado-da-arte.

**Método:** parte do princípio de que LLMs decoder-only (GPT etc.) sozinhos têm acurácia baixa em detecção de vulnerabilidades, porque não foram treinados com rótulos. A solução tem 3 etapas:

1. Análise de **14 tipos de vulnerabilidades** comuns/perigosas; a partir do racional de cada uma, são criados **9 prompts de perspectiva** que guiam o LLM a gerar *explicações do código* úteis para detecção.
2. Um módulo de **fusão semântica baseado em CodeT5** integra o código do contrato + as explicações geradas pelo LLM.
3. **Aprendizado supervisionado** sobre rótulos confiáveis refina a detecção.

**Como usar no nosso pipeline:** é a referência mais direta para substituir/complementar o diagnóstico determinístico. Em vez de mapear cada detector do Slither para um diagnóstico fixo, o LLM gera explicações do código sob perspectivas fixas (reentrância, overflow, controle de acesso etc.) e essas explicações viram a entrada do diagnóstico e do patch. A ideia dos "perspective prompts" por categoria de vulnerabilidade generaliza o que hoje fazemos caso a caso.

## 2. MANDO-LLM — "Heterogeneous Graph Transformers with Large Language Models for Smart Contract Vulnerability Detection"

- **Link:** https://dl.acm.org/doi/10.1145/3765751 (acesso aberto, licença CC-BY)
- **Autores:** Nhat-Minh Nguyen, H. Nguyen, Long Le Thanh, Zahra Ahmadi, Thanh-Nam Doan, Daoyuan Wu, Lingxiao Jiang
- **Resultado:** melhorias de F1 de 0,59% a 80,72% no nível de contrato; um dos primeiros métodos eficazes de detecção **no nível de linha** (+3% a +95% conforme o tipo).
- **Código relacionado:** https://github.com/MANDO-Project/ge-sc-transformer (MANDO-HGT, versão anterior)

**Método:** representa o contrato como **grafo heterogêneo** construído a partir do control-flow graph e do call graph. LLMs extraem features de código dos nós; um **Heterogeneous Graph Transformer** aprende embeddings com meta-relações nó-aresta específicas; classificadores detectam vulnerabilidades no nível de contrato **e de linha**.

**Como usar no nosso pipeline:** o ponto-chave para generalização é que o MANDO-LLM **não precisa de padrões definidos manualmente** — retreina-se para novos tipos de vulnerabilidade. Isso ataca exatamente a limitação atual do nosso pipeline (cada detector novo do Slither exige lógica determinística nova). A localização por linha também alimenta diretamente a geração de patch (saber a linha exata a corrigir). O Slither já nos dá CFG e call graph, então a representação em grafo é viável com o que temos.

## 3. CCIHunter — "Enhancing Smart Contract Code–Comment Inconsistencies Detection via Two-Stage Pre-Training"

- **Link:** https://dl.acm.org/doi/10.1145/3764867
- **Autores:** Ziwei Li, Jiajing Wu, Zhiying Wu, Dongchen Tan, Weipeng Zou, Zigui Jiang, Yi Zhen, Zheng Zhang, Zibin Zheng
- **Resultado:** precisão 0,95, recall 0,90, F1 0,93, superando ferramentas existentes.

**Método:** detecta **inconsistências entre código e comentários** (CCI) — quando a lógica implementada não bate com a intenção descrita. Enriquece comentários com templates, modela o código como grafo heterogêneo de chamadas de função, gera embeddings com **CodeBERT** (comentários) e **UniMP** (código) e julga consistência pela similaridade entre os dois. O diferencial é o **pré-treinamento em 2 estágios sem dados rotulados**: contrastive learning + análise de mutação.

**Como usar no nosso pipeline:** dois usos. (a) Os comentários expressam a *intenção* do contrato — a mesma informação que usamos para gerar specs do Certora; a técnica de alinhar intenção × implementação pode guiar a geração automática de regras CVL. (b) O pré-treinamento sem rótulos (contrastive + mutação) é a resposta para o nosso problema de escassez de dados: dá para gerar dados de treino mutando os contratos do próprio benchmark.

## Síntese — estratégia de generalização

| Limitação atual do pipeline | Artigo que resolve | Técnica |
|---|---|---|
| Diagnóstico determinístico por detector (não escala) | CodeXplain | Prompts de perspectiva por categoria + explicações do LLM como entrada |
| Novos tipos de vulnerabilidade exigem código novo | MANDO-LLM | Grafo heterogêneo (CFG + call graph do Slither) + retreino sem padrões manuais |
| Localização imprecisa do trecho a corrigir | MANDO-LLM | Detecção no nível de linha |
| Specs CVL escritas à mão / poucos dados rotulados | CCIHunter | Intenção via comentários + pré-treino sem rótulos (contrastive + mutação) |

> **Nota:** este resumo foi montado a partir dos abstracts e metadados oficiais (API do Semantic Scholar); os PDFs completos estão atrás do paywall da ACM. Para os detalhes de implementação (arquiteturas exatas, hiperparâmetros, datasets), colocar os 3 PDFs do WhatsApp em `docs/referencias/` quando conseguir baixá-los.
