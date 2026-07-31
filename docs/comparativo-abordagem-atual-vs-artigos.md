# Nossa abordagem hoje × a abordagem dos 3 artigos × como melhorar a correção

Documento de decisão técnica. Lido a partir do código atual (`agent/`) e dos PDFs completos
dos 3 artigos ACM TOSEM (`3765753`, `3765751`, `3764867`), agora em `docs/referencias/`.

---

## 1. O que o nosso pipeline faz hoje, e como

`agent/orchestrator.py` (1.146 linhas) executa 6 etapas sequenciais:

| Etapa | O que faz | Onde |
|---|---|---|
| 1 | Slither → JSON → normalização determinística | `core/slither_normalizer.py` (979 ln) |
| 2 | LLM decide **quais** achados formalizar (`PlanoFormal`) | `core/formal_plan.py` |
| 3 | Gera spec CVL + autocorrige com ~15 transformações regex | `tools/spec_validator.py` (1.032 ln) |
| — | Certora no contrato **original** → `confirmed` / `confirmed_static` | `tools/certora_cli.py` |
| 5 | Diagnostica → gera patch → valida patch | `core/diagnosis_context.py`, `core/deterministic_patch.py`, `core/patch_guard.py` (1.056 ln) |
| 6 | Loop ≤3 tentativas: Certora no FIXED → contraexemplo → re-diagnose/re-fix | `MAX_TENTATIVAS_CORRECAO = 3` |

### Como a correção acontece de fato

1. **Diagnóstico**: `deterministic_diagnosis()` consulta `DETERMINISTIC_REPAIR_HINTS` —
   um dict com **6 entradas fixas** (`missing-zero-check`, `tx-origin`, `suicidal`,
   `arbitrary-send-eth`, `unchecked-lowlevel`, `erc2771-multicall-context`). Cada entrada é um
   par `{motivo, correcao}` escrito à mão. Se o detector não está no dict, cai para o LLM sem guia.
2. **Patch**: `apply_deterministic_patches()` cobre **exatamente 1 classe** — `missing-zero-check`
   (`deterministic_patch.py:18`). Localiza a função por regex `function\s+NOME\s*\(` e insere
   `require(param != address(0), ...)`. Todo o resto vai para o LLM.
3. **Validação**: `patch_guard.py` verifica se o patch mexeu só nas linhas permitidas
   (`allowed_ranges`), depois Certora confirma formalmente.
4. **Aprendizado**: `fix_library.json` guarda snippets `(vuln_type, fix_snippet)` como few-shot.
   É cache, não modelo — nada generaliza entre contratos.

### As 3 limitações estruturais (confirmadas no código)

**(a) Tudo é indexado por nome de detector do Slither.** Adicionar uma classe de vulnerabilidade
exige entradas novas em pelo menos 3 dicts — `VULNERABILITY_CATALOG` (flag `formalizable`),
`SPEC_PATTERNS` (6 chaves), `DETERMINISTIC_REPAIR_HINTS` (6 chaves) — e frequentemente regex nova
em `deterministic_patch` e `patch_guard`. Custo linear por classe, escrito à mão.

**(b) Cobertura formal estreita.** No `vulnerability_catalog.py`, apenas 6 tipos são
`formalizable: True` (tx-origin, arbitrary-send-eth, suicidal, missing-zero-check,
integer-overflow/underflow). Reentrância — a classe mais explorada em produção — está
`formalizable: False` com a nota *"temporarily kept out of Certora"*.

**(c) Dependência de compilação.** Slither exige `solc` resolvido; Certora exige `solc` + config.
Em projeto real isso quebra: os 7 projetos em `smart-audt/contracts/real/` têm de 3 a 586 arquivos
`.sol`, `foundry.toml`, `lib/` e `remappings.txt`. `core/import_context.py` já resolve remappings
(bom), mas `run_slither_raw()` chama `slither <arquivo>` — modo arquivo único, não modo projeto.

---

## 2. O que cada nova abordagem faz (método real, não abstract)

### CodeXplain — explicações do LLM como *feature* de treino

**Problema que atacam:** LLM decoder-only sozinho erra muito em detecção porque nunca viu rótulo;
modelo pré-treinado (CodeT5) aceita rótulo mas não entende o código em profundidade.

**Método (3 módulos):**
1. **9 prompts de perspectiva**, fixos e independentes de vulnerabilidade — *Basic Functionality
   Interpretation, Step-by-Step Analysis, Logic and Flow Interpretation, State Management Analysis,
   Event and Function Interaction, Error Handling and Exceptions, Contract Interaction Analysis,
   Ownership and Access Control, Gas Efficiency Examination*. Os prompts literais estão nas p. 8–9.
   A Tabela 1 (p. 7) mapeia **14 vulnerabilidades → subconjunto de perspectivas** (ex.: reentrância →
   State Management + Logic and Flow + Basic Functionality).
2. **Fusão semântica CodeT5**: código e as 9 explicações são embutidos separadamente pelo *mesmo*
   CodeT5; cross-attention usa as explicações como K/V e o código como Q, iterando as 9 com camada
   residual, ordem embaralhada a cada passo de treino.
3. **Supervisão** sobre rótulos confiáveis → softmax binário.

**Resultado:** F1 94,12% / acurácia 93,88% em 3.544 contratos reais; supera 16 métodos SOTA.
Código em `github.com/chenpp1881/CodeXplain`.

**Limite:** é **detecção binária em nível de contrato**. Não localiza linha, não gera correção.

### MANDO-LLM — grafo heterogêneo + tokenizer de LLM, detecção por linha

**Método (5 componentes):**
1. **HCG Generator** — usa **tree-sitter** (não solc!) para o AST. Gera HCFG (tipos de nó
   `EXPRESSION`, `NEW_VARIABLE`, `RETURN`, `IF`, `END_IF`, `IF_LOOP`, `END_LOOP`; arestas
   `NEXT`/`TRUE`/`FALSE`) e HCG (`INTERNAL_CALL`, `EXTERNAL_CALL`, `CONTRACT_DECLARATION`,
   `FUNCTION_NAME`, `FALLBACK_NODE`), depois funde os dois pelos nós `FUNCTION_NAME`.
   Trocaram Slither por tree-sitter **exatamente** por causa de conflito de versão de solc e libs
   faltando (p. 4).
2. **Meta Relations Extractor** — relações `⟨tipo_origem, tipo_aresta, tipo_destino⟩` descobertas
   **dinamicamente** durante o treino (até 18 tipos de nó × 5 de aresta = 1.620 possíveis; na prática
   dezenas a centenas por contrato). Isso substitui metapaths definidos à mão.
3. **Node Features Extractor** — usa **só o tokenizer** do LLM (Solidity-T5 770M, StarCoder 15.5B,
   CodeT5p-770m), não o encoder inteiro. Escolha deliberada de custo: herda o conhecimento
   pré-treinado sem fine-tuning, "de dias para horas".
4. **HGT** — atenção mútua heterogênea + message passing + agregação por tipo de nó.
5. **Detector em 2 fases** — Fase 1: classificação de **grafo** (contrato limpo/vulnerável, score >0,5
   por tipo de bug); Fase 2: classificação de **nó** nos contratos suspeitos → cada nó é um statement,
   logo **localização por linha**.

**Resultado:** +0,59% a +80,72% F1 em nível de contrato; +3% a +95% em nível de linha. 7 tipos
(Access Control, Arithmetic, DoS, Front Running, Reentrancy, Time Manipulation, Unchecked Low-Level
Calls). Datasets: Smartbugs Curated (143 contratos / 208 tags), SolidiFI (9.369 injetadas / 350
contratos), DAppSCAN (39.904 arquivos / 682 projetos / 1.618 SWC), 2.742 contratos limpos.
Código: `github.com/MANDO-Project/ge-sc-llm`.

**Limite:** precisa treinar. Sem dataset rotulado, não roda.

### CCIHunter — intenção (comentário) × implementação, pré-treino sem rótulo

**Método (4 partes):**
1. **Modelagem de dados** — código: solc → AST → **AST+**, que substitui cada nó `FunctionCall`
   pelo AST da função chamada, **com limite de 2 expansões**. O limite é medido, não arbitrário:
   em 14.039 funções de 16 DApps, 84,50% têm profundidade de chamada 1, 11,97% têm 2, 2,68% têm 3.
   Comentários: template textual *"This is a function named X, and the corresponding documentation is
   Y; during its execution it calls Z, which has the comment W…"*, com **recuperação de referência** —
   um `@See {IERC721-transferFrom}` é resolvido buscando o comentário no contrato padrão.
2. **Embedding** — CodeBERT nos comentários, UniMP (GNN) no AST+.
3. **Pré-treino em 2 estágios, sem rótulo**:
   - *Contrastive learning*: pares código–comentário, positivo = par real, negativos = os outros do
     batch (n=64, 15.625 batches); maximiza SimScore (cosseno) do positivo.
   - *Mutation analysis*: 7 operadores — **AOR** (Assignment Operator Replacement), **BOR** (Binary
     Operator Replacement), **UOR** (Unary Operator Replacement), **Event Emission Deletion**,
     **Modifier Deletion**, **Payable Keyword Replacement**, **Function Visibility Replacement** —
     e treina para *maximizar* a distância entre original e mutante.
4. **Detecção** — SimScore + concat(code_emb, comment_emb) → classificador.

**Resultado:** precisão 0,95 / recall 0,90 / F1 0,93.

**Limite:** detecta *inconsistência de intenção*, não vulnerabilidade. Serve como oráculo de
propriedade, não como detector de exploit.

---

## 3. Como isso melhora a nossa correção de contratos

Ponto importante antes de mapear: **o gargalo do nosso pipeline não é detecção.** O Slither já
detecta bem. O gargalo é (i) generalização do diagnóstico+patch para classes que não enumeramos,
(ii) fragilidade de compilação em projeto real, (iii) provar que o patch está certo.

Priorizado por custo de implementação × ganho:

### Fase 1 — barato, sem treino, ganho imediato

**1.1 Perspective prompts substituem `DETERMINISTIC_REPAIR_HINTS`** (CodeXplain)
Em vez de `if detector == X: hint = HINTS[X]`, rodar um subconjunto de perspectivas sobre a função
afetada e usar as explicações como entrada de diagnóstico e de patch. Efeito: o diagnóstico passa a
funcionar para detector que nunca cadastramos — o dict de 6 entradas deixa de ser o teto.
Mitigação de custo: selecionar 2–3 perspectivas por *categoria* (o campo `category` já existe no
`vulnerability_catalog`), no espírito da Tabela 1, em vez de rodar as 9 sempre.
Ressalva honesta: no artigo as explicações alimentam um classificador **treinado**. Sem treino
ganhamos o efeito de contexto, não o F1 de 94% — é melhora de generalização, não de acurácia medida.

**1.2 AST+ com expansão de chamada nível 2 no contexto do LLM** (CCIHunter)
Hoje `build_contract_brief` / `build_methods_block` dão assinaturas. Trocar por corpo das funções
chamadas inlined até profundidade 2. O próprio artigo mostra o modo de falha que isso corrige
(Exemplo 1, p. 6): `transferFrom` parecia não checar saldo porque a checagem estava dentro de
`safeSub`. É exatamente o falso-diagnóstico que nosso patch parcial produz hoje.

**1.3 Operadores de mutação como suíte de regressão** (CCIHunter)
Aplicar os 7 operadores **ao contrário**: partir de um contrato FIXED e re-injetar o bug, então
verificar se o pipeline detecta e corrige de novo. `Modifier Deletion` e
`Function Visibility Replacement` geram precisamente bugs de controle de acesso; `BOR` gera
off-by-one em `require`. Hoje temos 83 testes unitários e 3 contratos de benchmark — isso vira
um gerador de casos, não uma lista fixa.

### Fase 2 — médio esforço, resolve o bloqueio de contrato real

**2.1 tree-sitter como camada de parsing independente de compilação** (MANDO-LLM)
Este é o item de maior impacto prático. Adotar o *representation* (HCFG+HCG fundido) como índice
determinístico, sem treinar HGT ainda. Ganhos diretos:
- Ingestão de contrato que não compila (o caso normal em projeto real de 500 arquivos).
- **Localização por nó de statement** para o patcher. Hoje `_insert_zero_check` acha a função por
  `re.search(r"function\s+NOME\s*\(")` — quebra com overload, modifier multi-linha, assinatura
  quebrada em várias linhas. Posição de nó resolve isso e é independente de detector.
- Contexto de call-graph para o prompt, de graça.

**2.2 NatSpec como fonte de propriedade CVL** (CCIHunter)
`SPEC_PATTERNS` tem 6 padrões escritos à mão. `@notice`/`@dev`/`@param` declaram a invariante
pretendida em linguagem natural. O template de comentário deles — com recuperação de referência
para IERC20/IERC721 — é receita direta para montar o contexto de geração de spec. Contrato real
derivado de OpenZeppelin é rico em NatSpec: é onde isso rende.

**2.3 Refator: `VulnerabilityEvidence` não indexada por detector**
Estrutura `{location: nó, category, evidence: [explicações], intent: comentário, property: CVL}`.
Nome do detector do Slither passa a ser *uma* fonte de evidência entre várias. É a mudança que
mata a limitação (a) na raiz.

### Fase 3 — escala de pesquisa, só com dataset

**3.1 Treinar HGT para detecção por linha** (MANDO-LLM)
Exige os datasets do artigo (Smartbugs Curated + SolidiFI + DAppSCAN). Combinável com 1.3: os
operadores de mutação do CCIHunter geram dados rotulados a partir do nosso próprio benchmark,
que é a resposta deles para escassez de rótulo. Só entrar aqui depois das fases 1 e 2.

---

## 4. Plano de teste com os contratos reais

Estado verificado de `smart-audt/contracts/real/`:

| Projeto | `.sol` | Build | Observação |
|---|---:|---|---|
| solmate | 3 | — | **começar aqui**: mínimo de dependência |
| inverse | 33 | remappings.txt | sem foundry.toml |
| astaria | 60 | foundry.toml + lib | |
| runes | 103 | hardhat + node_modules | |
| maia | 372 | foundry + hardhat | |
| caviar | 512 | foundry.toml + lib | |
| escher | 586 | foundry.toml + remappings | |

Todos são projetos de auditoria reais (perfil Code4rena), com `discord-export` — ou seja, há
achados de referência para comparar.

### Medição real (2026-07-30) — etapas 1 e 2 executadas

O `inverse` é o único projeto íntegro neste ambiente (0 libs faltando, pragmas com caret que
aceitam o solc 0.8.21 local). Slither rodou nele **sem mudança nenhuma de código** — a hipótese de
que precisávamos de "modo projeto" estava errada; o modo arquivo único funciona quando o solc está
disponível e as remappings resolvem (`import_context.py` já faz isso corretamente).

Os outros projetos estão bloqueados por **falta de rede**, não por limitação do pipeline:
submódulos git nunca clonados (`lib/gpl` em astaria, 5/7 em maia) e solc pinado que o solc-select
não consegue baixar (astaria `=0.8.17`, caviar `0.8.19`, maia `0.8.18`; local só tem 0.8.20/21/26).

**Cobertura do catálogo em 5 contratos reais do `inverse` — 108 achados:**

| | achados | % |
|---|---:|---:|
| `formalizable: True` (chega ao Certora) | 18 | **17%** |
| catalogado mas `formalizable: False` | 22 | 20% |
| **fora do catálogo** | **68** | **63%** |

Dos 18 formalizáveis, 17 são `missing-zero-check` e 1 é `tx-origin`. Entre os 68 fora do catálogo
há ruído informacional (`naming-convention` 22, `solc-version` 5, `too-many-digits` 4), mas também
segurança real: `reentrancy-events` 11, `unchecked-transfer` 7, `divide-before-multiply` 5,
`incorrect-equality` 2.

Este é o argumento quantificado para a Fase 1: a abordagem indexada por detector cobre 17% do que
um contrato real produz.

**Etapas, em ordem, cada uma com critério de parada:**

1. **Passe de ingestão (parse-only).** Medir quantos contratos conseguimos sequer ler. Métrica:
   % de arquivos parseados. Rodar com solc *e* com tree-sitter para quantificar o ganho do item 2.1
   — esse número é o que justifica (ou não) a Fase 2.
2. **Passe Slither com remappings.** `import_context.solc_remappings()` já existe; falta `run_slither_raw`
   suportar modo projeto (`slither .`) em vez de arquivo único. Métrica: achados por projeto,
   por detector — mostra quais classes aparecem em produção e se as 6 `formalizable: True` cobrem
   o que importa. Suspeita a testar: reentrância vai dominar, e está fora do Certora hoje.
3. **Diagnose + patch em shortlist.** Selecionar contratos de arquivo único e baixa dependência
   (solmate primeiro). Métrica: patch aplicado sem violar `patch_guard`.
4. **Certora só na shortlist.** Job de nuvem é caro e precisa de config por contrato — não rodar
   em massa. Métrica: violação eliminada sem regressão nas outras rules.

Ordem importa: etapa 1 é diagnóstico do próprio pipeline e custa quase nada; etapa 4 é a caríssima.
Não pular para a 4.

---

## Resumo em uma linha por artigo

- **CodeXplain** → como fazer o diagnóstico deixar de ser um dict de 6 entradas (barato, já).
- **MANDO-LLM** → como parar de depender de compilação e localizar a linha exata (médio, desbloqueia contrato real).
- **CCIHunter** → como gerar nossos próprios dados de teste e tirar a propriedade CVL do NatSpec (barato + médio).
