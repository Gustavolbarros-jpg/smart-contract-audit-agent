# Relatório Final de Iniciação Científica

**Discente:** Gustavo Ferreira Leite de Barros (20240020300)
**Orientador:** Alexandre Cabral Mota
**Centro:** Centro de Informática (CIn) — UFPE
**Projeto:** PIC2192-2025 — Verificação Formal e Sugestão Automática de Propriedades em
Contratos Inteligentes: Integrando LLMs e Preservação Semântica
**Plano de Trabalho:** Abordagem Experimental para Comprovação de Otimização de Gás em
Contratos Inteligentes Solidity
**Período de execução:** 01/09/2025 a 31/08/2026
**Situação atual do projeto:** ( ) Em andamento ( ) Concluído *(confirmar antes do envio)*
**Versão deste documento:** snapshot de 23/11/2026

> Este documento é um snapshot novo e **não substitui** `docs/relatorio-final-pibic-2026.md`
> (08/11/2026), que fica preservado como registro histórico. O que mudou desde aquela versão
> está nas Seções **5.5** (oráculo formal local, 17/11) e **5.6** (propositor de propriedades
> e propriedades de *liveness*, 18/11), e refletido nas Seções 6 e 7.

---

## 1. Introdução

Contratos inteligentes são programas executados em blockchain que automatizam transações e
serviços digitais sem intermediário central. Como administram diretamente recursos financeiros
e, uma vez implantados, são difíceis ou impossíveis de modificar, uma vulnerabilidade ou uma
alteração incorreta no código pode causar prejuízo financeiro imediato e irreversível — ao
contrário de software convencional, não há como aplicar um patch de emergência depois que o
contrato já está em produção na rede.

Um segundo fator de pressão sobre esse código é o custo de execução: toda operação em uma rede
como a Ethereum consome **gás**, cobrado do usuário em cada transação. Esse custo cria um
incentivo real para otimizar contratos — reduzir armazenamento, simplificar laços, eliminar
checagens redundantes. O problema é que essas mesmas otimizações são uma fonte comum de
regressão de segurança: uma checagem removida por parecer redundante pode ser exatamente a
checagem que impedia uma exploração. Otimizar sem verificar é trocar custo de gás por risco de
exploração.

Este trabalho parte dessa tensão para propor e validar uma abordagem automatizada que combina
**análise estática** (Slither), **modelos de linguagem** (LLM) e **verificação formal**
(Certora Prover) em uma pipeline única: identificar vulnerabilidades reais, formalizar as
propriedades de segurança violadas, corrigir o contrato e **provar matematicamente** — não
apenas testar por exemplos — que a versão corrigida preserva o comportamento esperado. É essa
capacidade de prova formal que torna a abordagem adequada como rede de segurança para mudanças
no contrato, incluindo mudanças motivadas por otimização de gás: qualquer alteração no código,
por economia ou por correção, pode ser revalidada contra as mesmas propriedades formais antes de
ser aceita.

## 2. Objetivos

### 2.1 Objetivo geral

Projetar, implementar e validar uma pipeline automatizada que identifique, diagnostique,
corrija e valide formalmente vulnerabilidades de segurança em contratos inteligentes escritos em
Solidity, combinando análise estática, modelos de linguagem e verificação formal, de modo que o
mesmo mecanismo sirva como salvaguarda para mudanças no contrato motivadas por otimização de
custo de execução (gás).

### 2.2 Objetivos específicos

- Integrar análise estática (Slither) como fonte determinística de evidência de vulnerabilidade.
- Usar um LLM para planejar quais achados são formalizáveis, gerar as propriedades em CVL
  (Certora Verification Language) e diagnosticar/corrigir os casos confirmados.
- Usar o Certora Prover para confirmar formalmente violações de propriedade e obter
  contraexemplos concretos, e para revalidar o contrato corrigido.
- Construir salvaguardas determinísticas (*guardrails*) que limitem o que o LLM pode gerar ou
  alterar, reduzindo o risco de correções incorretas ou fora de escopo.
- Avaliar a abordagem em um benchmark controlado e em contratos reais de auditorias públicas
  (Code4rena), medindo cobertura, taxa de resolução e minimalidade das correções.
- Investigar a generalização da pipeline para além dos padrões cadastrados manualmente,
  incorporando técnicas recentes da literatura (prompts de perspectiva, contexto por grafo de
  chamadas, geração de casos de teste por mutação).

## 3. Fundamentação Teórica

A abordagem determinística por detector — mapear cada tipo de achado do Slither a uma regra de
diagnóstico e correção escrita à mão — tem limite estrutural conhecido: cada classe nova de
vulnerabilidade exige código novo, e a cobertura fica presa ao que foi cadastrado manualmente.
Para endereçar essa limitação, o trabalho se apoiou em três artigos recentes (2025–2026) da ACM
Transactions on Software Engineering and Methodology (TOSEM), cada um cobrindo um ângulo
diferente do problema de detecção de vulnerabilidades em contratos inteligentes com LLMs:

**CodeXplain** (Chen et al.) propõe gerar, para cada contrato, explicações de código guiadas por
nove *prompts de perspectiva* fixos (ex.: análise de fluxo lógico, controle de acesso, gestão de
estado), que alimentam um classificador treinado. Relata F1 de 94,12% em 3.544 contratos reais.
A contribuição aproveitada aqui foi a ideia dos prompts de perspectiva como substituto de um
dicionário fixo de dicas de correção por detector.

**MANDO-LLM** (Nguyen et al.) representa o contrato como grafo heterogêneo construído a partir
de um AST obtido via **tree-sitter** — não via compilador —, o que permite analisar código que
não compila, situação comum em repositórios reais grandes. Relata melhorias de F1 de até 80,72%
no nível de contrato e detecção no nível de linha. A contribuição aproveitada foi a adoção de
tree-sitter como camada de parsing independente de compilação.

**CCIHunter** (Li et al.) detecta inconsistências entre o código implementado e a intenção
declarada em comentários (NatSpec), usando profundidade de expansão de chamada de função
limitada a 2 níveis — limite validado empiricamente pelos autores em 14.039 funções reais
(84,50% de profundidade 1, 11,97% de profundidade 2) — e usa sete operadores de mutação de
código (troca de operador aritmético/binário/unário, remoção de evento, remoção de modifier,
troca de `payable`, troca de visibilidade de função) como técnica de pré-treino sem rótulo.
Relata precisão de 0,95 e F1 de 0,93. As contribuições aproveitadas foram o contexto de chamada
em profundidade 2 e os operadores de mutação como gerador de casos de teste de regressão.

## 4. Metodologia

### 4.1 Arquitetura da pipeline

A pipeline é organizada em seis etapas sequenciais:

1. **Análise estática.** O Slither analisa o contrato-fonte e os achados brutos são normalizados
   (`agent/core/slither_normalizer.py`) em classes estáveis de vulnerabilidade, desacoplando o
   restante da pipeline do formato de saída específico da ferramenta.
2. **Planejamento formal.** Um LLM decide, entre os achados normalizados, quais são candidatos a
   verificação formal, com base em um catálogo de vulnerabilidades (`vulnerability_catalog.py`)
   que classifica cada classe como formalizável via Certora, estática-confirmada ou apenas
   revisão manual.
3. **Geração de propriedade formal.** Para cada candidato, é gerada uma especificação em CVL. Um
   validador determinístico (`tools/spec_validator.py`) corrige automaticamente erros sintáticos
   comuns do CVL gerado pelo LLM (blocos `methods{}` mal formados, tipos incompatíveis,
   instruções múltiplas em uma linha, regras planejadas mas nunca escritas), sem gastar uma
   chamada de LLM adicional para isso.
4. **Verificação formal.** O Certora Prover roda a especificação contra o contrato original. Uma
   violação confirmada vem acompanhada de um contraexemplo concreto (valores de entrada que
   quebram a propriedade), extraído e reaproveitado nas etapas seguintes.
5. **Diagnóstico e correção.** Para classes de vulnerabilidade conhecidas, o diagnóstico é
   determinístico (sem chamada de LLM); para o restante, o LLM diagnostica a causa raiz e propõe
   um patch, recebendo o contrato completo para preservar imports, structs, modifiers e
   invariantes locais.
6. **Validação do patch.** Um *patch guard* (`core/patch_guard.py`) verifica que a correção é
   mínima — bloqueia mudança de assinatura pública, remoção de variável de estado, alteração de
   string literal fora de escopo — antes de o Slither e o Certora rodarem novamente sobre a
   versão corrigida. Se a primeira tentativa é bloqueada, uma nova tentativa (até 3 no total)
   recebe o relatório do guard e o contraexemplo da falha anterior.

Essa combinação de LLM com validadores determinísticos foi uma escolha deliberada de projeto:
usar o LLM onde julgamento é necessário (planejamento, diagnóstico semântico, geração inicial de
código/CVL) e reservar regras determinísticas para tudo que é decidível sintaticamente — o que
reduz custo de chamadas ao modelo e elimina uma classe inteira de erro (a LLM “esquecer” de
escrever uma regra que ela mesma planejou, por exemplo).

### 4.2 Generalização além do catálogo manual

A segunda frente de trabalho, motivada pela literatura descrita na Seção 3, endereçou a
limitação estrutural de depender de um catálogo fixo de detectores:

- **Prompts de perspectiva** (`core/perspectives.py`): implementadas as nove perspectivas do
  CodeXplain e a tabela de mapeamento vulnerabilidade → subconjunto de perspectivas, injetadas
  no prompt de diagnóstico sem custo de chamada extra de API.
- **Contexto por grafo de chamadas** (`core/call_expansion.py`): busca em largura no grafo de
  chamadas a partir da função do achado, profundidade 2 (valor validado empiricamente pelo
  CCIHunter), incluindo modifiers aplicados como chamada — é onde normalmente mora o guard de
  controle de acesso. Isso corrigiu um caso real de diagnóstico falso: um `require` de
  autorização dentro de um modifier sem parênteses não aparecia no contexto enviado ao LLM, que
  diagnosticava “controle de acesso ausente” em uma função que na verdade já era protegida.
- **Parsing independente de compilador** (`core/treesitter_source.py`): adoção de tree-sitter
  como alternativa ao parser por expressão regular, com fallback automático. Validado em 2.035
  arquivos `.sol` reais.
- **Operadores de mutação como suíte de regressão** (`core/mutation.py`): os sete operadores do
  CCIHunter aplicados na direção inversa — a partir de um contrato já corrigido, reinjetam um
  defeito por vez — para gerar casos de teste sem depender de um dataset rotulado externo.

### 4.3 Avaliação

A avaliação foi feita em duas frentes: um benchmark controlado de contratos escritos
especificamente para exercitar classes conhecidas de vulnerabilidade, e um conjunto de contratos
reais extraídos de auditorias públicas do Code4rena, usados como teste de generalização sem
nenhum ajuste específico de regra para o contrato-alvo.

## 5. Resultados

### 5.1 Benchmark controlado

| Contrato | Achados Slither | Selecionados | Confirmados | Resolvidos | Taxa |
|---|---:|---:|---:|---:|---|
| SimpleBank | 12 | 4 | 4 | 4 | 4/4 |
| King | 9 | 4 | 4 | 4 | 4/4 |
| CrowdfundingVault | 16 | 4 | 4 | 4 | 4/4 |
| DeFiVault | 19 | 5 | 5 | 5 | 5/5 |
| ERC2771MulticallVulnerable | 8 | 1 | 1 | 1 | 1/1 |
| EnterpriseTreasury300 (327 linhas) | 26 | 9 | 9 | 9 | 9/9 |

Três contratos adicionais (`TimelockVault`, `AnotherVulnerableBank`, `VulnerableBankToken`)
serviram de controle negativo — a pipeline corretamente não gerou nenhum candidato acionável,
evitando falso positivo.

### 5.2 Contratos reais (Code4rena)

| Projeto / arquivo | Tamanho | Resultado |
|---|---:|---|
| Solmate `WETH.sol` | — | 0 candidatos acionáveis (controle negativo real) |
| Forgotten Runes `ForgottenRunesWarriorsMinter.sol` | — | 71 achados normalizados → 2/2 resolvidos (`missing-zero-check`) |
| Inverse `Market.sol` | 621 linhas | 63 achados normalizados → 3/3 resolvidos (`missing-zero-check`) |
| Escher `FixedPrice.sol` | — | 0 candidatos — evitou falso positivo em `selfdestruct` interno |
| Caviar `PrivatePool.sol` | 794 linhas | 0 candidatos acionáveis; validou compilação de repositório Foundry real com `remappings.txt` |
| Astaria (`PublicVault.sol`, `AstariaRouter.sol`, `LienToken.sol`) | 725–919 linhas | Bloqueado — dependência de submódulo privado não pôde ser clonada no ambiente de teste |

Em todos os casos resolvidos, o *patch guard* aprovou a correção final com 0 erros e 0 avisos
fora de escopo, e a revalidação (Slither + Certora) confirmou a eliminação da vulnerabilidade
sem regressão nas demais propriedades.

### 5.3 Cobertura do catálogo em código real

Uma medição feita sobre 5 contratos reais do projeto Inverse (108 achados normalizados de
Slither) quantificou a limitação estrutural que motivou o trabalho de generalização:

| Categoria | Achados | % |
|---|---:|---:|
| Formalizável (chega ao Certora) | 18 | 17% |
| Catalogado, mas não formalizável | 22 | 20% |
| Fora do catálogo | 68 | 63% |

Dos 18 achados formalizáveis, 17 são `missing-zero-check` e 1 é `tx-origin`. Entre os 68 fora do
catálogo há tanto ruído informacional (convenção de nomes, versão de solc) quanto vulnerabilidade
de segurança real ainda não coberta por uma regra formal — `reentrancy-events` (11 ocorrências),
`unchecked-transfer` (7), `divide-before-multiply` (5), `incorrect-equality` (2). Esse número —
17% de cobertura formal em código real — é o argumento quantificado que justifica investir em
generalização (Seção 4.2) em vez de continuar apenas adicionando classes manualmente ao catálogo.

### 5.4 Cobertura total do catálogo e execução sem LLM (novembro/2026)

O catálogo de vulnerabilidades passou a cobrir os 99 detectores do Slither 0.11.3 (105 entradas);
um teste automatizado falha se uma versão nova do Slither listar um detector desconhecido. Foi
criado o modo `--static-only`, que executa Slither, catálogo, patches determinísticos e reanálise
sem nenhuma chamada a LLM, e um detector próprio (`unrestricted-write`).

Sobre 201 dos 264 arquivos dos projetos reais, o modo sem LLM confirmou 77 correções pela
reanálise do Slither e deixou 16 achados críticos sem correção. Os 63 arquivos restantes não
puderam ser analisados por limites de ambiente (dependência privada indisponível, *stack too deep*,
testes de `forge-std`).

Com a pipeline completa nos 10 contratos do registro, 7 achados acionáveis foram aprovados e 28
foram resolvidos: 21 por patch determinístico e 7 pelo LLM, todos verificados pelo Certora. Cada
contrato foi executado uma vez, com modelo diferente do usado nos experimentos originais.

No conjunto DeFiVulnLabs (57 arquivos), 53 foram analisados, com 702 achados em 42 tipos de
detector; 29 arquivos foram corrigidos sem LLM. Nos 26 arquivos com achados críticos, a execução
com LLM e Certora aprovou 9. Uma auditoria dessas execuções mostrou que 12 de 19 reparos recaíam em
contratos de teste (`ContractTest`, `Attack`) e não no contrato vulnerável; passou-se a descartar
esses contratos, escolhendo para verificação o contrato com mais achados críticos. Uma reexecução
posterior, com essas correções, aprovou 4 arquivos (`phantom-permit`, `txorigin`,
`Storage-collision`, `Storage-collision-audio`). Dois não foram aprovados: `Randomness`, cujo
achado `arbitrary-send-eth` não tem regra formal por decisão de projeto, e `fee-on-transfer`, cujo
patch do LLM foi rejeitado pelo *patch guard* por alterar um literal de string.

Ressalva: a cota diária do provedor de LLM se esgotou no modelo principal, e parte da rodada usou
um modelo menor, com desempenho inferior; os números do LLM não são comparáveis diretamente aos
da Seção 5.1.

### 5.5 O oráculo formal local: medir o que a análise estática não vê (17/11/2026)

Todas as taxas de resolução relatadas até a Seção 5.4 compartilham um instrumento único de
medição: o Slither. Um defeito que o Slither não reporta nunca chega ao estágio de reparo, e
portanto o benchmark nunca cobra a pipeline por ele — nenhum número da forma "resolveu X de Y"
tem significado sobre essa parte do espaço de defeito. A medição que expôs o tamanho do
problema usou os operadores de mutação da Seção 4.2 na direção inversa: a partir do contrato já
corrigido (`DeFiVault_FIXED.sol`), 46 mutantes com um defeito injetado cada. **O Slither, com o
detector próprio incluído, produz achado de segurança novo em 9 deles.** Os operadores AOR
(aritmético), BOR (binário), UOR (unário), EED (remoção de evento) e PKR (troca de `payable`)
têm detectabilidade zero.

O oráculo independente natural seria o Certora Prover, barrado até então pelo custo: cada
verificação consumia cota de nuvem. O achado técnico que destravou a medição é que
`certoraRun --compilation_steps_only` para **antes de enviar** o job, não antes de verificar: o
`emv.jar` roda na máquina local e imprime vereditos de regra reais, sem consumir cota. Está
implementado em `tools/certora_cli.verify_locally`, e a variável `AUDIT_CERTORA_LOCAL=1` faz a
pipeline inteira rodar nesse modo.

Sobre isso foi construída uma **especificação congelada** (`specs/oracle/DeFiVault.spec`): 19
regras escritas a partir do contrato original, antes de qualquer mutante existir — saldos andam
exatamente o valor pedido, o período de lock e o teto de saque valem, a *whitelist* e o estado
`paused` barram saque, só o dono administra, a transferência de posse exige o `pendingOwner` e
rejeita o endereço zero, o pool de recompensa se conserva. Nenhuma regra menciona um defeito
específico, o que é o que permite rodar a mesma especificação em todos os mutantes. As 19
verificam no original e nenhuma é vácua. Uma salvaguarda de vacuidade acompanha cada veredito:
a regra auxiliar `-rule_not_vacuous` do Prover aparece violada quando a regra é alcançável; se
ela passa a verificar, a propriedade foi aprovada **sem ser exercitada** — exatamente o que um
"reparo" que faz a função reverter sempre provoca. `LocalVerdict.vacuous_rules` registra o caso,
e um reparo nessas condições não conta como reparo.

| Slither × oráculo | mata | sobrevive | erro |
|---|---:|---:|---:|
| detecta (9) | 3 | 6 | 0 |
| não vê (35) | 15 | 20 | 0 |
| não compila (2) | 0 | 0 | 2 |

Dos 44 mutantes que compilam, o Slither sozinho pega **9 (20%)**; Slither e oráculo juntos pegam
**24 (54%)**. Os dois instrumentos são **complementares, não aninhados**: os 15 que só o oráculo
mata violam cada um uma propriedade escrita antes do mutante existir, e em compensação 6
mutantes que o Slither detecta sobrevivem à especificação — são remoções de `onlyOwner` em
funções para as quais a especificação congelada não escreveu regra de autorização. Essa lacuna
fica registrada como lacuna; corrigi-la depois de conhecer o resultado invalidaria a medição.

A mesma infraestrutura permitiu separar, com veredito formal, o que a trilha determinística
alcança do que a LLM alcança. Dos 18 mutantes que a especificação mata, a trilha determinística
(Slither → catálogo → molde, sem LLM e sem cota) conserta **4** — exatamente os que caem em uma
classe da biblioteca de moldes (`unrestricted-write`, `tx-origin`, `missing-zero-check`) — e
**0 dos 14** fora dela, onde não aplica patch nenhum por não haver achado acionável. Nenhum
reparo vácuo. O controle sobre o original não mutado não aplica patch e mantém as 19 regras
válidas. A trilha mecânica é, portanto, confiável e limitada nos limites exatos da biblioteca.

Cruzando os dois estratos aparece um **teto de arquitetura**: apenas **3** dos 46 mutantes são
simultaneamente mortos pela especificação e reportados pelo Slither, e só esses 3 são
alcançáveis por qualquer trilha de reparo da pipeline atual, porque é o achado do Slither que
inicia o diagnóstico. No braço só-LLM (`AUDIT_NO_DETERMINISTIC_PATCH=1`) a LLM repara **3 de 3**,
com confirmação formal e sem regra vácua, e o *patch guard* aprova os três; a predição
pré-registrada ("repara no máximo 1 dos 3") estava errada e fica registrada como errada. O que
esse número **não** autoriza a concluir é generalização: N = 3 é o teto da arquitetura e não uma
escolha de amostra, a população alcançável não contém nenhuma classe ausente da biblioteca de
moldes — logo o medido é um empate com a trilha mecânica, e não uma vitória.

Uma consequência do mesmo cruzamento responde se bastaria crescer o catálogo até cobrir os 15
defeitos que só o oráculo vê: **11 deles não são lacuna de catálogo, são lacuna de análise
estática.** O mutante AOR troca `balances[msg.sender] -= amount` por `+=`, e o BOR troca `>=`
por `>`: as duas versões são Solidity válido, com a mesma forma sintática e o mesmo fluxo de
dados. Não há padrão a casar, então não existe entrada de catálogo a escrever — só uma
especificação separa as duas. Os outros 4 são lacunas reais e nomeáveis do catálogo.

O custo da medição inteira foi **zero cota de nuvem**: 28,1 s para as 19 regras no original,
29,0 s de média por mutante, cerca de 22 min de CPU para a varredura dos 46. Evidência em
`runs/20261117_oracle_defivault/`; detalhamento em
`docs/resultado-oraculo-formal-20261117.md`.

### 5.6 Propriedades propostas a partir do fonte, sem detector e sem LLM (18/11/2026)

A especificação da Seção 5.5 foi escrita à mão, e isso não escala: cada contrato novo exigiria
um especialista redigindo CVL. A pergunta seguinte foi se a própria forma do código fonte basta
para propor as propriedades. O módulo `agent/core/property_proposer.py` (CLI
`agent/propose_properties.py --verify`) lê o contrato e emite CVL **sem detector e sem LLM**, em
seis formas:

- **crédito** e **débito** — um depósito credita exatamente o valor pedido, um saque debita
  exatamente o valor pedido, no saldo do usuário e no total.
- **portão de identidade** — uma função guardada por `require(msg.sender == <estado>)` só é
  executável por esse endereço.
- **guard** — cada `require(...)` do próprio contrato vira a propriedade de que a condição vale
  depois da chamada.
- **boundary** e **gate_liveness** (acrescentadas em 18/11) — as duas de *liveness*, em
  `satisfy`: o limite declarado continua alcançável na fronteira exata, e quem o portão admite
  continua conseguindo entrar.

As duas últimas respondem a um limite estrutural das quatro primeiras, que são todas de
*safety*. Trocar `require(saldo >= valor)` por `require(saldo > valor)` **não deixa passar nada
de novo**: recusa o caso exato da igualdade, que o original aceitava. Toda regra de *safety*
continua verdadeira — mais verdadeira, até, porque o mutante reverte com mais frequência.
*Safety* não reclama de uma função que recusa demais. Para ver esse defeito é preciso afirmar
alcançabilidade, com a fronteira fixada (`require saldo == valor`) e `satisfy` em vez de
`assert`, porque uma função correta pode legitimamente reverter por overflow ou por falha de
transferência externa, e exigir "tem de passar" seria alarme falso.

Medido na mesma população de mutantes da Seção 5.5, com a especificação gerada **antes** de
qualquer mutante existir e congelada (`specs/oracle/DeFiVault_proposed_v3.spec`, 45 regras):

| instrumento | mutantes pegos (de 44 que compilam) |
|---|---:|
| Slither com plugins | 9 (20%) |
| especificação escrita à mão, 19 regras | 18 (41%) |
| especificação gerada, 28 regras (só *safety*) | 27 (61%) |
| especificação gerada, 45 regras (com *liveness*) | 32 (72%) |
| Slither + especificação gerada de 45 regras | 33 (75%) |

**As 45 regras verificam no contrato correto e nenhuma é vácua** — zero alarme falso, o mesmo
resultado da versão de 28. A especificação gerada pela máquina supera a escrita à mão (32 contra
18) e não houve regressão: os 27 mutantes que a versão de *safety* matava continuam mortos, e os
5 novos são todos BOR de aperto de limite, mortos **só** pelas formas de *liveness* — em nenhum
deles qualquer regra de *safety* foi violada. 24 das 32 mortes são invisíveis ao Slither, e um
único mutante é exclusividade do Slither (`FXR@174`).

Dos 11 mutantes que nenhum instrumento pega, **2 são mutantes equivalentes** — não mudam
comportamento nenhum, e por isso nenhum instrumento poderia matá-los: `MD@173` remove um
`onlyOwner` redundante (a linha seguinte repete `require(msg.sender == owner)`) e `PKR@164`
troca `address payable` por `address` em uma função cujo corpo usa `.call{value:}`, que existe
nos dois tipos. Eles inflavam o denominador das medições anteriores; sobre os **42 defeitos
reais**, Slither e especificação gerada pegam **33 (79%)**. Dos 9 restantes, 5 são remoções de
`emit` (CVL não observa evento: é inexpressável, não é lacuna de forma), 3 têm a mesma causa raiz
nomeada — uma variável local atribuída a partir de uma função `view` do próprio contrato, que
*é* dizível em CVL e desbloquearia os três de uma vez — e 1 está em `receive()`, que exige regra
paramétrica.

No corpus real de 321 arquivos dos projetos de auditoria, o propositor produz propriedade em
**60 arquivos, com 344 propriedades** no total. O resultado por tamanho é o inverso do esperado:
contratos de 300 linhas ou mais rendem propriedade em 16 de 46 arquivos (34%), contra 44 de 275
(16%) abaixo de 300 linhas — `inverse/src/Market.sol` (622 linhas, mercado de empréstimo real)
rende 44 propriedades sozinho. E o que bloqueia os contratos grandes que rendem zero está
medido, não suposto: o propositor lê `require(...)`, e contrato grande moderno declara invariante
com `if (cond) revert CustomError();`. No corpus são **632 `require(` contra 358
`revert CustomError()`**, e `caviar/PrivatePool.sol` (795 linhas) tem zero `require` e 15
`revert` — daí render zero propriedade. Além disso, **269 de 1.093** funções externas não-*view*
(24%) são descartadas porque um parâmetro é `struct` ou `enum`. São os dois trabalhos seguintes,
nessa ordem de alavanca.

O custo também é zero cota de nuvem: 45 regras levam cerca de 45 s por contrato no verificador
local. Evidência em `runs/20261118_proposer_sweep_v3/`; detalhamento em
`docs/resultado-liveness-20261118.md`.

## 6. Discussão e limitações

Os resultados no benchmark controlado (33/33 correções resolvidas nas classes cobertas) mostram
que, quando a vulnerabilidade pertence a uma classe modelada, a pipeline resolve com alta
confiabilidade e correção mínima verificável. Os resultados em código real (2/2 e 3/3 em
contratos de auditorias públicas, sem ajuste específico por contrato) indicam que esse resultado
não depende de o contrato ter sido escrito para o benchmark.

A limitação principal, medida diretamente (Seção 5.3), é de cobertura: 63% dos achados de um
contrato real de produção caem fora do catálogo formalizável atual, e a classe mais explorada em
incidentes reais — reentrância — permanece fora do Certora por decisão deliberada, mantida como
evidência de revisão estática até que a propriedade formal necessária (ordem entre chamada
externa e escrita de estado, não apenas condição de valor) esteja validada; uma primeira versão
dessa especificação (`specs/defivault_reentrancy_cei.spec`) foi escrita mas ainda não validada
contra os dois lados do teste (deve falhar no contrato vulnerável, passar no corrigido).

Essa limitação deixou de ser apenas estimada e passou a ser medida por um segundo
instrumento. O oráculo formal local (Seção 5.5) mostra que a cobertura do par
Slither + especificação chega a 54% do espaço de defeito injetado, e o propositor de
propriedades (Seção 5.6) a 75% — contra 20% do Slither sozinho. Mais importante do que o número:
a propriedade formal **não depende do catálogo**, de modo que a limitação estrutural que motivou
o trabalho deixa de ser um limite do método e passa a ser uma escolha de implementação.

O que permanece como limite de arquitetura é o ponto de partida do reparo. A pipeline diagnostica
a partir de um achado do Slither, e por isso apenas 3 dos 46 mutantes são alcançáveis pela
trilha de correção, por mais capaz que seja a LLM: nos outros não existe achado para
diagnosticar. Daí a conclusão sem ambiguidade sobre o passo seguinte — **o diagnóstico precisa
poder partir do contraexemplo do oráculo**, e não só do achado estático. Enquanto isso não
existir, qualquer afirmação sobre generalização da LLM está limitada a essa população de 3, e
dizer isso é parte do resultado: no que é alcançável hoje a LLM repara 3 de 3 com confirmação
formal, mas **empata** com a trilha mecânica, porque não há nessa população nenhuma classe
ausente da biblioteca de moldes. O desenho capaz de falsificar a hipótese de generalização está
pré-registrado em `docs/experimento-generalizacao-pre-registro.md`, com a predição declarada
antes da rodada.

Uma terceira limitação, agora do lado da especificação, é de expressividade: CVL não observa
evento, de modo que remoção de `emit` é inexpressável (5 dos 46 mutantes), e duas classes de
propriedade ainda não geradas — condição vinda de `if (cond) revert CustomError()` e funções com
parâmetro `struct`/`enum` — respondem pela maior parte dos contratos grandes que hoje rendem zero
propriedade (Seção 5.6).

Uma segunda limitação é de ambiente. Os projetos reais antes bloqueados foram em grande parte
liberados (Seção 5.4), mas 63 de 264 arquivos ainda não são analisáveis: dependência privada
indisponível (28 do Astaria), *stack too deep* (19 do Maia) e testes de `forge-std`. São limites do
ambiente de teste, não da pipeline em si.

Por fim, sobre o objetivo de gás citado no título do plano de trabalho: o resultado deste
período de pesquisa é a construção da salvaguarda de verificação formal em si — a capacidade de
provar que uma mudança no contrato preserva as propriedades de segurança esperadas — que é o
pré-requisito necessário para que otimizações de gás possam ser aplicadas com segurança. A
condução de experimentos de otimização de gás sobre essa salvaguarda, usando o benchmark e os
contratos reais já validados como base, é o passo natural seguinte e está listada em trabalhos
futuros.

## 7. Conclusão

Este trabalho implementou e validou uma pipeline automatizada que integra análise estática,
modelos de linguagem e verificação formal para identificar, corrigir e provar formalmente a
correção de vulnerabilidades em contratos inteligentes Solidity. A validação em benchmark
controlado (33/33 correções resolvidas) e em contratos reais de auditorias públicas (5/5
correções resolvidas em dois projetos Code4rena distintos, mais três controles negativos
corretos) mostra que a abordagem generaliza para código não escrito especificamente para o
projeto. A medição de cobertura em contrato real (17% formalizável) expôs quantitativamente o
limite da abordagem original — indexação manual por detector — e motivou a segunda frente do
trabalho: prompts de perspectiva, contexto por grafo de chamadas e parsing independente de
compilador, todos incorporados à pipeline e testados.

A terceira frente, concluída em novembro de 2026, atacou o instrumento de medição em si. A
verificação formal passou a rodar localmente sem consumir cota de nuvem, o que tornou viável
usar o Certora Prover como **oráculo** sobre uma população de 46 defeitos injetados: a cobertura
medida sai de 9 de 44 (20%, Slither sozinho) para 24 de 44 (54%) com uma especificação escrita à
mão e para 33 de 44 (75%) com uma especificação **gerada do próprio código fonte, sem detector e
sem LLM** — 33 de 42 (79%) quando os dois mutantes equivalentes identificados saem do
denominador. As 45 regras geradas verificam no contrato correto e nenhuma é vácua, isto é, a
cobertura não foi comprada com alarme falso. Esse resultado reposiciona a contribuição do
trabalho: a salvaguarda formal não depende mais de um catálogo mantido à mão.

Os passos seguintes ficam, por isso, mais precisos do que na versão anterior deste relatório:
permitir que o diagnóstico parta do contraexemplo do oráculo — hoje o reparo só alcança os
defeitos que a análise estática reporta, o que limita a 3 de 46 a população em que a
generalização da LLM pode ser cobrada —, gerar propriedade também a partir de
`if (cond) revert CustomError()` e de funções com parâmetro `struct`, validar formalmente a
propriedade de reentrância, e conduzir o experimento de otimização de gás propriamente dito
sobre a base já verificada.

## 8. Referências

CHEN, Yizhou et al. From Cryptic to Clear: Training on LLM Explanations to Detect Smart
Contract Vulnerabilities. **ACM Transactions on Software Engineering and Methodology**, [S. l.],
2025. DOI: 10.1145/3765753. Disponível em: https://dl.acm.org/doi/10.1145/3765753. Acesso em: 18
set. 2026.

NGUYEN, Nhat-Minh et al. Heterogeneous Graph Transformers with Large Language Models for Smart
Contract Vulnerability Detection. **ACM Transactions on Software Engineering and Methodology**,
[S. l.], 2025. DOI: 10.1145/3765751. Disponível em: https://dl.acm.org/doi/10.1145/3765751.
Acesso em: 18 set. 2026.

LI, Ziwei et al. Enhancing Smart Contract Code–Comment Inconsistencies Detection via Two-Stage
Pre-Training. **ACM Transactions on Software Engineering and Methodology**, [S. l.], 2025. DOI:
10.1145/3764867. Disponível em: https://dl.acm.org/doi/10.1145/3764867. Acesso em: 18 set. 2026.

FEIST, Josselin; GRIECO, Gustavo; GROCE, Alex. Slither: a static analysis framework for smart
contracts. In: IEEE/ACM INTERNATIONAL WORKSHOP ON EMERGING TRENDS IN SOFTWARE ENGINEERING FOR
BLOCKCHAIN (WETSEB), 2., 2019, Montreal. **Anais [...]**. Montreal: IEEE, 2019. p. 8-15.

CERTORA. **Certora Prover Documentation**. [S. l.]: Certora, 2026. Disponível em:
https://docs.certora.com. Acesso em: 18 set. 2026.
