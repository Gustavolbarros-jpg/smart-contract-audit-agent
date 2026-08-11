# Project Progress And Next Steps

Data: 2026-05-27

Este documento resume o que foi feito desde o inicio da organizacao do
pipeline e o que ainda falta atualizar antes de uma revisao/merge.

## Estado Atual

- Branch de trabalho: `feature/pipeline-guardrails`.
- `main` e `develop` permanecem intactas.
- O pipeline atual preserva artefatos em `runs/`.
- O fluxo principal continua sendo agente com LLM, mas com guardrails
  deterministicos onde a regra ja e confiavel.

## Estrategia Atual

O equilibrio atual e:

1. Slither encontra e normaliza evidencias.
2. O pipeline classifica cada achado como formalizavel, static-confirmed ou
   revisao estatica.
3. A LLM ainda participa do planejamento formal e da geracao de CVL.
4. O pipeline repara CVL com validadores deterministicos antes do Certora.
5. Certora confirma ou rejeita as propriedades formais.
6. O diagnostico de classes conhecidas e gerado deterministicamente.
7. A etapa de patch ainda envia o contrato completo para a LLM.
8. O patch guard limita mudancas fora do escopo.
9. Slither/Certora rodam novamente para validar o resultado.

Essa escolha evita economizar token de um jeito perigoso. Para patch, a LLM
precisa ver o contrato completo para preservar imports, structs, modifiers,
estado, funcoes auxiliares, strings, comentarios e invariantes locais.

## O Que Foi Feito

### Organizacao De Branches E Baseline

- `develop` foi alinhada com `main` no inicio do trabalho.
- Mudancas locais foram preservadas em stash quando necessario.
- Foi criado o relatorio baseline em `docs/pipeline-baseline.pdf`.
- A branch atual concentra as mudancas novas para revisao separada.

### Organizacao Do Repositorio

- Foi criado o registry de contratos em `agent/core/contract_registry.py`.
- Os contratos foram separados em:
  - `benchmark`;
  - `exploratory`;
  - `manual`;
  - `scratch`.
- A documentacao da organizacao esta em `docs/benchmark-contracts.md`.

### Normalizacao Slither

- O Slither deixou de ser apenas texto livre para a LLM.
- Achados agora passam por `agent/core/slither_normalizer.py`.
- O pipeline produz classes estaveis de vulnerabilidade.
- Chamadas low-level agora sao triadas:
  - retorno checado fica como evidencia;
  - retorno ignorado vira `unchecked-lowlevel` acionavel.

### Catalogo De Vulnerabilidades

- Foi criado/fortalecido o catalogo deterministico em
  `agent/core/vulnerability_catalog.py`.
- Classes fortes atualmente:
  - `missing-zero-check`;
  - `tx-origin`;
  - `suicidal`;
  - `arbitrary-send-eth` quando o alvo e claro;
  - `unchecked-lowlevel` como static-confirmed;
  - `erc2771-multicall-context` como static-confirmed.
- Classes mantidas como revisao:
  - `reentrancy-*`;
  - `timestamp`;
  - `block-number`;
  - `unprotected-critical-update`.

### Certora/CVL

- O bloco `methods{}` agora e reconstruido deterministicamente.
- Funcoes que usam ambiente restrito nao recebem `envfree`.
- O pipeline bloqueia logs Certora com spec invalida, mesmo se
  `comparison_t1.json` parecer positivo.
- Erros conhecidos de CVL viraram catalogo em
  `agent/core/certora_error_catalog.py`.
- Regras adicionadas depois dos testes maiores:
  - remover nomes de variaveis em `returns(...)` no `methods{}`;
  - normalizar `bytes calldata`, `string memory`, `address payable` dentro de
    rules CVL.

### Patch Guard

- `agent/core/patch_guard.py` bloqueia mudancas arriscadas:
  - strings originais alteradas;
  - assinatura public/external alterada;
  - variaveis de estado removidas/renomeadas;
  - hunks fora do escopo confirmado.
- O autorepair restaura strings originais em casos obvios.
- Validado no caso ERC2771: a LLM mudou strings fora do escopo, o guard
  bloqueou, o autorepair restaurou, e o patch final ficou minimo.

### ERC2771 + Multicall

- O pipeline passou a reconhecer a composicao:
  - ERC2771 sender recovery;
  - `multicall`;
  - `delegatecall`;
  - falta de bloqueio para chamadas vindas do trusted forwarder.
- Essa classe virou `erc2771-multicall-context`.
- Run validado: `runs/20260524_192015_ERC2771MulticallVulnerable`.

### Contratos Maiores

- `DeFiVault` foi validado com 187 linhas.
- `CrowdfundingVault` foi validado com 173 linhas.
- Foi criado `EnterpriseTreasury300.sol` com 327 linhas para stress
  controlado.
- No `EnterpriseTreasury300`, o pipeline agora completou o ciclo inteiro:
  - 26 achados Slither;
  - 9 selecionados;
  - 9 confirmados;
  - 9 resolvidos apos patch/revalidacao.
- Run aprovado: `runs/20260527_095632_EnterpriseTreasury300`.
- Reteste documentado em
  `docs/retests/enterprise-treasury300-retest-20260527.md`.

### Contratos Reais

- Solmate `WETH.sol` foi usado como teste real negativo:
  - imports compilados com Slither;
  - 0 candidatos acionaveis;
  - pipeline parou sem LLM/Certora/patch;
  - run: `runs/20260527_102842_WETH`.
- Code4rena Forgotten Runes foi usado como teste real maior:
  - alvo:
    `smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter.sol`;
  - run: `runs/20260527_105459_ForgottenRunesWarriorsMinter`;
  - 71 achados Slither normalizados;
  - 2 candidatos formalizados e confirmados pelo Certora;
  - 2/2 resolvidos por patch deterministico minimo;
  - `patch_guard`: 2 hunks, 0 erros, 0 avisos.
- Code4rena Inverse `Market.sol` foi usado como teste real maior:
  - alvo: `smart-audt/contracts/real/inverse/src/Market.sol`;
  - tamanho: 621 linhas;
  - run: `runs/20260528_093346_Market`;
  - 63 achados Slither normalizados;
  - 3 candidatos formalizados e confirmados pelo Certora;
  - 3/3 resolvidos por spec, diagnostico e patch deterministicos;
  - `patch_guard`: 3 hunks, 0 erros, 0 avisos.
- Code4rena Escher `FixedPrice.sol` foi usado como triagem negativa de
  `selfdestruct`:
  - run corrigido: `runs/20260528_093456_FixedPrice`;
  - resultado: 0 candidatos;
  - evita criar finding falso `destroy` para `selfdestruct` interno.
- Code4rena Caviar `PrivatePool.sol` foi usado como teste real na faixa
  700-1200 linhas:
  - alvo: `smart-audt/contracts/real/caviar/src/PrivatePool.sol`;
  - tamanho: 794 linhas;
  - run: `runs/20260528_101335_PrivatePool`;
  - resultado: 0 candidatos acionaveis;
  - validou compilacao de repo Foundry com `remappings.txt`.
- Code4rena Astaria foi avaliado como candidato grande:
  - `PublicVault.sol`: 725 linhas;
  - `AstariaRouter.sol`: 803 linhas;
  - `LienToken.sol`: 919 linhas;
  - bloqueado porque `AstariaXYZ/astaria-gpl` nao clonou sem autenticacao.
- Relatorios:
  - `docs/retests/real-code-solmate-weth-20260527.md`;
  - `docs/retests/real-code-forgotten-runes-20260527.md`;
  - `docs/retests/real-code-inverse-market-20260528.md`;
  - `docs/retests/real-code-escher-selfdestruct-triage-20260528.md`;
  - `docs/retests/real-code-caviar-privatepool-20260528.md`;
  - `docs/retests/real-code-astaria-dependency-blocker-20260528.md`.

### Economia De LLM

- O contexto de diagnostico foi compactado.
- Sucessos irrelevantes do Certora foram removidos do prompt.
- Planos formais enviados ao diagnostico foram reduzidos.
- O diagnostico de classes conhecidas agora e deterministico.
- No `EnterpriseTreasury300`, isso cobre todos os 9 IDs confirmados e remove
  uma chamada LLM inteira.
- No Forgotten Runes, `missing-zero-check` foi corrigido por patch
  deterministico, evitando pedir para a LLM reescrever um contrato real grande.
- No Inverse `Market.sol`, a spec CVL de `missing-zero-check` tambem foi gerada
  deterministicamente, removendo uma chamada LLM de spec para esse padrao
  mecanico.
- O pipeline agora le `remappings.txt` de Foundry para resolver imports em
  repos reais como Caviar.
- A etapa de patch continua recebendo o contrato completo por seguranca.

## Validacoes Atuais

Comandos usados:

```bash
python3 tests/test_certora_learning.py
python3 -m py_compile agent/main.py agent/evaluate.py agent/orchestrator.py agent/core/*.py agent/tools/*.py agent/prompts/system_prompts.py agent/llm/client.py
git diff --check
```

Resultado atual esperado:

```text
83 tests OK
py_compile OK
git diff --check OK
```

Snapshots importantes:

- Core benchmark:
  - `docs/evaluations/evaluation-results-20260524_232506_044465.md`
- Benchmark + exploratory:
  - `docs/evaluations/evaluation-results-20260525_004032_486537.md`
- Benchmark + exploratory apos reteste do contrato maior:
  - `docs/evaluations/evaluation-results-20260527_100012_638925.md`
- Todos os contratos registrados:
  - `docs/evaluations/evaluation-results-20260525_004125_584645.md`

## O Que Falta Atualizar

### Antes De Rodar Mais Contratos Reais

- Corrigir os falsos warnings do patch guard observados no
  `EnterpriseTreasury300`.
- Associar achados `tx-origin` a linhas de modifier quando o check de auth fica
  centralizado fora da funcao vulneravel.
- Continuar restringindo `suicidal` a casos em que a propriedade seja realmente
  autorizacao de `selfdestruct`; Escher mostrou que nem todo `selfdestruct`
  real corresponde a essa classe.
- Rodar `git diff --check` depois das atualizacoes finais.
- Ja existem resultados reais positivos no Forgotten Runes e no Inverse
  `Market.sol`; o proximo contrato real deve mirar outra classe vulneravel sem
  especializar a regra para um contrato especifico.

### Patch E Minimalidade

- Endurecer `patch_guard` em contratos grandes.
- Transformar excesso de warnings fora do alvo em bloqueio.
- Criar metrica de minimalidade por run:
  - hunks totais;
  - hunks permitidos;
  - hunks fora do alvo;
  - strings restauradas;
  - comentarios alterados.

### Documentacao

- Atualizar o PDF baseline ou gerar um novo PDF apos a validacao final do
  `EnterpriseTreasury300`.
- Atualizar `docs/professor-review-pipeline-guardrails.md` com o resultado da
  reexecucao completa.
- Criar um pequeno relatorio especifico de economia de tokens:
  - antes;
  - depois;
  - chamadas LLM removidas;
  - limites ainda existentes.

### Proximos Experimentos

- Testar outro contrato real Solidity 0.8 com uma classe diferente de
  `missing-zero-check`.
- Revisar a classe `tx-origin`: Inverse `BorrowController.sol` mostrou que
  `tx.origin` em funcao de politica/allowlist nao e a mesma coisa que
  autorizacao `owner()` simples.
- Priorizar classes que o Slither identifica com boa evidencia e que o Certora
  consegue confirmar sem modelagem excessiva.
- Evitar reentrancia por enquanto.
- Continuar usando contratos reais pequenos/medios antes de subir para repos
  inteiros.

## Decisao Atual

Nao vamos remover o contrato completo da etapa de patch por enquanto.

O desenho correto agora e:

- economizar no diagnostico;
- manter patch com contrato completo;
- aplicar patch guard forte;
- revalidar com Slither e Certora;
- so depois pensar em patch estruturado por hunks/linhas.
