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
- No `EnterpriseTreasury300`, o pipeline chegou ate Certora e confirmou:
  - 8 achados formais;
  - 1 achado static-confirmed;
  - 9 confirmacoes no total.
- O bloqueio nesse contrato foi limite diario do Groq na etapa de diagnostico,
  nao falha de Slither/Certora.

### Economia De LLM

- O contexto de diagnostico foi compactado.
- Sucessos irrelevantes do Certora foram removidos do prompt.
- Planos formais enviados ao diagnostico foram reduzidos.
- O diagnostico de classes conhecidas agora e deterministico.
- No `EnterpriseTreasury300`, isso cobre todos os 9 IDs confirmados e remove
  uma chamada LLM inteira.
- A etapa de patch continua recebendo o contrato completo por seguranca.

## Validacoes Atuais

Comandos usados:

```bash
python3 tests/test_certora_learning.py
python3 -m py_compile agent/main.py agent/evaluate.py agent/orchestrator.py agent/core/*.py agent/tools/spec_validator.py agent/prompts/system_prompts.py agent/llm/client.py
git diff --check
```

Resultado atual esperado:

```text
60 tests OK
py_compile OK
git diff --check OK
```

Snapshots importantes:

- Core benchmark:
  - `docs/evaluations/evaluation-results-20260524_232506_044465.md`
- Benchmark + exploratory:
  - `docs/evaluations/evaluation-results-20260525_004032_486537.md`
- Todos os contratos registrados:
  - `docs/evaluations/evaluation-results-20260525_004125_584645.md`

## O Que Falta Atualizar

### Antes De Rodar Mais Contratos Reais

- Reexecutar `EnterpriseTreasury300` depois do reset/renovacao do limite Groq.
- Confirmar que a etapa pula o diagnostico LLM e vai direto para patch.
- Verificar se o patch gerado no contrato de 327 linhas:
  - compila;
  - passa no patch guard;
  - remove as confirmacoes do Certora/Slither;
  - nao altera logica fora do escopo.

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

- So depois de passar o contrato de 327 linhas ate patch/revalidacao, testar um
  contrato existente de fora.
- Comecar por um contrato real pequeno/medio e compilavel em Solidity 0.8.
- Nao puxar um repo inteiro antes de resolver imports/remappings/dependencias.

## Decisao Atual

Nao vamos remover o contrato completo da etapa de patch por enquanto.

O desenho correto agora e:

- economizar no diagnostico;
- manter patch com contrato completo;
- aplicar patch guard forte;
- revalidar com Slither e Certora;
- so depois pensar em patch estruturado por hunks/linhas.
