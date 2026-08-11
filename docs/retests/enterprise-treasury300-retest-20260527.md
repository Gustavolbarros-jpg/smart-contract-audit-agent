# EnterpriseTreasury300 Retest - 2026-05-27

Este documento registra o reteste do contrato exploratorio maior depois das
melhorias de diagnostico deterministico e normalizacao CVL.

## Objetivo

Verificar se o pipeline generaliza alem dos contratos pequenos/medios e se
consegue completar o ciclo:

1. Slither.
2. Selecao de candidatos.
3. Spec CVL.
4. Certora no contrato original.
5. Diagnostico.
6. Patch via LLM.
7. Patch guard.
8. Certora/Slither no contrato corrigido.
9. Comparacao final.

## Runs

- Primeiro reteste: `runs/20260527_093646_EnterpriseTreasury300`.
- Run final aprovado: `runs/20260527_095632_EnterpriseTreasury300`.
- Snapshot agregado:
  `docs/evaluations/evaluation-results-20260527_100012_638925.md`.

## Problema Encontrado

No primeiro reteste, a spec gerada pela LLM ficou invalida porque usou `0x`
como argumento `bytes` em CVL:

```cvl
notifyPartner@withrevert(e, target, 0x);
```

O Certora rejeitou isso com erro de sintaxe perto de `x`.

## Correcao Implementada

Foi adicionada uma normalizacao deterministica em
`agent/tools/spec_validator.py`:

- Detecta argumento `0x` dentro de chamadas CVL em rules.
- Cria uma variavel `bytes payload;`.
- Substitui o argumento invalido pela variavel.

Exemplo normalizado:

```cvl
bytes payload;
notifyPartner@withrevert(e, target, payload);
```

A normalizacao foi integrada em `agent/orchestrator.py` antes das demais
correcoes automaticas da spec.

## Resultado Do Run Final

Run: `runs/20260527_095632_EnterpriseTreasury300`.

- Achados Slither: 26.
- Selecionados para o pipeline: 9.
- Confirmados: 9.
- Resolvidos apos patch/revalidacao: 9.
- Taxa de resolucao: `9/9`.

Classes cobertas:

- `missing-zero-check`;
- `tx-origin`;
- `suicidal`;
- `arbitrary-send-eth`;
- `unchecked-lowlevel`.

O arquivo `comparison_t1.json` nao registrou persistentes nem inconclusivas.

## Sobre Os `rule_not_vacuous`

O log fixed ainda mostra linhas `Violated: ...-rule_not_vacuous`.

Isso nao representa falha das regras principais. Essas linhas pertencem ao
sanity check de nao-vacuidade. No mesmo log, as regras reais aparecem como
`Not violated` em `Results for all`.

## Patch Guard

O primeiro patch da LLM foi bloqueado:

- `patch_guard_t0.json`;
- 76 errors;
- 4 warnings;
- principal problema: alteracoes amplas em strings e fora do escopo.

O retry minimo passou:

- `patch_guard_t0_guard_retry1.json`;
- status `warning`;
- 0 errors;
- 2 warnings.

Warnings restantes:

- troca de `tx.origin` para `msg.sender` no modifier `onlyOwner`;
- insercao de check em `destroyTreasury`.

Essas mudancas parecem coerentes com as vulnerabilidades confirmadas, mas o
guard ainda nao associa perfeitamente `tx-origin` a linhas de modifier nem
`suicidal` a funcao `selfdestruct`. Isso deve virar melhoria do patch guard.

## Validacao Local

Comandos executados:

```bash
python3 tests/test_certora_learning.py
python3 -m py_compile agent/main.py agent/evaluate.py agent/orchestrator.py agent/core/contract_registry.py agent/core/evaluation.py agent/core/patch_guard.py agent/tools/spec_validator.py agent/prompts/system_prompts.py agent/llm/client.py
python3 agent/evaluate.py --include-exploratory
```

Resultado:

- `61 tests OK`;
- `py_compile` OK;
- avaliacao agregada com todos os contratos acionaveis passando.

## Interpretacao

O pipeline esta generalizando melhor do que antes para contratos Solidity 0.8
maiores. O ponto mais importante e que ele nao dependeu da LLM para diagnosticar
as 9 falhas conhecidas: o diagnostico deterministico cobriu os IDs confirmados,
e a LLM ficou focada na geracao do patch.

Ainda nao e o momento de dizer que generaliza para qualquer contrato real. O
proximo passo seguro e melhorar o patch guard para reduzir falsos warnings e
depois testar um contrato real Solidity 0.8 com dependencias simples.
