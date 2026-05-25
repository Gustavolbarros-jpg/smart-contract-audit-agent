# Revisao da Branch `feature/pipeline-guardrails`

Data: 2026-05-24

## Objetivo

Esta branch isola as mudancas propostas para tornar o pipeline de auditoria e
correcao de contratos mais confiavel antes de qualquer merge em `develop` ou
`main`.

O foco foi reduzir decisoes livres da LLM, preservar rastreabilidade dos
achados e impedir que a correcao automatica altere codigo fora do escopo da
vulnerabilidade confirmada.

## O Que Mudou

- Catalogo deterministico de vulnerabilidades em `agent/core/vulnerability_catalog.py`.
- Normalizacao deterministica do Slither em `agent/core/slither_normalizer.py`.
- Separacao entre:
  - achados formalizaveis com Certora;
  - achados `static_confirmed`;
  - achados apenas para revisao estatica.
- `patch_guard` para bloquear ou avisar sobre patches amplos demais da LLM.
- Registry de contratos para separar `benchmark`, `exploratory`, `manual` e `scratch`.
- Relatorios de avaliacao em snapshots timestampados.
- Prompts principais em ingles, preservando schemas/campos compativeis com o codigo atual.

## Classes Consideradas Estaveis Agora

- `missing-zero-check`
- `tx-origin`
- `suicidal`
- `arbitrary-send-eth` quando o alvo e claro
- `unchecked-lowlevel` como fluxo `static_confirmed`
- `erc2771-multicall-context` como composicao estatica confirmada

## Classes Mantidas Como Revisao

- `reentrancy-*`
- `timestamp`
- `block-number`
- `unprotected-critical-update`

`unprotected-critical-update` foi propositalmente rebaixada para revisao porque
a heuristica ainda depende parcialmente de nomes de variaveis/funcoes. Ela
preserva evidencia, mas nao dispara correcao automatica.

## Validacao Local

Comandos principais:

```bash
python3 tests/test_certora_learning.py
python3 -m py_compile agent/main.py agent/evaluate.py agent/orchestrator.py agent/core/*.py
git diff --check
```

Resultado atual:

```text
48 tests OK
py_compile OK
git diff --check OK
```

## Testes Em Contratos Maiores

### `DeFiVault.sol`

- Tamanho: 187 linhas.
- Run: `runs/20260524_210746_DeFiVault`.
- Achados Slither normalizados: 19.
- Candidatos formais: 5.
- Confirmadas: 5.
- Resolvidas: 5/5.

Classes resolvidas:

- `missing-zero-check`
- `tx-origin`
- `suicidal`
- `arbitrary-send-eth`

Ressalva:

- O `patch_guard` terminou com `warning`, nao `blocked`.
- Foram 40 avisos por mudancas fora do range alvo, principalmente comentarios e reformatacao.
- A correcao passou em Certora/Slither, mas o resultado mostra que ainda precisamos endurecer
  a politica de minimalidade para contratos maiores.

### `CrowdfundingVault.sol`

- Tamanho: 173 linhas.
- Run: `runs/20260524_210914_CrowdfundingVault`.
- Achados Slither normalizados: 16.
- Candidatos formais: 1.
- `static_confirmed`: 3.
- Confirmadas: 4.
- Resolvidas: 4/4.

Classes resolvidas:

- `tx-origin`
- `unchecked-lowlevel`

Resultado do `patch_guard`:

- `ok`
- 0 erros
- 0 avisos

Esse foi o melhor teste de generalizacao ate agora, porque combinou Certora
para `tx-origin` com revalidacao estatica para `unchecked-lowlevel`.

## ERC2771 / Multicall

O pipeline agora reconhece a composicao:

- ERC2771 com recuperacao de sender por sufixo de calldata;
- `multicall`;
- `delegatecall`;
- ausencia de bloqueio para chamadas vindas do trusted forwarder.

Run de validacao:

- `runs/20260524_192015_ERC2771MulticallVulnerable`
- Resultado: 1/1 resolvido.

Observacao importante:

- A primeira resposta da LLM alterou strings de erro fora do escopo.
- O `patch_guard` bloqueou.
- O autorepair restaurou as strings originais.
- O patch aceito ficou restrito ao guard no `multicall`.

## Avaliacoes Snapshot

Snapshots mais recentes:

- Core benchmark:
  - `docs/evaluations/evaluation-results-20260524_211017_840188.md`
- Benchmark + exploratory:
  - `docs/evaluations/evaluation-results-20260524_211010_010326.md`

## Riscos Abertos

- O `patch_guard` ainda permite alguns casos como warning. Em contratos maiores,
  isso pode aceitar reformatacao ampla demais.
- `unprotected-critical-update` ainda nao deve ser promovida para correcao automatica.
- Reentrancia continua fora do escopo automatico por enquanto.
- Specs Certora geradas por LLM ainda precisam dos validadores deterministas para evitar
  falso senso de verificacao.

## Proximos Passos Recomendados

1. Transformar certos warnings do `patch_guard` em bloqueio quando houver muitos hunks fora do alvo.
2. Adicionar autorepair para restaurar comentarios fora do alvo quando a LLM apenas reescrever texto.
3. Criar uma metrica de minimalidade por run:
   - hunks totais;
   - hunks permitidos;
   - hunks fora do alvo;
   - strings restauradas;
   - comentarios alterados.
4. Continuar testando contratos maiores antes de promover novas classes.
5. So fazer merge em `develop` depois de revisao manual dos professores.

