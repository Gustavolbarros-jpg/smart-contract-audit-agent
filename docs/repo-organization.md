# Repo Organization Baseline

Data: 2026-05-23
Branch de trabalho: `develop`

## Estado Git

- `develop` foi alinhada com `main`.
- `main`, `develop` e `HEAD` estavam no commit `fda0435` no momento do alinhamento.
- Mudancas locais anteriores foram preservadas em:
  - `stash@{0}: baseline-before-develop-align-2026-05-23`
- Os contratos ERC2771 foram recuperados seletivamente do stash para voltarem como casos de teste:
  - `smart-audt/contracts/ERC2771MulticallVulnerable.sol`
  - `smart-audt/contracts/ERC2771MulticallVulnerable_FIXED.sol`

## Fonte Principal

- `agent/orchestrator.py`
  - Orquestra Slither, LLM, Certora, diagnostico, correcao e revalidacao.
- `agent/llm/`
  - Cliente Groq/OpenAI-compatible e schemas Pydantic.
- `agent/tools/`
  - Wrappers de Slither, Certora e validacao/autocorrecao de specs CVL.
- `agent/prompts/system_prompts.py`
  - Prompts usados em cada etapa do pipeline.

## Casos de Teste e Estudos

- `smart-audt/contracts/`
  - Contratos vulneraveis e algumas versoes corrigidas.
  - Deve continuar sendo a area principal de exemplos pequenos e controlados.
- `agent/core/contract_registry.py`
  - Separa os contratos em `benchmark`, `exploratory`, `manual` e `scratch`.
  - Evita que arquivos `_FIXED` ou exemplos corrigidos entrem na avaliacao
    padrao por acidente.
- `docs/benchmark-contracts.md`
  - Documenta a classificacao atual dos contratos e os comandos de listagem.
- `specs/`
  - Specs CVL manuais ou semi-manuais usadas nos experimentos.

## Artefatos Gerados

Estes devem continuar ignorados pelo Git:

- `agent/agent_outputs/`
- `emv-*-certora-*`
- `.certora_internal/`
- `audit_outputs/`
- `slither*.json`
- `resultado*.json`
- `relatorio_final.csv`
- `__pycache__/`
- ambientes locais como `.venv/` e `certora-env/`

## Historico Experimental

- `logs_antigos/`
  - Tamanho observado: cerca de 1.4GB.
  - Contem muitos runs do Certora, logs, JSONs e relatorios antigos.
  - Esta ignorado pelo Git.
  - Nao foi apagado porque pode conter evidencias experimentais.

## Legado / Candidatos a Reorganizacao

- `audit_pandas.py`
  - Script manual de analise exploratoria e cruzamento de logs.
  - Parece ter sido antecessor de parte do pipeline.
  - Candidato: mover para `archive/manual/` ou integrar ao `agent`.

- `slither_minify.py`
  - Script manual de minificacao/normalizacao de Slither.
  - A logica atual equivalente vive em `agent/tools/slither_cli.py`.
  - Candidato: mover para `archive/manual/` depois de confirmar que nao e mais usado.

- `agent/main.py`
  - Arquivo vazio.
  - Candidato: remover ou transformar em CLI limpa para executar `orchestrator.py`.

- `specs/storage.spec:`
  - Nome estranho com `:` no final.
  - Conteudo parece mais um comando/anotacao do que uma spec CVL.
  - Candidato: revisar e remover/renomear.

- `smart-audt/contracts/vulneravel.md`
  - Arquivo vazio.
  - Candidato: remover.

## Limpeza Ja Aplicada

Foram removidos apenas artefatos locais/gerados:

- caches Certora em `agent/`, `smart-audt/`, `smart-audt/contracts/` e `specs/`;
- runs `agent/emv-*-certora-*`;
- `__pycache__`;
- ambientes locais `smart-audt/.venv` e `smart-audt/certora-env`;
- JSONs gerados `smart-audt/contracts/resultado.json` e `smart-audt/contracts/slither.json`;
- repo aninhado `smart-audt/aave-v4/`.

## Proxima Organizacao Recomendada

1. Decidir o destino de `logs_antigos/`.
2. Separar scripts manuais antigos de pipeline ativo.
3. Criar uma CLI simples para escolher contrato/spec/modelo sem editar `orchestrator.py`.
4. Recuperar do stash apenas o que for virar caso de estudo real.
5. Evitar aplicar o stash inteiro, porque ele tambem contem `Hub.sol`, `smart-audt/src/` e outputs grandes/experimentais.
