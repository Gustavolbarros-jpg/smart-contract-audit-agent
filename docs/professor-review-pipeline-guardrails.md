# Revisao da Branch `feature/pipeline-guardrails`

Data: 2026-05-27

## Objetivo

Esta branch isola as mudancas propostas para tornar o pipeline de auditoria e
correcao de contratos mais confiavel antes de qualquer merge em `develop` ou
`main`.

O foco foi reduzir decisoes livres da LLM, preservar rastreabilidade dos
achados e impedir que a correcao automatica altere codigo fora do escopo da
vulnerabilidade confirmada.

Resumo cronologico completo:

- `docs/project-progress-and-next-steps.md`

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
83 tests OK
py_compile OK
git diff --check OK
```

## Testes Em Contratos Maiores

### `DeFiVault.sol`

- Tamanho: 187 linhas.
- Run: `runs/20260524_232148_DeFiVault`.
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
- Foram 37 avisos por mudancas fora do range alvo, principalmente comentarios e reformatacao.
- A correcao passou em Certora/Slither, mas o resultado mostra que ainda precisamos endurecer
  a politica de minimalidade para contratos maiores.
- A run antiga `runs/20260524_210746_DeFiVault` tinha `envfreeFuncsStaticCheck`
  violado por marcar `calculateReward(address)` como `envfree`; a run atual
  remove essa marcacao e mostra `envfreeFuncsStaticCheck: Not violated`.

### `CrowdfundingVault.sol`

- Tamanho: 173 linhas.
- Run: `runs/20260524_212214_CrowdfundingVault`.
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

Correcao importante apos revisao do log:

- A run anterior marcava `createCampaign`, `timeLeft` e `isSuccessful` como
  `envfree`, mas essas funcoes usam `msg.sender` ou `block.timestamp`.
- Isso fazia `envfreeFuncsStaticCheck` violar e tornava a spec invalida, mesmo
  com a rule de auth passando.
- A geracao de `methods{}` agora remove `envfree` de funcoes que leem ambiente
  restrito.
- O validador tambem parou de adicionar `envfree` automaticamente em qualquer
  metodo com `returns`.
- A run atual mostra `envfreeFuncsStaticCheck: Not violated`.
- A avaliacao agora inspeciona `certora*.log` antes de aceitar `comparison_t1.json`;
  se houver erro bloqueante de spec, como `cvl_invalid_envfree`, o status vira
  `blocked:<log>` mesmo que a comparacao diga `passed`.

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

## Validacao Manual/Scratch

Snapshot completo:

- `docs/evaluations/evaluation-results-20260525_002330_000739.md`

Resultados adicionais:

- `SimpleBank_FIXED`, `DeFiVault_FIXED` e `VulnerableVault` ainda geram
  candidatos formais pelo Slither, mas Certora nao confirmou vulnerabilidades.
- `SafeBankToken`, `SafeBankToken2`, `SuperSecureBank` e
  `VulnerableBankTokenCorrected` pararam corretamente em
  `no_actionable_candidates`.
- `TreasuryVault` bloqueou em `certora_original` porque o Solidity esta
  sintaticamente invalido (`}x` no final do arquivo).

Correcao importante encontrada nessa rodada:

- Arquivos `_FIXED` podem ter nome de arquivo diferente do contrato interno.
- `SimpleBank_FIXED.sol` contem `contract SimpleBank`; antes disso, o pipeline
  chamava Certora com `SimpleBank_FIXED` e gerava conclusao inconclusiva.
- O orquestrador agora detecta o nome real do contrato no Solidity e passa esse
  nome para `certoraRun`.

## Validacao Exploratoria Maior

### `EnterpriseTreasury300.sol`

- Tamanho: 327 linhas.
- Grupo: `exploratory`.
- Run principal: `runs/20260527_095632_EnterpriseTreasury300`.
- Achados Slither normalizados: 26.
- Candidatos selecionados: 9.
- `static_confirmed`: 1.
- Confirmadas: 9.
- Resolvidas: 9/9.
- Status atual: `passed`.

Classes confirmadas:

- `missing-zero-check`
- `tx-origin`
- `suicidal`
- `arbitrary-send-eth`
- `unchecked-lowlevel`

Resultado importante:

- A cadeia Slither -> plano -> spec -> Certora generalizou para um contrato de
  mais de 300 linhas.
- A spec precisou de duas novas protecoes deterministicas:
  - remover nomes de variaveis em `returns(...)` no `methods{}`;
  - normalizar tipos Solidity dentro de rules CVL, como `bytes calldata` e
    `address payable`.
- O bloqueio anterior por limite diario do Groq foi removido para esta classe
  de run porque o diagnostico conhecido virou deterministico.
- O contexto de diagnostico foi compactado para reduzir custo de token em
  contratos maiores.
- O diagnostico para classes conhecidas agora e gerado deterministicamente.
  No `EnterpriseTreasury300`, isso cobre todos os 9 IDs confirmados e remove
  uma chamada LLM inteira antes da etapa de patch.
- A etapa de patch continua recebendo o contrato completo por seguranca, e o
  contexto enviado e preservado em `patch_t0_prompt_context.txt` dentro do run.
- A primeira tentativa de patch foi bloqueada pelo `patch_guard`; o retry
  minimo passou com 0 errors e 2 warnings de escopo.
- Reteste detalhado:
  `docs/retests/enterprise-treasury300-retest-20260527.md`.

## Validacao Em Codigo Real

### Solmate `WETH.sol`

- Origem: `https://github.com/transmissions11/solmate`.
- Fonte local:
  `smart-audt/contracts/real/solmate/src/tokens/WETH.sol`.
- Run principal: `runs/20260527_102842_WETH`.
- Resultado: `no_actionable_candidates`.

Interpretacao:

- O pipeline compilou codigo real com imports.
- Slither nao gerou candidatos acionaveis apos a normalizacao.
- O pipeline nao chamou LLM/Certora e nao produziu patch.
- Esse caso funciona como teste negativo contra alucinacao de correcao.

Relatorio:

- `docs/retests/real-code-solmate-weth-20260527.md`.

### Code4rena Forgotten Runes

- Origem: `https://github.com/code-423n4/2022-05-runes`.
- Fonte local:
  `smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter.sol`.
- Run principal:
  `runs/20260527_105459_ForgottenRunesWarriorsMinter`.
- Achados Slither normalizados: 71.
- Candidatos formalizados: 2.
- Confirmadas pelo Certora: 2.
- Resolvidas: 2/2.
- Status atual: `passed`.

Classes confirmadas:

- `missing-zero-check` em `setVaultAddress(address)`;
- `missing-zero-check` em `setWethAddress(address)`.

Resultado importante:

- O contrato real usa imports OpenZeppelin e tipos definidos pelo usuario.
- O pipeline agora detecta remappings/pacotes proximos ao contrato para Slither
  e Certora.
- O `_AGENT_FIXED.sol` e gerado no mesmo diretorio do contrato original quando
  existem imports, preservando imports relativos.
- A normalizacao deixou de tratar falsamente `token.transfer(...)` como envio
  arbitrario de ETH.
- Helpers que retornam `success` de low-level call nao sao mais classificados
  como `unchecked-lowlevel` quando o chamador trata o resultado.
- O patch final foi deterministico e minimo:
  - 2 hunks;
  - 0 erros de `patch_guard`;
  - 0 avisos de `patch_guard`.

Interpretacao:

- Este teste reforca que a arquitetura nao depende de regras especificas para
  contratos sinteticos.
- A LLM ainda participa do planejamento, mas correcoes mecanicas conhecidas
  podem ser executadas deterministicamente para economizar tokens e evitar
  truncamento em contratos grandes.
- O resultado nao deve ser lido como prova ampla sobre todas as vulnerabilidades
  reais; ele valida uma classe especifica em codigo real.

Relatorio:

- `docs/retests/real-code-forgotten-runes-20260527.md`.

### Code4rena Inverse `Market.sol`

- Origem: `https://github.com/code-423n4/2022-10-inverse`.
- Relatorio publico: `https://code4rena.com/reports/2022-10-inverse`.
- Fonte local:
  `smart-audt/contracts/real/inverse/src/Market.sol`.
- Tamanho aproximado: 621 linhas.
- Run principal: `runs/20260528_093346_Market`.
- Achados Slither normalizados: 63.
- Candidatos formalizados: 3.
- Confirmadas pelo Certora: 3.
- Resolvidas: 3/3.
- Status atual: `passed`.

Classes confirmadas:

- `missing-zero-check` em `setPauseGuardian(address)`;
- `missing-zero-check` em `setGov(address)`;
- `missing-zero-check` em `setLender(address)`.

Resultado importante:

- O contrato real contem interfaces top-level no mesmo arquivo. O `methods{}`
  agora extrai apenas a API do contrato principal, evitando declarar metodos de
  interfaces como se fossem metodos do contrato alvo.
- Retornos nomeados com tipo de interface, como `IEscrow predicted`, sao
  normalizados para `address` no CVL.
- Para `missing-zero-check`, a spec CVL agora pode ser gerada
  deterministicamente quando todas as regras selecionadas pertencem a esse
  padrao.
- O patch deterministico agora expande funcoes de uma linha antes de inserir
  `require(...)`, evitando Solidity invalido.
- Patch final:
  - 3 hunks;
  - 0 erros de `patch_guard`;
  - 0 avisos de `patch_guard`.

Interpretacao:

- Este e o maior contrato real validado ate agora pelo pipeline.
- A LLM ainda participou do planejamento formal, mas spec, diagnostico e patch
  foram deterministicos para uma classe mecanica conhecida.
- O resultado fortalece a tese de que o agente deve combinar LLM com guardrails
  deterministas, em vez de delegar todas as decisoes ao modelo.

Relatorio:

- `docs/retests/real-code-inverse-market-20260528.md`.

### Code4rena Escher `FixedPrice.sol`

- Origem: `https://github.com/code-423n4/2022-12-escher`.
- Relatorio publico: `https://code4rena.com/reports/2022-12-escher`.
- Fonte local:
  `smart-audt/contracts/real/escher/src/minters/FixedPrice.sol`.
- Run apos correcao da normalizacao:
  `runs/20260528_093456_FixedPrice`.
- Resultado: 0 achados, 0 candidatos formais, 0 static-confirmed.

Interpretacao:

- O contrato contem `selfdestruct`, mas dentro de funcao interna.
- O risco do relatorio Escher e arquitetural/de compatibilidade de opcode, nao
  uma autorizacao simples modelada pela classe `suicidal`.
- O fallback de `selfdestruct` foi restringido para evitar criar um finding
  falso chamado `destroy`.
- Esse caso e um teste negativo importante: o melhor comportamento do agente
  era nao corrigir.

Relatorio:

- `docs/retests/real-code-escher-selfdestruct-triage-20260528.md`.

### Code4rena Caviar `PrivatePool.sol`

- Origem: `https://github.com/code-423n4/2023-04-caviar`.
- Relatorio publico: `https://code4rena.com/reports/2023-04-caviar`.
- Fonte local:
  `smart-audt/contracts/real/caviar/src/PrivatePool.sol`.
- Tamanho: 794 linhas.
- Run principal: `runs/20260528_101335_PrivatePool`.
- Resultado: 0 achados normalizados acionaveis, 0 candidatos formais,
  0 static-confirmed.

Interpretacao:

- Este foi o primeiro teste na faixa 700-1200 linhas apos o Inverse `Market`.
- O contrato compila com dependencias reais em repo Foundry.
- O pipeline leu `remappings.txt` e resolveu imports sem stubs manuais.
- O resultado foi uma triagem negativa: o agente nao chamou LLM/Certora e nao
  inventou patch.
- Esse comportamento e desejavel quando os achados nao caem nas classes
  suportadas com evidencia suficiente.

Relatorio:

- `docs/retests/real-code-caviar-privatepool-20260528.md`.

### Code4rena Astaria

- Origem: `https://github.com/code-423n4/2023-01-astaria`.
- Fonte local:
  `smart-audt/contracts/real/astaria`.
- Candidatos de tamanho adequado:
  - `src/PublicVault.sol`: 725 linhas;
  - `src/AstariaRouter.sol`: 803 linhas;
  - `src/LienToken.sol`: 919 linhas.

Bloqueio:

- Esses contratos dependem do submodule `AstariaXYZ/astaria-gpl`.
- O submodule nao clonou sem autenticacao no ambiente atual.
- Decisao: nao usar stubs manuais para nao descaracterizar o contrato real.

Relatorio:

- `docs/retests/real-code-astaria-dependency-blocker-20260528.md`.

## Avaliacoes Snapshot

Snapshots mais recentes:

- Core benchmark:
  - `docs/evaluations/evaluation-results-20260524_232506_044465.md`
- Benchmark + exploratory:
  - `docs/evaluations/evaluation-results-20260527_100012_638925.md`
- Todos os contratos registrados:
  - `docs/evaluations/evaluation-results-20260525_004125_584645.md`

## Riscos Abertos

- O `patch_guard` ainda permite alguns casos como warning. Em contratos maiores,
  isso pode aceitar reformatacao ampla demais.
- `unprotected-critical-update` ainda nao deve ser promovida para correcao automatica.
- Reentrancia continua fora do escopo automatico por enquanto.
- Specs Certora geradas por LLM ainda precisam dos validadores deterministas para evitar
  falso senso de verificacao.
- Logs com `envfreeFuncsStaticCheck` violado devem bloquear a conclusao do run;
  a rule alvo passar nao basta se a spec estiver invalida.
- O resultado em codigo real ainda cobre poucas classes; o proximo experimento
  deve escolher outra classe vulneravel em Solidity 0.8 sem especializar a regra
  para um contrato especifico.
- `tx-origin` precisa de refinamento semantico. O Inverse `BorrowController.sol`
  usa `tx.origin` em uma politica de allowlist/EOA, que nao e equivalente a uma
  regra simples `owner()`/`onlyOwner`.
- Alguns repos reais podem bloquear por dependencia indisponivel. O pipeline
  deve registrar esses casos como bloqueio de ambiente/dependencia, nao como
  falha de analise.

## Proximos Passos Recomendados

1. Transformar certos warnings do `patch_guard` em bloqueio quando houver muitos hunks fora do alvo.
2. Adicionar autorepair para restaurar comentarios fora do alvo quando a LLM apenas reescrever texto.
3. Criar uma metrica de minimalidade por run:
   - hunks totais;
   - hunks permitidos;
   - hunks fora do alvo;
   - strings restauradas;
   - comentarios alterados.
4. Testar outro contrato real Solidity 0.8 com uma classe diferente de
   `missing-zero-check`.
5. Refinar `tx-origin` antes de promover essa classe para mais contratos reais.
6. So fazer merge em `develop` depois de revisao manual dos professores.
