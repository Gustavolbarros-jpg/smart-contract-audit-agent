# Relatorio Consolidado - Pipeline, Testes E Principais Achados

Data: 2026-05-28

Branch de trabalho: `feature/pipeline-guardrails`

## Objetivo Do Projeto

O projeto implementa um pipeline para auxiliar auditoria e correcao de
contratos inteligentes em runtime. A ideia central nao e deixar a LLM decidir
tudo sozinha, mas combinar:

- Slither como sensor inicial;
- normalizacao deterministica dos achados;
- LLM para planejamento e raciocinio quando necessario;
- geracao/validacao de specs CVL;
- Certora para confirmacao formal;
- diagnostico;
- correcao;
- `patch_guard` para bloquear patch amplo, truncado ou fora de escopo;
- revalidacao com Certora e Slither.

## Como O Pipeline Funciona

Fluxo principal:

1. O contrato Solidity e analisado pelo Slither.
2. Os achados brutos sao normalizados para classes conhecidas, como
   `missing-zero-check`, `tx-origin`, `suicidal`, `arbitrary-send-eth`,
   `unchecked-lowlevel` e `erc2771-multicall-context`.
3. Achados sem boa propriedade formal ou com alto risco de falso positivo sao
   filtrados.
4. Para achados formalizaveis, o pipeline gera uma spec CVL.
5. O Certora roda no contrato original para confirmar se a propriedade e
   violada.
6. Apenas vulnerabilidades confirmadas seguem para diagnostico.
7. A correcao pode ser:
   - deterministica para padroes mecanicos conhecidos;
   - via LLM quando o caso ainda exige raciocinio textual/estrutural.
8. O `patch_guard` verifica se o patch e minimo e se alterou apenas regioes
   associadas aos achados confirmados.
9. O contrato corrigido e revalidado com Certora e Slither.
10. A comparacao final classifica os achados como resolvidos, persistentes ou
    inconclusivos.

## Evolucao Importante Do Pipeline

Durante os testes, o pipeline deixou de depender apenas da LLM e ganhou
guardrails mais fortes:

- diagnostico deterministico para classes conhecidas;
- patch deterministico para `missing-zero-check`;
- spec deterministica para `missing-zero-check`;
- suporte a imports reais com `node_modules`;
- suporte a `remappings.txt` de Foundry;
- geracao de arquivo `_AGENT_FIXED.sol` no diretorio original quando ha imports
  relativos;
- normalizacao de tipos de interface/contrato para `address` no CVL;
- exclusao de interfaces top-level do `methods{}` do contrato alvo;
- filtro para evitar falso positivo de ERC20 `transfer(...)` como envio
  arbitrario de ETH;
- filtro para evitar `unchecked-lowlevel` quando o helper retorna `success` e o
  chamador trata o resultado;
- filtro para evitar `suicidal` falso quando `selfdestruct` esta em funcao
  interna ou guardada.

## Testes Com Contratos Controlados

| Contrato | Tipo | Run principal | Resultado |
| --- | --- | --- | --- |
| `SimpleBank` | benchmark controlado | `runs/20260523_152511_SimpleBank` | 3/3 resolvidos |
| `DeFiVault` | benchmark maior | `runs/20260524_232148_DeFiVault` | 5/5 resolvidos |
| `CrowdfundingVault` | benchmark medio | `runs/20260524_212214_CrowdfundingVault` | 4/4 resolvidos |
| `ERC2771MulticallVulnerable` | composicao ERC2771 + multicall | `runs/20260524_192015_ERC2771MulticallVulnerable` | 1/1 resolvido |
| `EnterpriseTreasury300` | stress controlado, 327 linhas | `runs/20260527_095632_EnterpriseTreasury300` | 9/9 resolvidos |

### Principais Achados Em Contratos Controlados

No `EnterpriseTreasury300`, o pipeline validou uma combinacao mais ampla:

- `missing-zero-check`: 5 achados resolvidos;
- `tx-origin`: 1 achado resolvido;
- `suicidal`: 1 achado resolvido;
- `arbitrary-send-eth`: 1 achado resolvido;
- `unchecked-lowlevel`: 1 achado resolvido.

Resultado final: `9/9`.

Esse caso foi importante porque mostrou que o pipeline conseguia lidar com um
contrato maior do que os exemplos pequenos iniciais, mantendo revalidacao e
comparacao final.

## Testes Com Contratos Reais

| Contrato real | Origem | Tamanho | Run | Resultado |
| --- | --- | ---: | --- | --- |
| Solmate `WETH.sol` | `transmissions11/solmate` | pequeno | `runs/20260527_102842_WETH` | 0 candidatos acionaveis |
| Forgotten Runes `ForgottenRunesWarriorsMinter.sol` | Code4rena `2022-05-runes` | 631 linhas | `runs/20260527_105459_ForgottenRunesWarriorsMinter` | 2/2 resolvidos |
| Inverse `Market.sol` | Code4rena `2022-10-inverse` | 621 linhas | `runs/20260528_093346_Market` | 3/3 resolvidos |
| Escher `FixedPrice.sol` | Code4rena `2022-12-escher` | 112 linhas | `runs/20260528_093456_FixedPrice` | 0 candidatos apos triagem correta |
| Caviar `PrivatePool.sol` | Code4rena `2023-04-caviar` | 794 linhas | `runs/20260528_101335_PrivatePool` | 0 candidatos acionaveis |
| Astaria | Code4rena `2023-01-astaria` | 725-919 linhas candidatos | sem run completo | bloqueado por dependencia privada/indisponivel |

### Forgotten Runes

Contrato:

- `smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter.sol`

Achados confirmados:

- `VULN_015`: falta de zero-check em `setVaultAddress(address)`;
- `VULN_016`: falta de zero-check em `setWethAddress(address)`.

Resultado:

- Slither normalizou 71 achados;
- Certora confirmou 2;
- patch deterministico inseriu 2 `require`;
- `patch_guard`: 2 hunks, 0 erros, 0 avisos;
- comparacao final: `2/2`.

Esse teste mostrou que o pipeline compila e corrige contrato real com imports,
sem pedir para a LLM reescrever um contrato grande inteiro.

### Inverse Market

Contrato:

- `smart-audt/contracts/real/inverse/src/Market.sol`

Achados confirmados:

- `VULN_020`: falta de zero-check em `setPauseGuardian(address)`;
- `VULN_023`: falta de zero-check em `setGov(address)`;
- `VULN_026`: falta de zero-check em `setLender(address)`.

Resultado:

- Slither normalizou 63 achados;
- Certora confirmou 3;
- spec CVL foi gerada deterministicamente;
- diagnostico foi deterministico;
- patch foi deterministico;
- `patch_guard`: 3 hunks, 0 erros, 0 avisos;
- comparacao final: `3/3`.

Esse foi o maior contrato real corrigido ate agora com ciclo completo de
confirmacao, patch e revalidacao.

### Solmate WETH

Resultado:

- 0 candidatos acionaveis;
- pipeline parou antes de LLM, Certora e patch.

Importancia:

- funciona como controle negativo;
- mostra que o agente nao inventa correcao quando nao ha achado confiavel nas
  classes suportadas.

### Escher FixedPrice

Resultado:

- apos ajuste da normalizacao: 0 candidatos.

Importancia:

- o contrato contem `selfdestruct`, mas em funcao interna;
- o risco real do relatorio e arquitetural/de compatibilidade de opcode, nao a
  classe `suicidal` simples;
- o pipeline foi ajustado para nao inventar uma funcao `destroy` falsa.

### Caviar PrivatePool

Contrato:

- `smart-audt/contracts/real/caviar/src/PrivatePool.sol`

Resultado:

- 794 linhas;
- compilou com Slither usando `remappings.txt` de Foundry;
- 0 candidatos acionaveis;
- pipeline parou antes de LLM, Certora e patch.

Importancia:

- valida triagem negativa em contrato real maior;
- mostra economia de tokens: nenhuma chamada LLM foi feita nesse run;
- mostra que o suporte a Foundry/remappings esta funcionando.

### Astaria

Astaria tinha bons candidatos de tamanho:

- `PublicVault.sol`: 725 linhas;
- `AstariaRouter.sol`: 803 linhas;
- `LienToken.sol`: 919 linhas.

Bloqueio:

- dependencia `AstariaXYZ/astaria-gpl` nao clonou sem autenticacao;
- decisao: nao criar stubs manuais para nao descaracterizar o contrato real.

## Achados Por Classe

Classes com ciclo completo validado:

- `missing-zero-check`;
- `tx-origin` em padroes simples de autorizacao;
- `suicidal` em padroes simples de autorizacao;
- `arbitrary-send-eth`;
- `unchecked-lowlevel`;
- `erc2771-multicall-context`.

Classes/areas que exigem cuidado:

- `reentrancy`: mantida fora do escopo automatico por enquanto;
- `tx-origin` em politica de allowlist/EOA, como Inverse `BorrowController`;
- `selfdestruct` arquitetural, como Escher;
- vulnerabilidades economicas/oracle/accounting, que exigem invariantes de
  negocio mais especificos.

## Como Testamos Sem Gastar Tokens Desnecessarios

O pipeline evita uso da LLM quando possivel:

- se Slither nao gera candidatos acionaveis, o pipeline para antes da LLM;
- `missing-zero-check` pode gerar spec e patch deterministicamente;
- diagnostico de classes conhecidas pode ser deterministico;
- casos negativos como Solmate WETH e Caviar PrivatePool nao chamaram Groq;
- o `patch_guard` bloqueia patches ruins antes de desperdiçar ciclos de
  revalidacao.

## Limites Encontrados

1. Specs invalidas podem gerar conclusoes enganosas se nao forem bloqueadas.
   Por isso logs com erro de CVL/Certora agora bloqueiam o run.
2. `envfree` mal aplicado pode invalidar uma spec. O pipeline passou a remover
   `envfree` de funcoes que leem `msg.sender`, `tx.origin`, `block.timestamp`
   ou similares.
3. Contratos reais podem ter interfaces no mesmo arquivo. O `methods{}` agora
   extrai apenas a API do contrato principal.
4. Contratos reais Foundry exigem `remappings.txt`.
5. Algumas dependencias externas podem estar indisponiveis ou exigir
   autenticacao.
6. Nem todo `selfdestruct` e `suicidal`; nem todo `tx.origin` e uma regra
   simples de `owner()`.

## Conclusao

O pipeline ja demonstra tres comportamentos importantes:

1. Corrigir vulnerabilidades confirmadas em contratos controlados.
2. Corrigir vulnerabilidades mecanicas em contratos reais com imports.
3. Parar sem gastar LLM/Certora quando nao ha candidato confiavel.

O resultado mais forte ate agora e o Inverse `Market.sol`: contrato real de 621
linhas, 63 achados Slither normalizados, 3 vulnerabilidades confirmadas pelo
Certora e `3/3` resolvidas com patch minimo.

O resultado de maior tamanho foi Caviar `PrivatePool.sol`, com 794 linhas,
usado como controle negativo: compilou e analisou corretamente, mas nao gerou
patch sem evidencia.

## Proximos Passos

- Escolher novo contrato real de 800-1200 linhas com achado acionavel.
- Priorizar uma classe diferente de `missing-zero-check`.
- Refinar `tx-origin` para distinguir autorizacao vulneravel de politica EOA.
- Manter reentrancia fora do automatico ate haver uma estrategia formal mais
  confiavel.
- Continuar registrando controles negativos, pois eles medem resistencia a
  alucinacao.
