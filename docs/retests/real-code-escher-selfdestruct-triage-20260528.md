# Real Code Triage - Escher FixedPrice - 2026-05-28

## Objetivo

Testar um caso real com `selfdestruct` para verificar se o pipeline estava
generalizando a classe `suicidal` de forma segura.

## Contrato Testado

- Origem externa:
  `https://github.com/code-423n4/2022-12-escher`
- Relatorio publico:
  `https://code4rena.com/reports/2022-12-escher`
- Fonte local:
  `smart-audt/contracts/real/escher/src/minters/FixedPrice.sol`
- Solidity:
  `pragma solidity ^0.8.17`

## Observacao Importante

O relatorio da Code4rena discute `selfdestruct`, mas o risco ali nao e a mesma
propriedade que o pipeline chama de `suicidal`.

No pipeline atual, `suicidal` significa:

- `selfdestruct` acessivel por fluxo publico/externo sem autorizacao clara por
  `msg.sender`.

No Escher `FixedPrice`, o `selfdestruct` fica dentro da funcao interna `_end`.
O caso do relatorio e mais arquitetural/de compatibilidade de opcode, nao uma
autorizacao simples que deva ser corrigida com `onlyOwner`.

## Runs

- Run que expôs o problema:
  `runs/20260528_092003_FixedPrice`
- Run apos correcao da normalizacao:
  `runs/20260528_093456_FixedPrice`

## Resultado

Depois do ajuste, o pipeline reportou:

- 0 achados normalizados;
- 0 candidatos formais;
- 0 static-confirmed.

Isso evita criar uma vulnerabilidade falsa chamada `destroy` quando o contrato
nao possui essa funcao.

## Melhoria De Pipeline

O fallback de `selfdestruct` foi restringido:

- nao cria mais finding para `selfdestruct` em funcao interna;
- nao cria finding para funcao publica/externa com guarda obvia, como
  `onlyOwner`, `onlyGov`, `onlyOperator` ou `require(msg.sender == owner)`;
- evita confundir risco arquitetural de `selfdestruct` com autorizacao
  vulneravel.

## Interpretacao

Esse teste e importante porque mostra um caso em que o melhor comportamento do
agente e nao corrigir. A generalizacao boa tambem inclui saber quando uma regra
existente nao representa a vulnerabilidade real.
