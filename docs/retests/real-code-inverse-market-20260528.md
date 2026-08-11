# Real Code Retest - Inverse Market - 2026-05-28

## Objetivo

Validar o pipeline em um contrato real maior, com mais de 600 linhas, vindo de
um repositorio publico da Code4rena.

Este teste foi feito depois do Forgotten Runes para verificar se o pipeline
continua funcionando em codigo real maior, com interfaces no mesmo arquivo,
funcoes de uma linha e propriedades mecanicas de validacao.

## Contrato Testado

- Origem externa:
  `https://github.com/code-423n4/2022-10-inverse`
- Relatorio publico:
  `https://code4rena.com/reports/2022-10-inverse`
- Fonte local:
  `smart-audt/contracts/real/inverse/src/Market.sol`
- Tamanho aproximado:
  621 linhas
- Solidity:
  `pragma solidity ^0.8.13`

## Run Principal

- Run:
  `runs/20260528_093346_Market`
- Arquivo corrigido:
  `agent/agent_outputs/Market_FIXED.sol`

## Resultado

- Slither normalizou 63 achados.
- O filtro formal selecionou 3 candidatos.
- A spec CVL foi gerada deterministicamente para `missing-zero-check`, sem
  chamar a LLM nessa etapa.
- Certora confirmou 3 vulnerabilidades:
  - `VULN_020`: `setPauseGuardian(address)`;
  - `VULN_023`: `setGov(address)`;
  - `VULN_026`: `setLender(address)`.
- O diagnostico foi deterministico.
- O patch foi deterministico.
- O `patch_guard` aprovou:
  - 3 hunks;
  - 0 erros;
  - 0 avisos.
- Revalidacao:
  - Certora aprovou;
  - Slither nao manteve os achados corrigidos;
  - comparacao final: `3/3`.

## Patch Aplicado

O patch expandiu funcoes de uma linha e adicionou validacao de endereco zero:

```solidity
function setGov(address _gov) public onlyGov {
    require(_gov != address(0), "Zero address"); // FIX VULN_023
    gov = _gov;
}

function setLender(address _lender) public onlyGov {
    require(_lender != address(0), "Zero address"); // FIX VULN_026
    lender = _lender;
}

function setPauseGuardian(address _pauseGuardian) public onlyGov {
    require(_pauseGuardian != address(0), "Zero address"); // FIX VULN_020
    pauseGuardian = _pauseGuardian;
}
```

## Melhorias De Pipeline Exercitadas

- O `methods{}` agora ignora interfaces top-level no mesmo arquivo e extrai
  apenas a API do contrato principal.
- Retornos nomeados com tipos de interface, como `IEscrow predicted`, sao
  normalizados para `address` em CVL.
- Specs de `missing-zero-check` podem ser geradas deterministicamente quando
  todas as regras selecionadas pertencem a esse padrao.
- O patch deterministico agora expande funcoes de uma linha antes de inserir
  `require(...)`, evitando Solidity invalido.

## Interpretacao

Este resultado e um degrau relevante:

- o pipeline rodou em contrato real de 621 linhas;
- confirmou e corrigiu propriedades com Certora;
- reduziu uso de LLM em uma etapa mecanica;
- preservou minimalidade do patch;
- evitou depender de prompt para gerar uma spec simples.

O teste ainda cobre principalmente `missing-zero-check`. A proxima meta deve
ser escolher outro contrato real com uma classe diferente que tenha semantica
compativel com a propriedade formal existente.
