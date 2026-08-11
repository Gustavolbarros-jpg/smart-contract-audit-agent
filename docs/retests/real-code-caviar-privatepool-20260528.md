# Real Code Retest - Caviar PrivatePool - 2026-05-28

## Objetivo

Testar o proximo degrau de tamanho em contrato real: 700-1200 linhas,
Solidity 0.8, repo publico e dependencias Foundry.

## Contrato Testado

- Origem externa:
  `https://github.com/code-423n4/2023-04-caviar`
- Relatorio publico:
  `https://code4rena.com/reports/2023-04-caviar`
- Fonte local:
  `smart-audt/contracts/real/caviar/src/PrivatePool.sol`
- Tamanho:
  794 linhas
- Solidity:
  `pragma solidity ^0.8.19`

## Run

- Run:
  `runs/20260528_101335_PrivatePool`

## Resultado

- O contrato compilou via Slither com imports reais.
- O pipeline leu `remappings.txt` estilo Foundry.
- Slither nao gerou achados normalizados acionaveis pelo catalogo atual.
- Candidatos formais: 0.
- Static-confirmed: 0.
- O pipeline parou antes de LLM/Certora/patch.

## Interpretacao

Este foi um teste negativo em contrato maior.

O comportamento esperado aqui era nao forcar uma correcao:

- o contrato tem 794 linhas;
- usa dependencias externas reais;
- possui chamadas externas/transferencias que poderiam induzir falsa correcao;
- mesmo assim o pipeline nao inventou vulnerabilidade dentro das classes
  atualmente suportadas.

Isso aumenta a confianca na triagem antes de gastar tokens ou rodar Certora.

## Melhoria De Pipeline Exercitada

Foi adicionado suporte geral a remappings Foundry:

- leitura de `remappings.txt`;
- resolucao de caminhos relativos ao root do projeto;
- uso desses remappings no Slither e no Certora.

Esse suporte tambem ajuda futuros testes em repos Foundry, nao apenas Caviar.

## Limites

- Este run nao exercitou patch/revalidacao porque nao houve candidato acionavel.
- O proximo alvo grande deve buscar uma classe diferente de
  `missing-zero-check`, mas com evidencia mais direta para evitar modelagem
  semantica excessiva.
