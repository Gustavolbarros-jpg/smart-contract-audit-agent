# Real Code Retest - Solmate WETH - 2026-05-27

Este documento registra o primeiro teste em codigo externo real antes de novas
mudancas no `patch_guard`.

## Alvo

Projeto: Solmate.

Contrato principal:

- `smart-audt/contracts/real/solmate/src/tokens/WETH.sol`

Dependencias baixadas:

- `smart-audt/contracts/real/solmate/src/tokens/ERC20.sol`
- `smart-audt/contracts/real/solmate/src/utils/SafeTransferLib.sol`

Fonte upstream:

- `https://github.com/transmissions11/solmate`

## Motivo Da Escolha

O Solmate WETH e um contrato real Solidity `>=0.8.0`, pequeno, com imports
reais e sem necessidade de configurar um projeto Hardhat/Foundry inteiro.

Esse teste serve para validar uma coisa importante: quando o codigo real nao
tem uma vulnerabilidade acionavel dentro das classes automatizadas atuais, o
pipeline deve parar sem inventar uma correcao.

## Run

Run gerado:

- `runs/20260527_102842_WETH`

Comando:

```bash
python3 agent/main.py --contract smart-audt/contracts/real/solmate/src/tokens/WETH.sol
```

## Resultado

O pipeline compilou o contrato e suas dependencias via Slither.

Resumo do run:

- Achados normalizados acionaveis: 0.
- Candidatos formais: 0.
- `static_confirmed`: 0.
- Status operacional: `no_actionable_candidates`.
- Nao chamou LLM.
- Nao chamou Certora.
- Nao gerou patch.

Artefato principal:

- `runs/20260527_102842_WETH/slither_normalized.json`

Conteudo relevante:

```json
{
  "vulnerabilidades": [],
  "stats": {
    "total": 0,
    "formalizable": 0,
    "non_formalizable": 0
  }
}
```

## Interpretacao

Esse foi um bom teste negativo em codigo real:

- O pipeline lidou com imports locais baixados de um projeto externo.
- O normalizador nao promoveu automaticamente ruido de biblioteca como
  vulnerabilidade corrigivel.
- O agente nao gastou LLM nem Certora quando nao havia classe acionavel.

Isso nao prova correcao em contrato real vulneravel. Prova que o pipeline
consegue analisar um alvo real Solidity 0.8 e nao alucinar patch quando o caso
nao passa pelo catalogo atual.

## Proximo Teste Real

Para testar correcao em codigo real, precisamos escolher um contrato Solidity
0.8 externo com ao menos uma classe ja suportada:

- `missing-zero-check`;
- `tx-origin`;
- `suicidal`;
- `arbitrary-send-eth` claro;
- `unchecked-lowlevel`.

O ideal e evitar, por enquanto, contratos reais com muitos remappings,
submodules ou dependencias de build complexas.
