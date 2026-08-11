# Real Code Retest - Forgotten Runes Warriors Minter - 2026-05-27

## Objetivo

Validar o pipeline em um contrato real Solidity 0.8 com imports externos e
tamanho maior que os contratos sinteticos do benchmark.

Este teste foi escolhido para responder tres perguntas:

- o pipeline consegue compilar codigo real com dependencias/remappings;
- a normalizacao Slither evita falsos positivos que levariam a patches ruins;
- a correcao consegue ser minima sem pedir para a LLM reescrever um contrato
  grande inteiro.

## Contrato Testado

- Fonte local:
  `smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter.sol`
- Origem externa:
  `https://github.com/code-423n4/2022-05-runes`
- Contrato interno:
  `ForgottenRunesWarriorsMinter`
- Dependencias locais usadas no teste:
  `smart-audt/contracts/real/runes/node_modules/@openzeppelin/contracts`

## Run

- Run principal:
  `runs/20260527_105459_ForgottenRunesWarriorsMinter`
- Modelo configurado:
  `llama-3.3-70b-versatile`
- Arquivo corrigido gerado:
  `smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter_AGENT_FIXED.sol`

## Resultado

- Slither normalizou 71 achados.
- O filtro formal selecionou 2 candidatos.
- Certora confirmou 2 vulnerabilidades:
  - `VULN_015`: `missing-zero-check` em `setVaultAddress(address)`;
  - `VULN_016`: `missing-zero-check` em `setWethAddress(address)`.
- O patch deterministico cobriu as 2 vulnerabilidades.
- O `patch_guard` aprovou o patch com:
  - 2 hunks alterados;
  - 0 erros;
  - 0 avisos.
- A revalidacao resolveu `2/2`.
- O pipeline concluiu com sucesso na tentativa 1.

## Patch Aplicado

O patch foi propositalmente minimo:

```solidity
function setVaultAddress(address _newVaultAddress) public onlyOwner {
    require(_newVaultAddress != address(0), "Zero address"); // FIX VULN_015
    vault = _newVaultAddress;
}

function setWethAddress(address _newWethAddress) public onlyOwner {
    require(_newWethAddress != address(0), "Zero address"); // FIX VULN_016
    weth = _newWethAddress;
}
```

## Correcoes De Pipeline Validadas Por Este Teste

- `slither_cli` agora detecta `node_modules` proximo ao contrato e adiciona
  remappings Solidity quando necessario.
- `certora_cli` agora passa `--packages_path` e `--packages` para imports
  externos.
- A validacao de contratos corrigidos com imports gera o `_AGENT_FIXED.sol` no
  mesmo diretorio do contrato original, preservando imports relativos.
- Parametros de interfaces/contratos em `methods{}` sao normalizados para
  `address` quando necessario para CVL.
- Chamadas ERC20 como `token.transfer(msg.sender, amount)` nao sao mais
  classificadas como `arbitrary-send-eth`.
- Helpers que retornam `success` de low-level call nao sao mais tratados como
  `unchecked-lowlevel` quando o chamador decide o fallback.
- `missing-zero-check` agora pode ser corrigido deterministicamente quando o
  alvo e inferivel pelos elementos do Slither.

## Interpretacao

Este teste e mais forte que os contratos sinteticos porque inclui:

- codigo real de um repositorio externo;
- imports OpenZeppelin;
- interfaces e tipos definidos pelo usuario;
- contrato grande o suficiente para expor truncamento de resposta da LLM;
- achados Slither que precisaram ser filtrados para evitar patch errado.

O resultado sugere que a arquitetura esta caminhando para um bom desenho:

- Slither continua sendo o sensor inicial;
- Certora confirma as propriedades realmente formalizaveis;
- o LLM ainda ajuda em planejamento e casos menos mecanicos;
- correcoes mecanicas conhecidas devem ser feitas deterministicamente;
- o `patch_guard` impede que patches grandes ou truncados sejam aceitos.

## Limitacoes

- Este teste validou principalmente `missing-zero-check`.
- Nao valida reentrancia.
- Nao prova que o pipeline resolve todas as vulnerabilidades reais do contrato.
- O proximo passo deve testar outra classe vulneravel em codigo real sem
  transformar tudo em regra especifica para este contrato.
