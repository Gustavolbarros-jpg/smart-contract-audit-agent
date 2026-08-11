# Real Code Candidate - Astaria Dependency Blocker - 2026-05-28

## Objetivo

Avaliar Astaria como candidato para o degrau de 700-1200 linhas.

## Repositorio

- Origem externa:
  `https://github.com/code-423n4/2023-01-astaria`
- Fonte local:
  `smart-audt/contracts/real/astaria`

## Contratos Candidatos

- `src/PublicVault.sol`: 725 linhas.
- `src/AstariaRouter.sol`: 803 linhas.
- `src/LienToken.sol`: 919 linhas.

## Bloqueio

Os contratos grandes dependem do submodule:

- `lib/gpl`
- URL declarada: `https://github.com/AstariaXYZ/astaria-gpl`

O clone do submodule falhou por exigir autenticacao ou por nao estar acessivel
publicamente no ambiente atual:

```text
fatal: could not read Username for 'https://github.com': No such device or address
```

## Interpretacao

Astaria tem tamanho perfeito para o proximo degrau, mas nao e um bom alvo agora
porque a compilacao depende de uma dependencia que nao esta publicamente
resolvivel pelo pipeline.

O pipeline nao deve tentar contornar isso com stubs manuais, pois isso mudaria
o contexto real do contrato e poderia invalidar o resultado.

## Decisao

Astaria fica como candidato bloqueado por dependencia externa.

Para validacao real, foi usado Caviar `PrivatePool.sol`, que tem 794 linhas e
dependencias publicas resolviveis.
