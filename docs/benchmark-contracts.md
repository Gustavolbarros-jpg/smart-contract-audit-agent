# Benchmark Contract Registry

Data: 2026-05-24

Este arquivo separa os contratos Solidity 0.8 usados pelo pipeline em grupos
operacionais. A separacao e feita por manifesto no codigo, sem mover ou apagar
arquivos em `smart-audt/contracts/`.

Fonte no codigo: `agent/core/contract_registry.py`.

## Grupos

- `benchmark`: suite principal usada por `python3 agent/evaluate.py`.
- `exploratory`: contratos Solidity 0.8 executaveis, bons para medir cobertura,
  mas ainda fora da pontuacao principal.
- `manual`: versoes corrigidas, exemplos finais ou arquivos com anotacoes
  manuais; nao devem ser entrada padrao do agente.
- `scratch`: arquivo de experimento/malformado; preservado, mas excluido de
  benchmarks.

## Suite Benchmark

| Contrato | Uso |
| --- | --- |
| `SimpleBank.sol` | Benchmark positivo para `missing-zero-check` e `tx-origin`. |
| `King.sol` | Benchmark positivo para auth, `arbitrary-send-eth` e zero-checks. |
| `CrowdfundingVault.sol` | Benchmark positivo incluindo `unchecked-lowlevel` static-confirmed. |
| `DeFiVault.sol` | Benchmark positivo misto para auth, zero-check, `suicidal` e envio de ETH. |
| `ERC2771MulticallVulnerable.sol` | Benchmark positivo para composicao ERC2771 + multicall com `delegatecall`. |

## Exploratorios

| Contrato | Uso |
| --- | --- |
| `TimelockVault.sol` | Caso positivo exploratorio para atualizacao critica sem autorizacao; ainda fora do benchmark principal por risco de falso positivo da heuristica. |
| `AnotherVulnerableBank.sol` | Exemplo bancario 0.8 executavel para cobertura exploratoria. |
| `VulnerableBankToken.sol` | Controle negativo atual: Slither acha sinais informacionais, mas nada acionavel. |

## Manuais / Corrigidos

| Contrato | Motivo |
| --- | --- |
| `DeFiVault_FIXED.sol` | Saida corrigida/gerada. |
| `SimpleBank_FIXED.sol` | Saida corrigida/gerada. |
| `SafeBankToken.sol` | Exemplo corrigido manualmente. |
| `SafeBankToken2.sol` | Exemplo corrigido manualmente. |
| `SuperSecureBank.sol` | Exemplo final/corrigido manualmente. |
| `VulnerableBankTokenCorrected.sol` | Exemplo corrigido manualmente. |
| `VulnerableVault.sol` | Arquivo com comentarios e patches manuais de experimento. |

## Scratch

| Contrato | Motivo |
| --- | --- |
| `TreasuryVault.sol` | Arquivo preservado, mas atualmente malformado (`}x` no fim). |

## Comandos

Listar apenas benchmarks:

```bash
python3 agent/main.py --list-benchmarks
```

Listar por grupo:

```bash
python3 agent/main.py --list-contracts --contract-group exploratory
python3 agent/main.py --list-contracts --contract-group manual
```

Gerar avaliacao da suite principal:

```bash
python3 agent/evaluate.py
```

Gerar avaliacao incluindo exploratorios:

```bash
python3 agent/evaluate.py --include-exploratory
```
