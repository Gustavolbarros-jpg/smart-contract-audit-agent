# Inventário de `runs/` — 17/11/2026, antes da poda

Levantado para responder uma pergunta concreta: **o que pode ser apagado sem perder
medição?** O número por rodada está em `docs/inventario-runs-20261117.json` (412 linhas,
uma por rodada).

## O total

| | tamanho | o que é |
|---|---|---|
| **Scratch do Prover** | **1.966 MB** | `emv-*`, `.certora_internal`, `_prover` — TAC compilado, relatório HTML, temporários do `emv.jar` |
| **Evidência** | **945 MB** | 11.899 arquivos: 1.284 logs de veredito, 8.514 JSONs, 1.291 fontes `.sol`, specs |
| | **2.912 MB** | 412 rodadas |

Correção de um número que circulou antes: eu tinha dito "126 MB de evidência". Estava
errado — veio de um `find … | xargs du -ch | tail -1`, e o `xargs` quebra a lista em
lotes, cada um com seu próprio total; `tail -1` mostrou só o do último lote. O valor certo
é **945 MB**, e a maior parte dele (572 MB) é uma rodada só, `static_only`.

## Onde está o scratch

Apenas **4 rodadas**, todas de 17/11, respondem por 100% dele:

| rodada | scratch | evidência | o que a evidência é |
|---|---|---|---|
| `20261117_oracle_defivault` | 1.360,6 MB | 3,2 MB | 44 logs de veredito + `report.json` — **a varredura dos 46 mutantes** |
| `20261117_arm_a2_deterministic` | 570,8 MB | 1,3 MB | 18 logs + relatório — **o braço determinístico** |
| `20261117_oracle_speccheck` | 30,4 MB | 0,1 MB | validação da spec congelada |
| `20261117_oracle_smoke` | 4,6 MB | 0,0 MB | teste de fumaça do oráculo |

As outras 408 rodadas não têm scratch nenhum: ou são anteriores ao oráculo local, ou
rodaram com `--prune-prover-dirs`.

**Por que a poda é segura:** o veredito de cada mutante fica no `.log` da rodada, que
vive *fora* dos `emv-*`. `docs/resultado-oraculo-formal-20261117.md` se apoia nesses 44
logs e no `report.json`, não no scratch. O `emv-*` é saída intermediária do `emv.jar` —
se alguém precisar dele de volta, é só rodar a varredura outra vez (28 s por contrato,
sem cota, por causa do `--compilation_steps_only`).

## Onde está a evidência

| rodada | tamanho | conteúdo |
|---|---|---|
| `static_only` | 572,3 MB | 2.332 JSONs + 697 `.sol` — a varredura `--static-only` do corpus real, base do resultado "33 → 77 correções determinísticas confirmadas" |
| 3× `TalosBaseStrategy` (09/11) | 4,9 MB cada | o contrato barrado pelo patch guard |
| `Market`, `ERC777-reentrancy`, … | ~3,9 MB cada | rodadas completas com log do Certora |
| restante (≈400 rodadas) | < 3 MB cada | pipeline completo: Slither normalizado, plano formal, spec, logs, comparação |

## Distribuição no tempo

| dia | rodadas | | dia | rodadas |
|---|---|---|---|---|
| 23–28/05 | 81 | | 04/11 | 65 |
| 27/06 | 13 | | 05/11 | 34 |
| 11–12/08 | 42 | | 08/11 | 52 |
| 18–23/08 | 15 | | 09/11 | 45 |
| 07–08/10 | 42 | | 17/11 | 18 |

Cinco diretórios sem data no nome (`static_only`, `probe_*`, `_probe_tmp`).

## Auditoria da poda

Antes de apagar, a lista completa dos 11.899 arquivos de evidência (caminho + tamanho)
foi reduzida a um hash, para que a poda possa ser conferida depois:

```
arquivos : 11.899
bytes    : 943.268.992
sha256   : c910969bfd0f6770a2183217a6bb8b1463eb43ec0b8d77ece2eb725ed96b4139
```

Se o mesmo cálculo depois da poda devolver os três valores idênticos, nenhum arquivo de
evidência foi tocado.
