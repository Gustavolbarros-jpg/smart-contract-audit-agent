# O oráculo formal local: quanto do espaço de defeito o pipeline passa a ver

**Data:** 2026-11-17
**Evidência:** `runs/oracle_validation_20261116/`, `runs/20261117_oracle_defivault/`,
`runs/20261117_arm_a2_deterministic/`
**Código:** `tools/certora_cli.verify_locally`, `agent/mutant_oracle.py`,
`specs/oracle/DeFiVault.spec`

---

## 1. O problema que isso resolve

O balanço de 12/11 registrou a dívida central do projeto em três causas somadas. A segunda
era a mais incômoda: **das 46 mutações injetadas no `DeFiVault_FIXED.sol`, o Slither (com o
detector próprio) produz achado novo em 9.** Os operadores AOR, BOR, UOR, EED e PKR têm
detectabilidade **zero**. Um defeito que o instrumento de medição não vê nunca chega ao
estágio de reparo, logo o benchmark nunca cobra o agente por ele — e nenhum número de
"resolveu X de Y" tem significado sobre esse pedaço do espaço.

Faltava um oráculo que não fosse o Slither. O Certora Prover era o candidato óbvio e estava
barrado pelo custo: cada verificação consumia cota de nuvem.

## 2. O achado técnico

`certoraRun --compilation_steps_only` para **antes de enviar** o job, não antes de
**verificar**. O `emv.jar` roda na máquina e imprime vereditos de regra reais.

Validado em 16/11 com um par (`runs/oracle_validation_20261116/`): mesma spec, original
`Verified`, mutante AOR `Violated` com contraexemplo, nenhuma URL de job nos logs, menos de
1 min cada. Está dentro do pipeline em `tools/certora_cli.verify_locally`, e
`AUDIT_CERTORA_LOCAL=1` faz o pipeline inteiro rodar assim.

Duas armadilhas ficaram no código, não na cabeça de quem roda:

- O veredito vem das linhas `Verified:` / `Violated:`. A tabela de resultados diz
  `Not violated`, que lida com essas duas palavras significa o contrário.
- `<regra>-rule_not_vacuous` aparece `Violated` sempre que a regra é **alcançável**. Se esse
  sanity check vira `Verified`, a regra passou **sem ser exercitada** — é exatamente o que um
  "reparo" que faz a função reverter sempre provoca. `LocalVerdict.vacuous_rules` marca isso,
  e um reparo nessas condições não conta como reparo.

## 3. A spec congelada

`specs/oracle/DeFiVault.spec`, 19 regras escritas a partir do original: saldos andam
exatamente o valor pedido (saque e depósito, no saldo do usuário e no total), o lock e o teto
de saque valem, a whitelist e o `paused` barram saque, só o dono administra, a transferência
de posse exige o `pendingOwner` e rejeita o endereço zero, e o pool de recompensa se
conserva. **As 19 verificam no original e nenhuma é vácua** (28,1 s).

Nenhuma regra fala de um defeito específico — é isso que permite rodar a mesma spec em todo
mutante. A spec é congelada: nenhuma regra pode ser acrescentada, apertada ou afrouxada
depois de se conhecer o resultado de um mutante.

## 4. Resultado: 46 mutantes, dois instrumentos

| Slither \ oráculo | mata | sobrevive | erro |
|---|---|---|---|
| **detecta** (9) | 3 | 6 | 0 |
| **não vê** (35) | **15** | 20 | 0 |
| não compila (2) | 0 | 0 | 2 |

Dos 44 mutantes que compilam, o Slither pegava **9 (20%)**; Slither + oráculo pegam
**24 (54%)**.

**Os 15 que só o oráculo pega** não são suposição: cada um viola uma propriedade escrita
antes de o mutante existir. `withdraw_debits_exactly` (um saque que credita em vez de
debitar), `deposit_credits_exactly`, `claim_reward_conserves_the_reward_pool`,
`only_the_owner_pauses` / `_sets_the_cap` / `_sets_the_reward_rate` (o `==` do `onlyOwner`
virou `!=`), `accept_ownership_needs_the_pending_owner`,
`transfer_ownership_rejects_the_zero_address`, `withdraw_is_blocked_while_paused`,
`withdraw_needs_the_whitelist`.

**Os dois instrumentos são complementares, não aninhados.** 6 mutantes o Slither detecta e o
oráculo não mata: remoção de `onlyOwner` em `unpause`, `setLockPeriod`,
`removeFromWhitelist`, `transferOwnership` e `emergencyWithdraw` — funções para as quais a
spec congelada não escreveu regra de autorização. É lacuna da spec e fica registrada como
lacuna, não corrigida depois do fato.

**20 mutantes ninguém pega**, por três causas que não devem ser somadas:

| Causa | Quantos | Observação |
|---|---|---|
| CVL não fala de eventos | 5 (EED) | a deleção de um `emit` não é expressável |
| Aperto de limite (`>=`→`>`) | 7 (BOR) | pegaria uma propriedade de *liveness*, que a spec não tem |
| Mutante equivalente | ~2 (MD@173, FXR@174) | `destroy` ainda tem `require(msg.sender == owner)` no corpo; sem efeito observável |

O mutante equivalente **sai da população** do experimento em vez de contar como erro do
agente — está declarado assim no pré-registro.

## 5. Custo

| | |
|---|---|
| cota de nuvem | **zero** |
| original (19 regras) | 28,1 s |
| média por mutante | 29,0 s |
| varredura de 46 | ~22 min de CPU |
| disco | ~30 MB de saída do Prover por verificação (1,4 GB na varredura inteira) — isolados em `_prover/`, apagáveis com `--prune-prover-dirs` |

## 6. O que isso muda no relatório

A frase "a generalização do LLM continua não demonstrada" **permanece verdadeira**, e esta
rodada não a contradiz: nada aqui mede o LLM. O que muda é que a segunda causa da dívida
deixa de ser um limite do método e passa a ser uma escolha de implementação — existe um
oráculo que cobra o agente por 15 defeitos que o Slither não vê, de graça.

O desenho do experimento que pode falsificar a generalização está em
`docs/experimento-generalizacao-pre-registro.md`, com a predição declarada antes da rodada.
