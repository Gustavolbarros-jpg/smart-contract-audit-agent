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

## 4.1 Braço A2: a trilha determinística cobrada pelo oráculo

Dos 18 mutantes que a spec mata, o patch determinístico (Slither → catálogo → molde, sem
LLM e sem cota) conserta **4** — `runs/20261117_arm_a2_deterministic/`:

| operador | reparados | não reparados |
|---|---|---|
| AOR | 0 | 6 |
| BOR | 0 | 4 |
| UOR | 0 | 1 |
| MD | 2 | 2 |
| FXR | 2 | 1 |
| **total** | **4** | **14** |

Os 4 são exatamente os que caem numa classe da biblioteca de moldes: `unrestricted-write`
(`MD@136`, `MD@140`), `tx-origin` (`FXR@39`) e `missing-zero-check` (`FXR@151`). Nos 14
restantes a trilha **não aplicou patch nenhum** — o Slither não reporta nada acionável.
Nenhum reparo vácuo.

Controle (`runs/20261117_arm_a2_control/`): a mesma trilha no original não mutado não aplica
patch e as 19 regras continuam valendo, então nenhum reparo de achado pré-existente derruba
regra e contamina o braço.

**A trilha determinística é boa e limitada nos limites exatos da biblioteca: 4 de 4 nas
classes cobertas, 0 de 14 fora dela.** É essa a linha de base contra a qual qualquer número
do braço só-LLM tem de ser lido.

## 4.2 Um viés de instrumento, encontrado por este braço

`FXR@151` consta como "o Slither não vê" e, ainda assim, o molde o reparou.
`mutant_detection.py` só conta como detecção um achado de `category == "security"`, e
`missing-zero-check` está no catálogo como `validation`: o Slither **reporta** esse mutante,
só não como achado de segurança.

Leitura corrigida: dos 15 mortos-e-não-detectados, **14 não produzem achado de segurança
algum** e 1 produz achado de validação. A cobertura (9 → 24 de 44) não muda; a frase "o
Slither não vê" passa a ser "não reporta achado de segurança novo".

## 4.3 O teto que a arquitetura impõe

O pipeline repara o que o Slither reporta. Cruzando os dois estratos:

- **E1 ∩ E2 = 3** mutantes (`MD@136`, `MD@140`, `FXR@39`) — a população que o pipeline
  atual **consegue alcançar** com qualquer trilha de reparo.
- Os outros 15 de E1 são inalcançáveis pela arquitetura de hoje, por mais capaz que a LLM
  seja: não existe achado para diagnosticar.

Isso dá o próximo passo sem ambiguidade: **o diagnóstico precisa poder partir do
contraexemplo do oráculo**, não só do achado do Slither. Enquanto isso não existir, qualquer
afirmação sobre generalização está limitada a 3 de 46 mutantes — e dizer isso é parte do
resultado.

## 4.4 Braço A3: só LLM, trilha determinística desligada

Rodado nos 3 mutantes alcançáveis, com `AUDIT_NO_DETERMINISTIC_PATCH=1` e
`AUDIT_CERTORA_LOCAL=1` — `runs/20261117_arm_a3_llm/`:

| mutante | achados reparados | oráculo |
|---|---|---|
| `MD@136` | `unrestricted-write` | **verified**, nenhuma regra vácua |
| `MD@140` | `unrestricted-write` | **verified**, nenhuma regra vácua |
| `FXR@39` | `tx-origin` + `arbitrary-send-eth` | **verified**, nenhuma regra vácua |

**3 de 3 reparados e confirmados**, `patch_guard` sem erro nos três. Os 4 achados saíram
rotulados `origem: llm` por `repair_origin.json` — primeira vez que a origem do reparo é
campo escrito pelo caminho de código, e não inferência sobre artefatos.

**A predição pré-registrada estava errada.** O pré-registro dizia, antes da rodada, "A3
repara no máximo 1 dos 3". Reparou 3. Fica registrado.

E o que isso **não** autoriza a dizer:

1. **N = 3**, que é o teto da arquitetura, não uma escolha de amostra.
2. **A3 não superou A2**: o braço determinístico repara os mesmos 3. Nesta população existe
   molde para todas as classes, então o medido é um **empate** onde a trilha mecânica já
   funciona.
3. **A pergunta de generalização continua aberta, por razão estrutural**: a população
   alcançável não tem nenhuma classe ausente da biblioteca de moldes — os 15 que só o
   oráculo pega são justamente os que teriam essa propriedade.
4. A classificação "novel 3/3" do probe **não informa nada aqui**: a rodada usou o filtro que
   comparava perspectiva (`unrestricted_write`) com nome de detector (`unrestricted-write`),
   conjunto vazio, "novel" por construção. Corrigido em `1cac001`, depois da rodada.

## 5. Custo

| | |
|---|---|
| cota de nuvem | **zero** |
| original (19 regras) | 28,1 s |
| média por mutante | 29,0 s |
| varredura de 46 | ~22 min de CPU |
| disco | ~30 MB de saída do Prover por verificação (1,4 GB na varredura inteira) — isolados em `_prover/`, apagáveis com `--prune-prover-dirs` |

## 6. O que isso muda no relatório

A frase "a generalização do LLM continua não demonstrada" **permanece verdadeira**, agora
por um motivo mais preciso do que antes: não é que a LLM falhe: é que a população em que ela
pode ser cobrada hoje (3 mutantes) não contém nenhuma classe fora da biblioteca de moldes.
No que é alcançável, ela repara 3 de 3 com confirmação formal — e empata com a trilha
mecânica. O que muda é que a segunda causa da dívida
deixa de ser um limite do método e passa a ser uma escolha de implementação — existe um
oráculo que cobra o agente por 15 defeitos que o Slither não vê, de graça.

O desenho do experimento que pode falsificar a generalização está em
`docs/experimento-generalizacao-pre-registro.md`, com a predição declarada antes da rodada.

## 7. O que destravou na prática

Duas coisas, no mesmo dia e pelo mesmo motivo (a verificação deixou de custar cota):

- **OpenEdition (escher) fechado.** Pendência desde 09/11 — "correção escrita, não
  verificada (cota)". Rodada completa com `AUDIT_CERTORA_LOCAL=1`: original `Violated`,
  reparo mínimo (`finalize()` ganhou `onlyOwner`), corrigido `Verified` com as duas regras
  ainda alcançáveis, 1/1, **sem job na nuvem**. `runs/20261117_095428_OpenEdition/`.
- **GovTokenEscrow (inverse) fechado, 4 de 4, com a origem separada.** Pendência desde
  09/11 — "Certora confirma 4 achados; parou no 400 do Groq". `comparison_t1.json`:
  `{"deterministic": {"resolvidas": 2}, "llm": {"resolvidas": 2}}`, e
  `zero_address_reverts` passou de `Violated` a `Verified` com a regra ainda alcançável.
  **Primeira medição do projeto com metade mecânica e metade LLM separadas por campo**, na
  mesma rodada. `runs/20261117_100413_GovTokenEscrow/`.
- **Dois limites do Groq que eram registrados como "limite do Groq" e não eram.**
  `400 json_validate_failed` com `failed_generation` vazio é o modelo de raciocínio gastando
  o `max_tokens` pensando (repetir com 4× o espaço resolve, `8254c4b`), e o `429` de TPM diz
  na mensagem quanto esperar (esperar e repetir resolve, `cf99fbf`). Eram eles que travavam
  este contrato desde 09/11.
- **Um bug que travava toda rodada completa desde `ffa56ee`.** `preparar_spec` chamava
  `declarar_owner_envfree(spec, contract_source)` sem receber `contract_source`, então
  **qualquer** pipeline completo morria na ETAPA 3 com `NameError`. Nenhum teste chamava a
  função inteira. Corrigido em `7fca2d5`, com teste da função ponta a ponta — e o que
  revelou o bug foi justamente a primeira rodada completa depois dele, hoje.
