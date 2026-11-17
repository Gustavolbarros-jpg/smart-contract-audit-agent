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

## 4.5 Até onde o catálogo pode crescer (e onde ele não alcança)

Pergunta direta: já que o oráculo expõe 15 defeitos que o Slither não reporta, dá para
**crescer o catálogo** até cobri-los? A resposta sai da classe esperada de cada um dos 18
mutantes que a spec mata:

| classe esperada | mortos | o Slither reporta? | existe molde? |
|---|---|---|---|
| `integer_overflow` (AOR) | 6 | não | **não pode existir** |
| `comparison_logic` (BOR/UOR) | 5 | não | **não pode existir** |
| `unrestricted_write` (MD) | 4 | 2 de 4 | sim (`restore_access_modifier`) |
| `tx-origin` (FXR) | 1 | sim | sim |
| `missing-zero-check` (FXR) | 1 | sim, como `validation` | sim |
| `arbitrary-send-eth` (FXR) | 1 | não | não |

**Os 11 primeiros não são uma lacuna do catálogo — são uma lacuna da análise estática.**
`integer_overflow` e `comparison_logic` nem são nomes de detector do Slither: são
perspectivas do CodeXplain. O mutante AOR troca `balances[msg.sender] -= amount` por
`+=`; o BOR troca `>=` por `>`. As duas versões são Solidity perfeitamente válido, com a
mesma forma sintática e o mesmo fluxo de dados. Não há padrão a casar, então não há
entrada de catálogo a escrever: só uma **especificação** separa as duas, que é exatamente
o que o oráculo traz.

Os outros 4 são lacunas reais e nomeáveis:

- **2× `unrestricted_write` em `MD@78`** — removem `notPaused` e `onlyWhitelisted` de
  `withdraw`. O detector próprio exige um gate de **identidade contra `msg.sender`** para
  disparar; `notPaused` testa estado e `onlyWhitelisted` testa um mapping. Ele não dispara
  por desenho, e alargar o desenho para "função externa que escreve estado sem modificador"
  faria alarme em código correto. Detectar a *remoção* de um guard exige um ponto de
  referência (a lista de modificadores de antes) que a análise de um arquivo só não tem.
- **1× `arbitrary-send-eth` em `FXR@167`** — classe que está no catálogo, mas sem molde.
  É a candidata mais concreta a molde novo.

Resumo: das 18 mortes, **4 estão ao alcance do catálogo** (e as 4 já foram reparadas pelo
braço A2), 1 é molde faltante, 2 são limite de desenho do detector e **11 são
indetectáveis estaticamente por natureza**. Crescer o catálogo continua valendo, mas não
é o caminho para a maior parte do espaço de defeito — o caminho é a fase 2, diagnosticar a
partir do contraexemplo do oráculo.

## 4.6 E as vulnerabilidades complexas?

A §4.5 mostra que 11 das 18 mortes estão fora do alcance de qualquer catálogo. A pergunta
seguinte é a que interessa para o relatório: **onde o pipeline está contra defeito
complexo de verdade** — inflação do primeiro depositante, manipulação de preço spot,
oráculo desatualizado, reentrância read-only, token com taxa na transferência?

### Onde estávamos: o pipeline fecha o contrato sem tocar na vulnerabilidade

O corpus tem 57 contratos do `defivulnlabs`, cada um escrito para demonstrar uma classe
dessas. Somando o que o Slither reporta em 15 deles:

```
19 naming-convention   14 immutable-states   10 constable-states
 9 pragma               9 solc-version        6 unchecked-transfer
```

Nenhum desses nomes é a vulnerabilidade do arquivo. Das 15 classes, o Slither nomeia **2**
(`controlled-delegatecall`, `divide-before-multiply`); as outras 13 passam em branco. E o
efeito é pior do que não achar:

| rodada | o pipeline declarou | o que de fato reparou | a vulnerabilidade do arquivo |
|---|---|---|---|
| `20261105_135945_ReadOnlyReentrancy` | **2/2 resolvidas** | 2× `unchecked-transfer` | reentrância read-only, intacta |
| `20261105_142355_phantom-permit` | **1/1 resolvida** | 1× `missing-zero-check` | permit fantasma, intacto |

Um relatório de sucesso num contrato cuja falha continua lá. Isso não é um bug do
pipeline — é o teto de um instrumento que só enxerga o que o detector nomeia.

### Onde estamos: o oráculo separa os dois, o Slither não

Demonstração em `tests/fixtures/certora/first_deposit_inflation/`, logs em
`runs/20261117_oracle_first_deposit/`. `Pool.sol` é o `SimplePool` do corpus;
`PoolFixed.sol` difere por **um argumento** — `tokenToShares` passa a arredondar para
cima, flag que a própria função já aceita.

A propriedade: *um depósito de valor não nulo tem de deixar o depositante com mais shares
do que antes.*

| | oráculo | Slither |
|---|---|---|
| `Pool.sol` | **Violated**, com contraexemplo | 10 achados |
| `PoolFixed.sol` | **Verified**, não vácuo | 10 achados |

O Slither devolve **os mesmos dez achados para os dois arquivos**, com as mesmas
contagens. Não distingue o cofre vulnerável do reparado, e nenhum dos dez é o defeito.
Não há o que catalogar: as duas versões são Solidity válido com a mesma forma sintática e
o mesmo fluxo de dados.

O token não é ligado, é sumarizado: `balanceOf` é `NONDET` — o Prover escolhe qualquer
saldo de pool, que é exatamente o efeito da doação do atacante — e `transfer`/
`transferFrom` são `ALWAYS(true)`, para que um token que falha não mascare a propriedade.

**Ressalva, porque ela importa:** o que ficou provado é a metade de arredondamento do
first-deposit — a que deixa alguém entregar tokens e não receber share nenhuma. A doação
continua mexendo no preço; arredondar para cima só impede o truncamento a zero. A
mitigação do Uniswap V2 (queimar liquidez mínima no primeiro depósito) é a outra metade e
não está modelada.

### O que isso diz sobre o caminho

O instrumento alcança a classe complexa — a prova está acima, de graça e em segundos. O
que **não** existe ainda é o pipeline chegar nela sozinho: a spec foi escrita à mão, e a
ETAPA 2 só propõe propriedade para as 6 classes `formalizable` do catálogo, todas
simples (`missing-zero-check`, `tx-origin`, `suicidal`, `arbitrary-send-eth`, over/under
flow). Enquanto a formalização for indexada pelo achado do Slither, o alcance do pipeline
é o alcance do Slither, por melhor que o oráculo seja.

## 4.7 A spec escrita pela máquina contra a spec escrita à mão

A §4.6 termina dizendo que, enquanto a formalização for indexada pelo achado do Slither, o
alcance do pipeline é o alcance do Slither. `agent/core/property_proposer.py` é a tentativa
de sair disso: lê o fonte e reconhece **formas de contabilidade** — função que credita um
mapping por endereço e um total, função que debita os dois, função guardada por modificador
que compara algo a `msg.sender`. Cada forma implica uma propriedade que vale em qualquer
implementação correta dela, e é por isso que a propriedade pode ser escrita **sem saber o
que está errado**. Sem LLM, sem Slither, sem rede.

### Primeiro, o teste que podia afundar a ideia

14 regras geradas do `DeFiVault_FIXED.sol`, rodadas contra o próprio contrato:
**14/14 Verified, nenhuma vácua**. Zero alarme falso num contrato já tido como bom. Uma
propriedade que falha em código correto custa mais que uma propriedade que ninguém
escreveu, e isso aqui não acontece.

### A comparação, nos mesmos 46 mutantes

| | regras | mortes | das quais o Slither não vê |
|---|---|---|---|
| spec escrita à mão (eu, lendo o contrato) | 19 | **18** | 15 |
| spec gerada do fonte (0,2 s, nenhum humano) | 14 | **14** | **6** |
| união das duas | — | 23 | — |

As duas são **complementares, não aninhadas**. A gerada mata 5 que a minha não pega:

```
MD@60   onlyOwner removido de removeFromWhitelist
MD@132  onlyOwner removido de unpause
MD@144  onlyOwner removido de setLockPeriod
MD@150  onlyOwner removido de transferOwnership
MD@164  onlyOwner removido de emergencyWithdraw
```

Todas funções para as quais eu simplesmente **esqueci de escrever regra**. O gerador é
exaustivo onde a pessoa é seletiva: emitiu `only_owner_calls_X` para as 10 funções com
portão, não para as 4 que me pareceram importantes.

E alcança sozinho a classe semântica:

```
AOR@68, AOR@69, AOR@91, AOR@92   += virou -= e vice-versa
BOR@39, BOR@156                  == virou !=
```

Seis defeitos que **nenhum detector nomeia**, pegos por uma spec que ninguém escreveu.

### O que ela não pega, e a ressalva que o número esconde

As 9 que só a escrita à mão pega são regras de domínio, não formas de contabilidade: o
teto de saque, o período de lock, a whitelist, o pause, a conservação do pool de
recompensa, o endereço zero, o destinatário do `emergencyWithdraw`. O propositor tem três
formas; nada nele sabe que existe um teto.

E a ressalva honesta: **somada ao Slither, a spec gerada não acrescenta nada ao total.**

| | cobertura em 44 mutantes |
|---|---|
| Slither sozinho | 9 |
| Slither + spec gerada | 15 |
| Slither + spec à mão | 24 |
| Slither + as duas | **24** |

Os 5 que a gerada acrescenta sobre a minha spec são exatamente modificadores removidos, que
o detector `unrestricted-write` do projeto já sinaliza. Então o ganho dela **sobre a
combinação existente** é zero, hoje.

O resultado não é "a máquina escreve spec melhor que a pessoa". É: **78% das mortes da
spec escrita à mão, de graça, em qualquer contrato, sem ninguém ler o código** — e 6 delas
na classe que a análise estática não alcança por natureza. A spec à mão custou uma tarde de
leitura e só existe para um contrato; esta roda em 320 arquivos do corpus e produz
propriedade em 32 deles (90 propriedades: 52 portão de identidade, 29 de contabilidade, 9
de totais).

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
