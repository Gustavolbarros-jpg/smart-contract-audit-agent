# Liveness: o que `assert` nunca ia ver — 18/11/2026

Snapshot novo. Não substitui `docs/resultado-oraculo-formal-20261117.md`: aquele mede as
quatro formas de safety, este mede o que foi acrescentado depois e por quê.

## 1. O diagnóstico

As quatro formas do propositor — crédito, débito, portão de identidade e os `require` do
próprio contrato — são todas de **safety**: afirmam que algo proibido não acontece. Por
construção nenhuma delas pode ver um limite apertado.

```solidity
- require(balances[msg.sender] >= amount, "insufficient");
+ require(balances[msg.sender] >  amount, "insufficient");
```

O mutante não deixa passar nada de novo. Ele **recusa** o caso exato da igualdade, que o
original aceitava. Toda regra de safety continua verdadeira — mais verdadeira, até, porque
o mutante reverte com mais frequência. Safety não reclama de uma função que recusa demais.

Na varredura de 17/11 isso apareceu como 6 BOR sobreviventes, e eu registrei a causa
("faltam os 6 BOR de aperto de limite, que precisam de *liveness*") sem ter o instrumento.

## 2. As duas formas novas

| forma | afirma | gatilho no fonte |
|---|---|---|
| `boundary` | o limite declarado, fixado na fronteira exata, continua alcançável | `require` com `>=`, `<=`, `>` ou `<` |
| `gate_liveness` | quem o portão de identidade admite continua conseguindo entrar | `require(msg.sender == <estado público address>)` |

As duas em `satisfy` do CVL:

```cvl
rule withdraw_accepts_boundary_balances_msg_sender_amount(uint256 amount) {
    env e;
    require balances(e.msg.sender) == amount;   // a fronteira de `balances[...] >= amount`

    withdraw(e, amount);                        // sem @withrevert: reversão é podada

    satisfy true;
}
```

Três decisões que são o que faz a forma funcionar:

**Fixar a fronteira é o que dá o veredito.** `satisfy` com a condição solta continua
satisfeito no mutante — basta o Prover escolher um caso folgado (`balances > amount`
estrito). Com `balances == amount` exigido, o mutante que pede `>` não tem execução
nenhuma e a regra fica Violated. A fronteira de `>=` e `<=` é a igualdade; a de `>` e `<`
é o vizinho, e o `+ 1` vai em `mathint` para não estourar o tipo e virar um `require`
impossível.

**`satisfy` em vez de `assert !lastReverted`.** A função pode reverter por overflow ou
porque a transferência externa falhou; "tem de passar" seria alarme falso em código
correto. `satisfy` precisa de *uma* execução boa, e o Prover escolhe os valores que a
tornam boa. Foi isso que dispensou modelar overflow e o `.call` externo.

**Omitir uma pré-condição não cria alarme falso.** As outras condições da função não
entram na regra: a chamada é crua, então os caminhos que revertem já são podados, e tirar
uma restrição só **amplia** o conjunto de execuções entre as quais o Prover procura a
testemunha. Por isso a forma não exige que todos os `require` da função sejam traduzíveis
— exige só que a fronteira seja.

`gate_liveness` é o dual do portão e cobre um caso que eu tinha dado por perdido:
`destroy()` tem `onlyOwner` **e** repete `require(msg.sender == owner)`. Inverter o
segundo para `!=` mata a função para todo mundo. A regra de portão
(`only_owner_calls_destroy`) continua passando — de fato ninguém indevido entra, porque
ninguém entra. Só `satisfy` vê.

`address(this).balance` passou a ser traduzível como `nativeBalances[currentContract]`,
que é o único uso de `address(this)` com nome em CVL. Isso rendeu uma regra de guard a
mais (29 em vez de 28) além da fronteira de `emergencyWithdraw`.

## 3. Resultado nos 46 mutantes

`runs/20261118_proposer_sweep_v3/`, spec congelada `specs/oracle/DeFiVault_proposed_v3.spec`
(45 regras, geradas do fonte antes de qualquer mutante existir), ~45 s por mutante, sem
cota de nuvem.

**As 45 verificam no contrato correto e nenhuma é vácua** — zero alarme falso, como as 28
anteriores.

| instrumento | pega (de 44 que compilam) |
|---|---|
| Slither com plugins | 9 (20%) |
| spec escrita à mão, 19 regras | 18 (41%) |
| spec gerada, 28 regras (só safety) | 27 (61%) |
| **spec gerada, 45 regras (+liveness)** | **32 (72%)** |
| **Slither + spec gerada de 45** | **33 (75%)** |

Por operador, com o antes e o depois onde mudou:

| operador | v2 (safety) | v3 (+liveness) | de |
|---|---|---|---|
| BOR | 5/11 | **10/11** | +5 |
| AOR | 4/7 | 4/7 | — |
| MD | 13/14 | 13/14 | — |
| FXR | 4/5 | 4/5 | — |
| UOR | 1/1 | 1/1 | — |
| EED | 0/5 | 0/5 | — |
| PKR | 0/1 | 0/1 | — |

**Nenhuma regressão**: os 27 que a versão de safety matava continuam mortos. Os 5 novos são
todos BOR e em todos os 5 **nenhuma regra de safety foi violada** — a morte é atribuível só
à forma nova:

| mutante | o que mudou | regra que matou |
|---|---|---|
| `BOR@79` | `balances[msg.sender] >= amount` → `>` | `withdraw_accepts_boundary_balances_msg_sender_amount` |
| `BOR@84` | `block.timestamp >= lastWithdraw + lockPeriod` → `>` | `withdraw_accepts_boundary_block_timestamp_...` |
| `BOR@89` | `amount <= maxWithdraw` → `<` | `withdraw_accepts_boundary_amount_maxwithdraw` |
| `BOR@166` | `amount <= address(this).balance` → `<` | `emergencyWithdraw_accepts_boundary_amount_address_this_balance` |
| `BOR@174` | `msg.sender == owner` → `!=` em `destroy` | `owner_can_call_destroy` |

24 das 32 mortes são invisíveis ao Slither. Um único mutante é exclusividade do Slither:
`FXR@174` (`msg.sender` → `tx.origin` dentro de `destroy`, que já tem `onlyOwner`).

## 4. Os 11 que ninguém pega — e dois deles não existem

Três causas que não devem ser somadas:

**2 são mutantes equivalentes**, e isso é um achado, não uma lacuna: nenhum instrumento
pode matá-los porque eles não mudam comportamento nenhum.

- `MD@173` remove `onlyOwner` de `destroy()` — e a linha seguinte é
  `require(msg.sender == owner)`. A verificação removida era redundante.
- `PKR@164` troca `address payable to` por `address to` em `emergencyWithdraw` — e o corpo
  usa `to.call{value:}`, que existe em `address` também. Só `.transfer`/`.send` exigiriam
  `payable`.

Estavam inflando o denominador das medições anteriores. O denominador honesto de defeitos
reais é **42**, e aí o par Slither + spec gerada pega **33 de 42 (79%)**.

**5 são EED** (remoção de `emit`). CVL não observa evento: é inexpressável, não é lacuna de
forma. Precisaria de outro instrumento.

**4 têm causa nomeada e endereço:**

| mutante | causa |
|---|---|
| `AOR@115` `rewards[msg.sender] += reward` → `-=` | `reward` é variável local |
| `AOR@116` `totalRewards -= reward` → `+=` | idem |
| `BOR@113` `totalRewards >= reward` → `>` | idem |
| `AOR@188` `totalDeposits += msg.value` → `-=` | está em `receive()`, que nenhuma forma alcança |

Os três primeiros têm a **mesma** causa raiz e um caminho concreto: `reward` vem de
`calculateReward(msg.sender)`, que é `public view` do próprio contrato — ou seja, *é*
dizível em CVL. Inlinear variável local atribuída a partir de função `view` do próprio
contrato desbloqueia os três de uma vez. `receive()` precisa de regra paramétrica
(`method f; calldataarg args;`), que é outra forma.

## 5. O corpus real, e uma correção

No corpus de 321 arquivos reais (`smart-audt/contracts/real/*/src`), com as duas formas
novas: **60 arquivos com propriedade, 344 propriedades** — contra 234 só com safety.

| forma | propriedades |
|---|---|
| guard | 123 |
| identity_gate | 73 |
| gate_liveness | 73 |
| boundary | 37 |
| debit | 16 |
| credit | 13 |
| debit_total | 5 |
| credit_total | 4 |

**Correção de um número anterior.** O relatório de 17/11 e o `CLAUDE.md` diziam "59 de 320
arquivos, 213 propriedades" com `identity_gate` 52. Medindo de novo contra o código de
`HEAD`, por dois caminhos independentes, dá **60 arquivos, 234 propriedades** e
`identity_gate` 73. Não há cópia antiga do módulo no disco que explique a diferença por
import velho; foi erro de medição. O número correto para a versão só-safety é 234.

Nenhum arquivo do corpus ganha propriedade *só* pelas formas novas — elas aumentam a
densidade dentro de um contrato que já tinha, não a cobertura entre contratos.

## 6. Tamanho de contrato: o resultado é o inverso do esperado

| | arquivos | com propriedade |
|---|---|---|
| ≥ 300 linhas | 46 | **16 (34%)** |
| < 300 linhas | 275 | 44 (16%) |

Contrato grande vai melhor, não pior. `inverse/src/Market.sol` (622 linhas, mercado de
empréstimo real) rende **44 propriedades**. O que é ralo é a cobertura *dentro* do contrato
grande: `BranchBridgeAgent.sol`, 1421 linhas, rende 4.

E os grandes que rendem **zero** têm uma causa única e medida:

| arquivo | linhas | `require(` | `revert CustomError()` |
|---|---|---|---|
| `caviar/PrivatePool.sol` | 795 | **0** | 15 |
| `astaria/LienToken.sol` | 920 | 2 | 28 |
| `astaria/AstariaRouter.sol` | 804 | 4 | 21 |
| `maia/UlyssesPool.sol` | 1223 | 2 | 14 |
| `inverse/Market.sol` | 622 | **28** | 0 |

O propositor lê `require(...)`. Contrato grande moderno declara invariante com
`if (cond) revert CustomError();`. No corpus são **632 `require(` contra 358
`revert CustomError()`**: mais de um terço dos invariantes declarados está numa forma que
não é lida. Além disso, **269 das 1.093** funções externas não-view (24%) são descartadas
porque um parâmetro é struct ou enum.

São os dois trabalhos seguintes, nessa ordem de alavanca:

1. **`if (cond) revert X()` como guard** — 358 invariantes, e provavelmente os 4 contratos
   grandes que hoje dão zero. É o mesmo maquinário de tradução: muda de onde vem a
   condição, e ela vem negada.
2. **parâmetro struct/enum** — 24% das funções externas.

## 7. Custo

Zero cota de nuvem. 45 regras levam ~45 s por contrato no verificador local, contra ~34 s
das 28 — `satisfy` não é mais caro por regra, são mais regras. A varredura de 46 mutantes
levou ~35 min de uma máquina, sem job nenhum enviado.
