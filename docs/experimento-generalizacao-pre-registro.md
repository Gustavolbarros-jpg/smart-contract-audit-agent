# Pré-registro: o experimento que pode falsificar a generalização

**Data:** 2026-11-17
**Status:** pré-registro — escrito **antes** de rodar qualquer braço.
**Commits congelados:**
`2c57bd0` (última mudança na biblioteca de moldes determinísticos — recongelada ao
acrescentar `incorrect-exp`, antes de qualquer braço rodar),
`e9eac64` (spec de oráculo `specs/oracle/DeFiVault.spec`),
`24a353e` (chaves de braço: `AUDIT_NO_DETERMINISTIC_PATCH`, `AUDIT_FIX_LIBRARY`).

---

## 0. Por que pré-registrar

As rodadas anteriores reportaram números como "1 de 7 novel" que, conferidos, eram
**artefato do instrumento**: "novel" significava apenas "a biblioteca de moldes não tinha
esse caso", não "o modelo generalizou". Pré-registrar fixa a pergunta, o instrumento, o N e
o limiar **antes** dos dados, para que a rodada possa dar errado. Um experimento que não
pode dar errado não mede nada.

## 1. A pergunta

> A trilha LLM repara instâncias de defeito cuja **classe** não está na biblioteca de
> moldes determinísticos?

Forma falsificável: no braço "só LLM", sobre a população pré-registrada de mutantes, o
número de reparos **confirmados pelo oráculo formal** é maior que zero — e quanto.

## 2. O que mudou e tornou o experimento possível

| Peça | O que resolve | Onde |
|---|---|---|
| Oráculo local do Certora | mede sem cota de nuvem; pega o que o Slither não vê | `tools/certora_cli.verify_locally` |
| Guarda de vacuidade | reparo degenerado ("reverte sempre") não passa como sucesso | `LocalVerdict.vacuous_rules` |
| `repair_origin` | separa "o patch mecânico resolveu" de "a LLM resolveu" | `core/repair_origin.py` |
| `AUDIT_NO_DETERMINISTIC_PATCH` | exercita a LLM no problema inteiro, não no resíduo | `core/deterministic_patch.py` |
| `AUDIT_FIX_LIBRARY` | biblioteca congelada por braço | `core/fix_library.py` |
| `AUDIT_CERTORA_LOCAL` | pipeline completo sem cota de Certora | `tools/certora_cli.run_certora` |

## 3. População

Base: `smart-audt/contracts/DeFiVault_FIXED.sol`, `SOLC_VERSION=0.8.21`.
Mutantes: `mutate(source, operators=OPERATORS, limit_per_operator=1000)` → **46**
(AOR 7, BOR 11, UOR 1, EED 5, MD 14, PKR 3, FXR 5).

Dois estratos, medidos antes de qualquer reparo:

- **E1 — mutantes que o oráculo mata.** Só para esses existe critério objetivo de
  "reparado". Medido em `runs/20261117_oracle_defivault/` (varredura desta data).
- **E2 — mutantes que o Slither enxerga.** Medido por `agent/mutant_detection.py`
  (9 de 46 na medição de 12/11; remedido junto com a varredura).

A **população mensurável do experimento é E1**. A interseção E1∩E2 e a diferença E1\E2 são
reportadas separadamente: é a diferença que diz quanto do espaço de defeito o pipeline
nunca é cobrado hoje.

### 3.1 Medido em 17/11 (antes de qualquer braço de reparo)

| estrato | tamanho |
|---|---|
| mutantes que compilam | 44 (2 PKR não compilam) |
| **E1** — o oráculo mata | **18** |
| **E2** — o Slither vê | **9** |
| **E1 ∩ E2** | **3** — `MD@136`, `MD@140`, `FXR@39` |
| E1 \ E2 (só o oráculo pega) | 15 |

**Duas bibliotecas diferentes, e a distinção importa.**

- A **biblioteca de moldes** (patch determinístico, 11 classes) cobre `unrestricted-write`
  e `tx-origin` — as classes dos 3 mutantes de E1∩E2.
- A **biblioteca de exemplos** (`runs/fix_library.json`, few-shot da LLM) tem 36 padrões de
  **3 classes só**: `missing-zero-check` (28), `arbitrary-send-eth` (7),
  `erc2771-multicall-context` (1). Snapshot congelado em
  `runs/20261117_experiment_library/fix_library_frozen_2c57bd0.json`.

A recuperação é por `vuln_type` exato, então os 3 mutantes de E1∩E2 **não recebem exemplo
nenhum**: no braço A3 a LLM repara uma classe sobre a qual não viu exemplo, que é a
definição de generalização usada por `core/generalization.py`. O que esse braço **não** mede
é generalização para classe ausente do *molde determinístico* — isso exigiria a fase 2
(§9.3).

## 4. Critério de sucesso de um reparo

Um reparo conta como bem-sucedido **se e somente se**, no contrato reparado:

1. as 19 regras de `specs/oracle/DeFiVault.spec` dão `Verified`;
2. **nenhuma** regra é vácua (`LocalVerdict.vacuous_rules` vazio) — isso barra o "reparo"
   que faz a função reverter sempre e satisfaz a spec sem consertar nada;
3. `patch_guard` não registra erro (patch mínimo: assinatura pública preservada, nenhuma
   variável de estado removida);
4. o veredito do oráculo é conclusivo (`verified`/`violated`, não `error`/`timeout`).

A spec é **congelada**: nenhuma regra pode ser adicionada, apertada ou afrouxada depois de
se conhecer o resultado de um mutante.

## 5. Braços

| Braço | O que roda | Para que serve |
|---|---|---|
| **A0** controle negativo | original não mutado pelo oráculo | o instrumento não mata contrato sadio |
| **A1** controle de potência | mutante **sem reparo** pelo oráculo | define E1; sem isso "reparado" não tem significado |
| **A2** só determinístico | `--static-only --with-plugins` + oráculo no resultado | a baseline defensável de hoje; custo zero |
| **A3** só LLM | `AUDIT_NO_DETERMINISTIC_PATCH=1 AUDIT_CERTORA_LOCAL=1` + oráculo | **o braço que responde à pergunta** |
| **A4** pipeline completo | configuração normal + oráculo | o número que vai ao relatório |

Cada braço roda com `AUDIT_FIX_LIBRARY` apontando para a **sua própria cópia** da biblioteca
congelada em `f2ca0a8`, para que um braço não ensine o seguinte.

## 6. Predição pré-registrada

Declarada como **aposta**, não derivada de medição anterior (a derivação do "1/7" está
desacreditada):

- **A3 repara no máximo 1 dos 3 mutantes de E1∩E2** (a população que o pipeline atual
  consegue alcançar). Declarado em 17/11, antes de rodar o braço.
- **A3 repara no máximo 30% de E1** quando a fase 2 tornar E1 inteiro alcançável.
- Nas classes **ausentes** da biblioteca de moldes (as 11 presentes são
  `missing-zero-check`, `tx-origin`, `suicidal`, `unrestricted-write`, `unchecked-send`,
  `unchecked-lowlevel`, `unchecked-transfer`, `arbitrary-send-erc20`,
  `divide-before-multiply`, `encode-packed-collision`, `incorrect-exp`), prevejo **no
  máximo 1** reparo bem-sucedido.

Acrescentar um molde depois do pré-registro **recongela** a biblioteca e tem de ser
registrado aqui, com o commit. Depois de o primeiro braço rodar, a biblioteca não muda
mais até a rodada terminar.

## 7. Como a rodada pode dar errado

| Resultado | Leitura |
|---|---|
| A3 = 0 e A2 > 0 | generalização **não demonstrada** neste corpus; a contribuição defensável continua sendo a baseline determinística + guardrails |
| 0 < A3 ≤ 30% de E1 | generalização existe, é pequena, e a predição acertou |
| A3 > 30% de E1 | **a predição estava errada** e há evidência de generalização — com a ressalva da especificidade da spec (§9.1) |
| A1 mata pouco de 46 | o instrumento é fraco; o resultado a reportar primeiro é a potência do oráculo, não o mérito do agente |

## 8. Orçamento

- **Certora:** zero cota. O oráculo é local (`--compilation_steps_only`), 27 s no original
  do DeFiVault e ~70 s num mutante que viola.
- **Groq:** 200k tokens/dia/modelo em `openai/gpt-oss-120b`. **Trocar de modelo no meio
  quebra a comparabilidade** — se a cota estourar, a rodada espera o reset.
- **Tempo:** a varredura de 46 mutantes com a spec de 19 regras leva ~1 h de CPU.

## 9. Ameaças à validade (declaradas antes)

1. **Especificidade da spec.** O oráculo só mata o que as 19 regras falam. "Sobreviveu"
   não é "inofensivo" — é "fora do alcance desta spec". Reportar sempre nesses termos.
2. **Um contrato só.** DeFiVault tem validade externa limitada. Estender exige uma spec
   congelada por contrato (SimpleBank é o próximo candidato).
3. **O pipeline só repara o que o Slither acha.** Para as classes de detectabilidade zero,
   o pipeline não produz achado nenhum, logo A3 nem chega ao estágio de reparo. Medido:
   isso limita A3 a **3 mutantes** de 18 em E1 — os 15 restantes, que só o oráculo pega,
   são inalcançáveis pela arquitetura atual, por mais capaz que a LLM seja. A fase 2 —
   diagnóstico guiado pelo **contraexemplo do oráculo** em vez do achado do Slither — é o
   que removeria o limite, e está fora deste pré-registro. Com N=3, qualquer resultado de
   A3 é indício, não demonstração: é o teto que a arquitetura permite hoje, e dizer isso é
   parte do resultado.
4. **Não determinismo da LLM.** Uma amostra por mutante: a estimativa é ruidosa. Repetir
   k=3 custa 3× a cota e fica para depois de A3 existir.
5. **Mutante equivalente.** Um mutante pode ser semanticamente equivalente ao original; o
   oráculo então não o mata e ele **sai** de E1, em vez de contar como erro do agente.

## 10. Pré-condições (checklist antes de rodar)

- [x] `repair_origin` escrito pelo caminho de código (`a8273cc`)
- [x] `AUDIT_FIX_LIBRARY` (`d28b505`)
- [x] `AUDIT_NO_DETERMINISTIC_PATCH` (`24a353e`)
- [x] oráculo + guarda de vacuidade (`e9eac64`, `a8273cc`)
- [x] A0 e A1 medidos (`runs/20261117_oracle_defivault/`)
- [x] A2 rodando com `mutant_oracle.py --repair static --only-from`
- [x] cópia congelada de `runs/fix_library.json`
      (`runs/20261117_experiment_library/fix_library_frozen_2c57bd0.json`)
- [x] seleção da população no probe (`--only-labels`)
- [ ] A3 rodado nos 3 mutantes de E1∩E2
- [ ] fase 2: diagnóstico a partir do contraexemplo do oráculo
