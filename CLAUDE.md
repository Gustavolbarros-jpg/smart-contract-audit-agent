# CLAUDE.md

Pipeline de auditoria de contratos Solidity: **Slither → catálogo → correção
(determinística ou LLM) → Certora → revalidação**. Python 3 puro, sem framework.

**Fale português com o usuário.** Commits e código em inglês.

---

## 1. Comece por aqui

| Objetivo | Comando |
|---|---|
| Pipeline completo (gasta cota) | `SOLC_VERSION=<ver> AUDIT_WITH_PLUGINS=1 AUDIT_LLM_MODEL=openai/gpt-oss-120b python3 agent/main.py --contract /caminho/absoluto/X.sol` |
| Sem gastar nada (sem LLM, sem Certora) | `python3 agent/main.py --contract /caminho/absoluto/X.sol --static-only --with-plugins` |
| Pipeline completo **sem cota de Certora** | `AUDIT_CERTORA_LOCAL=1 SOLC_VERSION=<ver> AUDIT_WITH_PLUGINS=1 AUDIT_LLM_MODEL=openai/gpt-oss-120b python3 agent/main.py --contract /caminho/absoluto/X.sol` |
| Testes | `python3 -m pytest tests/ -q` → **420 passed, 1 skipped, ~10 s** |
| Listar contratos | `python3 agent/main.py --list-contracts --contract-group benchmark` |
| Medir generalização | `SOLC_VERSION=0.8.21 python3 agent/generalization_probe.py <X>_FIXED.sol --detectable-only` |
| Ver o que o Slither enxerga de um mutante | `SOLC_VERSION=0.8.21 python3 agent/mutant_detection.py <X>_FIXED.sol` |
| Oráculo formal grátis sobre os mutantes | `SOLC_VERSION=0.8.21 python3 agent/mutant_oracle.py /caminho/absoluto/X_FIXED.sol --spec specs/oracle/DeFiVault.spec --contract-name DeFiVault` |
| Braço determinístico cobrado pelo oráculo | o comando acima + `--repair static --only-from runs/<varredura>/report.json` |
| Braço só-LLM (gasta Groq, não gasta Certora) | `AUDIT_NO_DETERMINISTIC_PATCH=1 AUDIT_CERTORA_LOCAL=1 AUDIT_WITH_PLUGINS=1 AUDIT_LLM_MODEL=openai/gpt-oss-120b AUDIT_FIX_LIBRARY=<cópia> SOLC_VERSION=0.8.21 python3 agent/generalization_probe.py <X>_FIXED.sol --only-labels "MD@136,FXR@39" --oracle-spec specs/oracle/DeFiVault.spec` |

**Sempre passe caminho absoluto do contrato.** Caminho relativo faz o Slither
falhar em projetos com imports (Foundry/remappings).

**Use sempre `src/`, nunca `out/`.** Os projetos Foundry em
`smart-audt/contracts/real/` tem 47 arquivos `.sol` duplicados em diretorios
`out/` (saida de build). `OpenEdition.sol`, por exemplo, existe nos dois lugares.
Corrigir a copia em `out/` e trabalho perdido: ela e regerada na proxima
compilacao, e o Slither nem sempre reclama.

Antes de rodar qualquer coisa que gaste cota, prefira `--static-only`: ele
exercita Slither + catálogo + patch determinístico sem tocar em LLM nem Certora.

---

## 2. Variáveis de ambiente (a maior fonte de tempo perdido)

| Variável | Valor | Por quê |
|---|---|---|
| `SOLC_VERSION` | por contrato | O preflight **ignora o pin do Foundry**. Sem isso, trava em "pragma incompatível". Vence o pin do projeto (`agent/tools/slither_cli.py:64`). |
| `AUDIT_LLM_MODEL` | `openai/gpt-oss-120b` | O default do código é `llama-3.3-70b-versatile`, que **dá 404 no Groq hoje** (`agent/llm/client.py:14`). |
| `AUDIT_WITH_PLUGINS` | `1` | Liga o detector próprio `unrestricted-write` no pipeline completo. Sem isso ele só roda em `--static-only --with-plugins`. |
| `AUDIT_CERTORA_TIMEOUT` | default `600` (10 min) | Suba para contratos grandes. |
| `AUDIT_CERTORA_LOCAL` | `1` para local | Acrescenta `--compilation_steps_only`: o `emv.jar` roda aqui, imprime `Verified:`/`Violated:` de verdade e **não envia job nenhum**. Use para rodar contrato novo sem gastar cota de nuvem; o número final do relatório continua vindo da nuvem. |
| `AUDIT_ORACLE_TIMEOUT` | default `300` | Segundos por verificação local (`verify_locally`, `mutant_oracle.py`). |
| `AUDIT_NO_DETERMINISTIC_PATCH` | `1` para desligar | Desliga a trilha mecânica de reparo **e** as dicas de diagnóstico determinístico. É o braço "só LLM" do experimento de generalização; sem isso a LLM só vê resíduo. |
| `AUDIT_FIX_LIBRARY` | caminho | Aponta a biblioteca de moldes para outro arquivo. Um braço do experimento usa a própria cópia, senão `save_pattern` contamina o braço seguinte. |
| `GROQ_API_KEY` | vem do `.env` | Nunca imprima o valor. |
| `CERTORAKEY` | já está no shell | Se faltar, o Certora falha no envio, não na spec. |

`solc` instalados: 0.8.13 (global), 0.8.17, 0.8.18, 0.8.19, 0.8.20, 0.8.21, 0.8.26.
Já conhecidos: DeFiVault → `0.8.21`; OpenEdition (escher) → `0.8.17`; Inverse
(Market, escrows) → deixe sem definir.

---

## 3. Armadilhas que já custaram horas

**CVL / Certora**
- CVL **não tem `assume`** — use `require`. Campos de `env` **não podem ser
  atribuídos** (`e.msg.sender = x;` é erro). `agent/tools/spec_validator.py` já
  conserta os dois casos automaticamente.
- **Nada de tipos de interface** em assinatura CVL (`IERC20` etc.) → vire `address`.
- Chamar `owner()` sem `env` exige declará-la `envfree` no bloco `methods`.
  `declarar_owner_envfree()` faz isso quando o contrato herda de Ownable.
- **Exit code 100 do Prover é normal** quando há violação. Não trate como falha.
- A regra `-rule_not_vacuous` aparecendo **Violated é o sanity check** — ignore.
- O Prover **recusa arquivos fora do diretório do repo**. Mutantes e temporários
  vão ao lado do original, nunca em `/tmp`.
- **Nunca abra o relatório HTML no navegador do usuário.** `agent/tools/certora_cli.py`
  já remove `DISPLAY`/`WAYLAND_DISPLAY` do ambiente de propósito. Leia o JSON/log.

**LLM (Groq)**
- `413` = prompt grande demais. `429` vem em dois sabores: **TPM** (8000 tokens por
  minuto no tier on_demand — um prompt de diagnóstico já usa metade) e **TPD** (cota
  diária). O cliente agora **espera o tempo que a própria mensagem informa e repete**
  (até 2 vezes, espera máxima de 60 s), então um TPM não derruba mais a rodada.
- `400 json_validate_failed` com `failed_generation` **vazio** não é prompt inválido: é
  modelo de raciocínio gastando o `max_tokens` pensando e não sobrando nada para a
  resposta. O cliente repete com 4× o orçamento e `reasoning_effort: low`. Foi isso que
  travava o GovTokenEscrow desde 09/11.
- Se a **cota diária** acabar: ou espere o reset, ou troque para um modelo com cota
  separada — **avisando que o resultado deixa de ser comparável** com as rodadas
  anteriores.
- Patch determinístico é calculado **antes** da diagnose do LLM, justamente para
  que uma falha de LLM não bloqueie o que já era mecânico.

---

## 4. Arquitetura em uma tela

1. Preflight de toolchain → `agent/tools/slither_cli.py`
2. Slither → `agent/core/slither_normalizer.py` (classes estáveis + fallbacks)
3. Catálogo decide a estratégia → `agent/core/vulnerability_catalog.py`
   (106 entradas; trilhas `formalizable`, `static_confirmed`, triagem)
4. Candidatos formais → `formal_candidate.py` / `formal_plan.py`
5. Spec CVL: determinística (`deterministic_spec.py`) ou LLM, depois
   **sempre** por `tools/spec_validator.py`
6. Certora → `tools/certora_cli.py` (`run_certora` manda para a nuvem;
   `verify_locally` roda só o verificador local, sem cota)
7. Correção: `core/deterministic_patch.py` primeiro, LLM só no resto
8. `core/patch_guard.py` barra patch não-mínimo (assinatura pública alterada,
   string literal mexida, variável de estado removida)
9. Revalidação: roda Slither **e os plugins** de novo no código corrigido
10. Artefatos em `runs/<timestamp>_<Contrato>/` — **nunca apague**

Detector próprio: `agent/slither_plugins/unrestricted_write.py`,
reparado por `restore_access_modifier` (só quando há **um** modificador de identidade).

---

## 5. Estado atual (2026-11-17)

Branch `analysis/catalog-coverage`, **22 commits locais sem push**, PR #2 contra `develop`.

**O que mudou em 17/11 — o oráculo formal local.** `certoraRun --compilation_steps_only`
para antes de *enviar* o job, não antes de *verificar*: o `emv.jar` roda aqui e imprime
vereditos reais, sem cota. Está em `tools/certora_cli.verify_locally`, e
`AUDIT_CERTORA_LOCAL=1` faz o pipeline inteiro rodar assim.

Medição com `specs/oracle/DeFiVault.spec` (19 regras, todas verificadas e nenhuma vácua no
original) sobre os 46 mutantes — `runs/20261117_oracle_defivault/`, detalhe em
`docs/resultado-oraculo-formal-20261117.md`:

| Slither \ oráculo | mata | sobrevive | erro |
|---|---|---|---|
| **detecta** (9) | 3 | 6 | 0 |
| **não vê** (35) | **15** | 20 | 0 |
| não compila (2) | 0 | 0 | 2 |

Dos 44 que compilam: Slither sozinho pega 9 (20%), Slither + oráculo pegam 24 (54%). Os
instrumentos são **complementares**: 6 mutantes o Slither vê e a spec não cobre (lacuna
registrada, não corrigida depois do fato).

Experimento de generalização **pré-registrado** em
`docs/experimento-generalizacao-pre-registro.md` (pergunta, população, critério de sucesso,
5 braços, predição declarada). Peças de controle já no código: `repair_origin.json` escrito
pelo caminho de código, `AUDIT_NO_DETERMINISTIC_PATCH` (braço só-LLM),
`AUDIT_FIX_LIBRARY` (biblioteca congelada por braço), guarda de vacuidade
(`LocalVerdict.vacuous_rules`) e `generalization_probe.py --oracle-spec`.

Lote de contratos de produção rodado em 09/11:

| Contrato | Situação |
|---|---|
| SimpleERC20Escrow (inverse) | **Resolvido 2/2**, aprovado pelo Certora na tentativa 2 |
| Initializable (escher) | Sem achado real — eram 2 falsos positivos, já corrigidos no normalizador |
| GovTokenEscrow (inverse) | **Fechado em 17/11**: 4/4, origem separada (2 determinísticos + 2 LLM), `zero_address_reverts` `Violated`→`Verified` e não vácuo, sem cota (`runs/20261117_100413_GovTokenEscrow/`) |
| OpenEdition (escher) | **Fechado em 17/11**: pipeline completo com `AUDIT_CERTORA_LOCAL=1`, original `Violated` → corrigido `Verified` e não vácuo, 1/1, sem cota (`runs/20261117_095428_OpenEdition/`) |
| TalosBaseStrategy (maia) | LLM removeu funções públicas → barrado pelo patch guard |
| GovernorBravoDelegateMaia (maia) | Spec já compila (bug de struct corrigido em `16b251c`); o que sobra é *stack too deep* |

Pendências conhecidas:
- Corpus recontado em 16/11: **294** arquivos reais sob `*/src` (323 − 22 artefatos
  `*_AGENT_FIXED.sol` − 7 fora de escopo). Lote de 238: 185 ok, 28 import não resolvido,
  19 *stack too deep*, 5 timeout, 1 crash do Slither. Substitui o "38 falhas" antigo.
- Os 22 `*_AGENT_FIXED.sol` dentro de `src/` de produção seguem lá: decidir entre apagar,
  limpar no fim da rodada ou excluir da enumeração do corpus.
- A generalização real do LLM **ainda não foi demonstrada** — e agora existe o instrumento
  para demonstrar ou refutar.
- `logs_antigos/` (1,4 GB, 156 entradas) ainda sem destino decidido.
- Uma varredura do oráculo deixa ~1,4 GB em `runs/<rodada>/_prover/`
  (`--prune-prover-dirs` apaga; nada é apagado sem pedir).

---

## 6. Regras de trabalho

- **Não dê `git push` sem pedir.** O usuário aprova cada envio.
- **Não apague** `runs/`, nem arquivos em geral, sem permissão explícita.
- Não sobrescreva relatórios históricos em `docs/` — crie um snapshot novo.
- Reentrância **não é foco** agora.
- Use os contratos Solidity 0.8 que já estão no repo; nada de exemplos 0.4/0.7.
- O objetivo é um pipeline agêntico com guardrails determinísticos, **não** uma
  lista de correções manuais chumbadas para um contrato específico.

---

## 7. Onde olhar

O projeto sao **171 arquivos rastreados pelo git**. Tudo que nao esta rastreado
(`runs/`, `logs_antigos/`, `agent_outputs/`, qualquer `out/` ou `emv-*`) e
artefato, nao codigo: nao procure respostas ali e nao edite nada la dentro.


| Assunto | Arquivo |
|---|---|
| Entrypoint CLI | `agent/main.py` |
| Orquestração ponta a ponta | `agent/orchestrator.py` |
| Política por classe de vulnerabilidade | `agent/core/vulnerability_catalog.py` |
| Lições de CVL/Certora acumuladas | `docs/certora-cookbook.md`, `docs/certora-lessons.md` |
| Oráculo formal local: o que mede e quanto custa | `docs/resultado-oraculo-formal-20261117.md` |
| Experimento de generalização (pré-registro) | `docs/experimento-generalizacao-pre-registro.md` |
| Spec congelada de oráculo | `specs/oracle/DeFiVault.spec` |
| Detector próprio | `docs/unrestricted-write-detector.md` |
| Relatório PIBIC (entregável) | `docs/relatorio-final-pibic-2026.md` |
| Histórico longo do projeto | `docs/session-context.md` (**desatualizado**, ver banner) |
| Organização do repo | `docs/repo-organization.md` |

Contratos reais em `smart-audt/contracts/real/`: astaria, caviar, defivulnlabs,
escher, inverse, maia, runes, solmate.
