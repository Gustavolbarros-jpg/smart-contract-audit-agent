# Balanço da semana — 04 a 12/11/2026

> Snapshot fechado em **2026-11-12**. Não substitui `docs/relatorio-final-pibic-2026.md`
> (entregável) nem `CLAUDE.md` (estado operacional). É o registro do que a semana
> produziu, do que foi medido e do que ficou em aberto.
>
> Itens marcados **[v]** foram reconferidos contra o repositório e os artefatos em
> 12/11. Os demais vêm do registro das sessões e estão identificados como tal.

---

## 1. Resumo executivo

A semana teve uma tese só: **tirar o LLM do caminho onde o problema é mecânico e medir
honestamente o que sobra para ele**. Tudo o que foi feito se encaixa nisso — catálogo
completo, trilha `--static-only`, patches determinísticos, detector próprio, e um
instrumento novo para medir detectabilidade antes de atribuir mérito ao agente.

O resultado tem dois lados:

**Ganho real.** Existe agora uma baseline sem IA que resolve a maioria dos achados
mecânicos, com guardrails que impedem o LLM de piorar o contrato. O pipeline roda
ponta a ponta em contratos de produção reais (Foundry, remappings, imports
transitivos), não só nos contratos de brinquedo.

**Custo intelectual.** Quanto mais a trilha determinística cresceu, mais ficou evidente
que **a generalização do LLM continua não demonstrada**: nas medições desta semana,
*todos* os reparos contabilizados pelo probe foram determinísticos. O "novel" que o
probe reportava era artefato de medição, não generalização. Isso é a principal
pendência científica do projeto e precisa de um experimento desenhado para falsificar
a hipótese, não para confirmá-la.

---

## 2. Números verificados hoje [v]

| Medida | Valor |
|---|---|
| Testes | **307 passed, 1 skipped, 69 subtests, 14,0 s** |
| Commits da semana (04–09/11) | **36**, todos na branch `analysis/catalog-coverage` |
| Commits sem push | **7** (`b33532b..ffa56ee`) |
| Commits à frente de `origin/develop` | 36 — é o conteúdo do **PR #2** |
| Diff da semana | 54 arquivos, **+4.869 / −77** linhas |
| Arquivos novos | 8 módulos em `agent/`, 7 suítes de teste, 18 fixtures, 3 docs |
| Entradas no catálogo | **105** (6 `formalizable`) |
| Execuções em `runs/` | 393 diretórios, 647 MB |
| Execuções `--static-only` | 310 (em `runs/static_only/`, fora da avaliação) |
| `logs_antigos/` | 1,4 GB, 156 entradas — sem destino decidido |
| Árvore suja | `docs/session-context.md` (banner de obsolescência), `CLAUDE.md` **untracked** |

---

## 3. O que entrou no código

### A. Cobertura total do catálogo
`2ffc6df`, `799b83a`, `cb3d65b` + `agent/verify_catalog.py`

As 105 entradas de `agent/core/vulnerability_catalog.py` cobrem os 99 detectores do
Slither 0.11.3. Há um teste que **falha se uma versão nova do Slither trouxer um
detector desconhecido** — o catálogo deixou de poder envelhecer em silêncio.
`verify_catalog.py` confere o catálogo contra o corpus de testes do próprio Slither
(baixa o tarball do GitHub e usa os `.zip` do crytic-compile, sem precisar de solc
antigo).

Decisão que vale registrar: **`arbitrary-send-erc20` foi promovido a `formalizable` e
depois revertido** (`cb3d65b` → `799b83a`). A regra CVL autocontida (ghost + summary de
`_.transferFrom`) funciona num par mínimo de cofres — a fixture está em
`tests/fixtures/certora/arbitrary_send_erc20/` —, mas os 7 achados reais são
autorização *por design* (`requiresAuth`, contrato de recompensas como origem,
`requiresBridgeAgent`) e **todos usam `safeTransferFrom`, que o summary não
intercepta**. Promover geraria spec para um achado que não é defeito.

### B. Trilha sem IA: `--static-only` + patches determinísticos
`6de3dac`, `2d22d0d`, `48cb4f8`, `16761cd`, `4fc3a38`, `c08adbf`, `d30d721`, `5250921`, `2b42000`

`python3 agent/main.py --static-only [--with-plugins] <contrato>` roda
Slither → catálogo → patch → reanálise, em `core/static_only.py`, **sem nenhum import
de `llm/`**. É a forma de exercitar o pipeline sem gastar cota nem chamar o Prover.

Patches mecânicos em `core/deterministic_patch.py`: `missing-zero-check` (inclusive em
construtor e em todas as sobrecargas), `tx-origin`, `unchecked-lowlevel`,
`unchecked-transfer`, `unchecked-send`, `suicidal`. **Não existe patch para
`arbitrary-send-eth`** — decisão de design, não lacuna.

Três detalhes que custaram tempo e agora estão resolvidos no código:
- O arquivo corrigido é reanalisado **ao lado do original**, senão os imports relativos
  não resolvem.
- A contagem por arquivo inflava porque o Slither reporta os imports; `scoped_to_file`
  filtra pelos elementos do próprio arquivo. *Desconfie de qualquer "N arquivos" de
  antes dessa correção.*
- As execuções `--static-only` vão para `runs/static_only/`, senão o `evaluate.py` as
  toma como "a execução mais recente".

### C. Detector próprio `unrestricted-write`
`316fc6a`, `904323d`, `10cf407`, `d7363f0`, `d986400`

Plugin Slither em `agent/slither_plugins/unrestricted_write.py` para escrita
privilegiada sem guarda. Recall de 38/80 nos mutantes MD e 1 achado nos 112 originais.
Documentado em `docs/unrestricted-write-detector.md`. Teste lento é opt-in
(`RUN_SLOW_TESTS=1`).

O reparo é `restore_access_modifier`, e ele é **deliberadamente conservador**: só atua
quando o contrato tem **exatamente um** modificador de identidade. Com dois ou mais, a
escolha não é mecânica e o caso vai para o LLM.

Dois bugs importantes fechados aqui:
- A reanálise do `--static-only` **não rodava o plugin**, então um achado de plugin
  contava como "resolvido" de graça (`10cf407`).
- O pipeline completo não rodava os detectores do projeto; agora roda com
  `AUDIT_WITH_PLUGINS=1`, e **um contrato não é chamado de seguro enquanto houver
  achado de segurança não revisado** (`d7363f0`).

### D. Contratos reais: configuração de Slither e do Prover
`0e87e8d`, `365ab98`, `e9a17c4`, `0718914`, `ff39943`

O que destravou os projetos Foundry de `smart-audt/contracts/real/`:
- Slither sai com **exit 1 e stdout vazio** se rodar fora da raiz do projeto;
  `tools/slither_cli.py` agora usa `cwd` = raiz (por `foundry.toml`/`remappings.txt`/
  hardhat/pai de `src`). `--json -` esconde o erro real — para diagnosticar, rode sem `--json`.
- `crytic-compile` guarda só o **último** `--solc-remaps`: tudo tem que ir junto num
  valor só, separado por espaço.
- Alvo de remap precisa da **barra final** quando o prefixo tem (o Prover normaliza, o
  Slither não); `solc_remappings` passou a seguir imports transitivos e prefixos
  multi-segmento.
- `certora_compiler_flags` repassa o otimizador do `foundry.toml` — sem isso, "Stack too
  deep" no caviar.
- `AUDIT_CERTORA_TIMEOUT` (padrão 600 s; PrivatePool passa de 15 min).
- Nome de arquivo com hífen quebra o Prover → ele roda numa **cópia sanitizada**.
- `safeTransfer*` deixou de ser reportado como `unchecked-transfer` (falso positivo que
  contaminava contagem).

### E. Verificar o contrato certo
`29b0fb5`, `f89796b`, `b3ef37c` + `core/contract_choice.py`, `core/slither_scope.py`

Na rodada do DeFiVulnLabs, **12 de 19 reparos caíram em `ContractTest`/`Attack`** — o
agente estava "consertando" o harness do teste. Agora `is_harness_contract` classifica
por palavras do nome CamelCase, `blank_harness_contracts` e
`without_harness_contracts` descartam harness no orchestrator e no `--static-only`, e o
contrato verificado é **o que concentra os achados críticos**, não o último do arquivo.
O bloco `methods` descreve esse contrato, não outro.

### F. Instrumento de medição: detectabilidade antes de mérito
`89f0c53`, `377b924`, `dd6348d`, `b33532b` + `agent/mutant_detection.py`

Esta é a mudança conceitualmente mais importante da semana. `mutant_detection.py` mede,
**só com Slither + plugin**, quais mutantes aparecem como achado novo. Em
`DeFiVault_FIXED.sol`: **9 de 46** (MD 7/14, FXR 2/5; AOR, BOR, UOR, EED, PKR = 0 — e 2
PKR nem compilam).

Ou seja: as rodadas antigas de "0/13, 2/13, 1/13" **não mediam o agente**. Mediam
mutantes invisíveis ao Slither. `generalization_probe.py --detectable-only` filtra para
o subconjunto que o stack enxerga, e só contam como detecção os **achados de
segurança**, escritos ao lado do original para os imports resolverem.

### G. Correções de CVL / Certora
`b33532b`, `ffa56ee`, `2dd70e4`, `8c04769`, `4e23980`

- CVL não tem `assume` → vira `require`; campos de `env` não podem ser atribuídos.
  `tools/spec_validator.py` conserta os dois automaticamente.
- `declarar_owner_envfree()` (`ffa56ee`, último commit): um `owner()` herdado de
  `Ownable` não está no arquivo, então o bloco `methods` não o declara e o Prover
  rejeita com "missing environment parameter". Agora é declarado `envfree` quando uma
  regra o chama e o contrato visivelmente herda/define owner.
- O aviso "autofinder … falling back to original file" **não é erro** — estava sendo
  classificado como bloqueio.
- Campos `tx`/`msg` crus corrigidos na spec gerada; e o pipeline **parou de reescrever
  o idioma de EOA (`msgSender == tx.origin`) como se fosse autorização** — era
  regressão semântica disfarçada de correção.
- O Prover **não abre mais o relatório HTML no navegador**: `tools/certora_cli.py`
  remove `DISPLAY`/`WAYLAND_DISPLAY` de propósito.

### H. Entregáveis e limpeza
`1ac0abc` (relatório final PIBIC com o catálogo de novembro e os resultados do
DeFiVulnLabs), `d986400` (doc do detector), `df2668b` (`AUDIT_LLM_MODEL` configurável),
`7c71487` (remoção de schemas Pydantic sem uso).

---

## 4. O saldo medido

### 4.1 Baseline estático, sem LLM e sem Certora
201 de 264 arquivos de `smart-audt/contracts/real/*/src`: **77 correções confirmadas
pelo Slither, 16 críticos sem correção**. No registry de 10 contratos: 21 de ~35
críticos. *(Registro de 04/11; ver §6 sobre a contagem do corpus.)*

### 4.2 Pipeline completo no registry
7 contratos acionáveis `passed`, **28 achados resolvidos — 21 por patch determinístico e
7 pelo LLM** (5 `arbitrary-send-eth`, 1 `unchecked-lowlevel`, 1
`erc2771-multicall-context`), todos verificados pelo Certora.

⚠️ **Armadilha de leitura:** o pipeline completo aplica os patches determinísticos
*antes* do LLM. Não compare "resolvidas" do completo com as do estático sem separar as
duas origens — 21 dos 28 são os mesmos do `--static-only`.

### 4.3 DeFiVulnLabs (57 arquivos, SunWeb3Sec)
Sem LLM: 53 analisados, 702 achados, 42 tipos de detector, **29 corrigidos**; os 4
restantes são solc 0.7. Com LLM+Certora (26 arquivos com críticos): 9 `passed`, mas
**só 3 tiveram o contrato vulnerável de fato corrigido** — foi o que motivou o §3.E. A
cota diária do `gpt-oss-120b` acabou no meio; a rodada 2 usou `gpt-oss-20b`, mais
fraco, e bateu em patch_guard e Certora inconclusivo. **As duas rodadas não são
comparáveis entre si.**

### 4.4 Lote de contratos de produção — 09/11 [v]
Causa-raiz lida dos artefatos em `runs/`, não do registro:

| Contrato | Desfecho | Causa-raiz verificada |
|---|---|---|
| **SimpleERC20Escrow** (inverse) | ✅ **2/2 resolvido** | t1 resolveu `unchecked-transfer` (patch determinístico em `pay`); t2 resolveu `unrestricted-write`. `patch_guard`: 4 hunks, 0 issues. `comparison_t2.json` → `"taxa_resolucao": "2/2"` |
| **Initializable** (escher) | ✅ Sem achado real | `static_confirmed_findings.json` vazio; sobrou só `assembly` informational. Os 2 "achados" eram falsos positivos, já corrigidos no normalizador |
| **GovTokenEscrow** (inverse) | 🟡 4 confirmados, parou no LLM | Certora **rodou**: `zero_address_reverts` → **Violated**, confirmando `missing-zero-check` formalmente; +3 `confirmed_static` (1 `unchecked-transfer`, 2 `unrestricted-write`). A spec do LLM nem foi necessária (`deterministic_spec_covered_all_selected_rules`). Bloqueou no **400 json_validate_failed** na etapa de diagnose |
| **OpenEdition** (escher) | 🟡 Correção escrita, **não verificada** | 1ª tentativa: Prover rejeitou a spec — `could not type expression "owner()" … Missing environment parameter`. É exatamente o que `ffa56ee` corrige. A re-execução das 20:20 bloqueou no **429 TPD** (195.488/200.000 tokens usados) **antes de chegar ao Certora** |
| **TalosBaseStrategy** (maia) | ❌ Barrado pelo guardrail | O patch do LLM **removeu uma função public/external** (linha 298). `patch_guard`: 5 erros, 19 avisos, `should_block: true`. O retry foi bloqueado de forma idêntica. O guardrail funcionou como projetado |
| **GovernorBravoDelegateMaia** (maia) | ❌ **Dois** bloqueios | (1) **spec inválida**: `getReceipt(...)` foi declarado `returns (address)` enquanto o contrato devolve a struct `Receipt` → `Cannot merge address with GovernorBravoDelegateStorageV1.Receipt`. (2) `CompilerError: Stack too deep` |

**Achado novo de hoje, que corrige o registro anterior:** o GovernorBravo estava
arquivado como "stack too deep, limite sem solução". Não é só isso. O **primeiro**
bloqueio é um bug nosso: a regra "tipo de interface em assinatura CVL → `address`" está
sendo aplicada também a **retorno de struct**. Isso é acionável (ver §7, P2) e pode
estar afetando silenciosamente outros contratos com getters que devolvem struct.

### 4.5 Probe de generalização
Com `--detectable-only` e `AUDIT_WITH_PLUGINS=1`: **DeFiVault_FIXED 6/9** e
**SimpleBank_FIXED 7/7**.

E aqui está o ponto: **os 13 reparos foram todos determinísticos** — 11
`unrestricted-write` + 2 `tx-origin`. Nenhum do LLM. As 3 falhas do DeFiVault são todas
do caminho LLM (400 do Groq; e uma spec que inventou a função `isAuthorized`).

---

## 5. A conclusão incômoda

**A generalização do LLM continua não demonstrada.** Não é "demonstrada como ruim" — é
**não medida**, e por três razões que se somam:

1. **O instrumento era enviesado.** O "novel" que o probe reportava significava apenas
   "a biblioteca de moldes não tinha esse caso", não "o modelo generalizou".
2. **O espaço de medição é pequeno demais.** Só 9 ou 10 dos 46 mutantes são visíveis ao
   stack estático. Os operadores AOR, BOR, UOR, EED e PKR têm detectabilidade zero — o
   Slither não os vê, logo o pipeline nunca é cobrado por eles.
3. **A trilha determinística chega primeiro.** Por construção, o patch mecânico é
   calculado antes da diagnose do LLM (de propósito: uma falha de LLM não deve bloquear
   o que já era mecânico). O efeito colateral é que o LLM só é exercitado no resíduo.

Para o relatório PIBIC isso precisa ser dito nesses termos. A contribuição defensável
da semana é **a baseline determinística + os guardrails**, não "o LLM generaliza".

---

## 6. Dívidas abertas, classificadas

**Acionável (bug ou tarefa nossa)**
- Retorno de struct virando `address` na spec CVL (GovernorBravo). §7 P2.
- OpenEdition: correção do `owner() envfree` escrita e **não verificada**. §7 P1.
- GovTokenEscrow: 4 achados confirmados, reparo não tentado (400 do Groq). §7 P3.
- TalosBaseStrategy: o LLM reincide em remover função pública; falta estratégia de
  reparo do patch em vez de só barrar. §7 P4.
- Operadores de mutação do CCIHunter como suíte de regressão — Fase 1 do plano de
  generalização, ainda pendente.
- NatSpec → spec CVL — Fase 2, pendente.

**Contagem a reconciliar (vira número no relatório)**
- A discrepância não é "63 vs 66": são **quatro** números incompatíveis.
  `CLAUDE.md` diz **38** arquivos de produção onde o Slither falha; o relatório fala em
  **63**; o registro das sessões fala em **66** não analisáveis; e a decomposição desses
  66 (28 astaria sem `lib/gpl` + 19 maia stack-too-deep + 6 testes forge-std + 1
  AssertionError do Slither) **soma 54** — 12 arquivos sem explicação. Hoje há **343**
  arquivos `.sol` sob `*/src` [v], contra os 264 do baseline. Nada disso pode entrar no
  PIBIC antes de ser recontado por um script único e versionado. §7 P6.

**Limite externo (não resolvemos aqui)**
- 28 arquivos do astaria exigem `lib/gpl` — o repo `AstariaXYZ/astaria-gpl` dá 404.
- 19 arquivos do maia dão stack-too-deep (`--via-ir`, `--optimize`, `--solc-ast` e
  `forge` não resolveram).
- Cota do Groq: 200k tokens/dia por modelo. Trocar de modelo para continuar **quebra a
  comparabilidade** com as rodadas anteriores — e isso tem que ser dito em qualquer
  tabela que misture as duas.

**Decisão pendente do usuário**
- `logs_antigos/`: 1,4 GB, 156 entradas, sem destino.
- `CLAUDE.md` está **untracked** — commitar ou manter fora do git?
- `docs/session-context.md` tem o banner de obsolescência **não commitado**.
- PR #2 contra `develop`: 36 commits, 7 sem push. Nada sai sem autorização explícita.

---

## 7. Próximos pontos

Ordenados por "menor esforço para fechar uma pendência real". Cada um tem comando e
critério de pronto.

### P1 — Fechar a verificação do OpenEdition *(bloqueado só por cota)*
A correção já está no código (`ffa56ee`); falta o Prover confirmar que a spec passa a
compilar.
```
SOLC_VERSION=0.8.17 AUDIT_WITH_PLUGINS=1 AUDIT_LLM_MODEL=openai/gpt-oss-120b \
  python3 agent/main.py --contract /caminho/absoluto/OpenEdition.sol
```
**Pronto quando:** `certora_status.json` da nova execução não tiver `spec_error`, e o
log não repetir `could not type expression "owner()"`.
**Atenção:** use `src/`, nunca a cópia em `out/`.

### P2 — Corrigir o retorno de struct na spec (bug novo, achado hoje)
A conversão de tipo de interface para `address` está pegando retorno de struct.
`getReceipt` virou `returns (address)` e o Prover recusou com `Cannot merge`.
Local: a geração do bloco `methods` / `tools/spec_validator.py`.
**Pronto quando:** houver teste cobrindo um getter que devolve struct, e o
GovernorBravo falhar **só** por stack-too-deep — isolando o limite externo do nosso bug.
*Ganho colateral: qualquer contrato com getter de struct estava quebrando por isso.*

### P3 — Retomar o GovTokenEscrow
Os 4 achados estão confirmados (1 formalmente pelo Certora). Falta o reparo, que parou
no `400 json_validate_failed` — o `failed_generation` menciona **limite de tokens de
completion**, então pode ser prompt grande, não aleatoriedade.
**Pronto quando:** `comparison_t*.json` mostrar `taxa_resolucao` e o `zero_address_reverts`
passar a "Not violated" no contrato corrigido.

### P4 — TalosBaseStrategy: reparar em vez de só barrar
O guardrail está certo em bloquear, mas o LLM reincidiu idêntico no retry. Vale um
prompt de reparo que receba **a lista de funções removidas** e exija restaurá-las, em
vez de só repetir que foi bloqueado.
**Pronto quando:** o retry produzir `patch_guard` com `errors: 0`, ou o contrato ser
registrado como "sem reparo viável pelo LLM" com evidência — as duas saídas são
resultado legítimo.

### P5 — Desenhar um experimento que possa falsificar a generalização
Esta é a tarefa de maior valor para o PIBIC, e a única que não é mecânica. Elementos
mínimos:
- **Separar as origens na contagem.** Todo reparo precisa sair rotulado
  `deterministic` ou `llm`. Hoje dá para inferir dos artefatos; precisa ser campo.
- **Rodar o probe com a trilha determinística desligada** num braço do experimento.
  Sem isso o LLM só vê resíduo e a medição nunca separa os dois efeitos.
- **Enfrentar a detectabilidade zero.** Para AOR/BOR/UOR/EED/PKR, o oráculo não pode
  ser o Slither. Ou o oráculo passa a ser o Certora com uma invariante, ou esses
  operadores saem declaradamente do escopo — ambas são posições defensáveis; o que não
  é defensável é deixar implícito.
- **Pré-registrar o número esperado** antes de rodar, para a rodada poder dar errado.

### P6 — Recontar o corpus de uma vez
Um script versionado que emita: total de `.sol`, excluídos por categoria (teste, mock,
harness, interface), analisados, falhos **com a razão**. Substituir 38/63/66/264/343 por
uma saída só.
**Pronto quando:** `docs/relatorio-final-pibic-2026.md` citar números gerados por esse
script, e a soma fechar.

### P7 — Housekeeping (rápido, destrava o PR)
Decidir sobre `CLAUDE.md` untracked, commitar o banner de `session-context.md`, decidir
o destino de `logs_antigos/`, e autorizar (ou não) o push dos 7 commits do PR #2.

---

## 8. Riscos que podem invalidar medição

1. **Troca de modelo no meio do lote.** Já aconteceu no DeFiVulnLabs (120b → 20b). Toda
   tabela que misture rodadas de modelos diferentes tem que dizer isso na própria tabela.
2. **Cota como viés silencioso.** Um 429 no meio de um lote faz o contrato parecer
   "falha do agente" quando foi infraestrutura. Os status `blocked` em `runs/` distinguem
   os dois casos — qualquer agregação precisa respeitar essa distinção.
3. **Exit code e avisos do Prover.** Exit 100 com violação é normal;
   `-rule_not_vacuous` Violated é o sanity check; "autofinder … falling back" é aviso.
   Tratar qualquer um deles como falha corrompe a contagem.
4. **Contagem por arquivo antes de `scoped_to_file`.** Qualquer "N arquivos" anterior a
   essa correção está inflado pelos imports.

---

## 9. Anexo — comandos e ambiente

```bash
# Pipeline completo (gasta cota)
SOLC_VERSION=<ver> AUDIT_WITH_PLUGINS=1 AUDIT_LLM_MODEL=openai/gpt-oss-120b \
  python3 agent/main.py --contract /caminho/absoluto/X.sol

# Sem gastar nada
python3 agent/main.py --contract /caminho/absoluto/X.sol --static-only --with-plugins

# Testes (307 passed, 1 skipped, ~14 s)
python3 -m pytest tests/ -q

# Medir generalização / detectabilidade
SOLC_VERSION=0.8.21 python3 agent/generalization_probe.py <X>_FIXED.sol --detectable-only
SOLC_VERSION=0.8.21 python3 agent/mutant_detection.py <X>_FIXED.sol
```

| Variável | Valor | Por quê |
|---|---|---|
| `SOLC_VERSION` | por contrato | O preflight ignora o pin do Foundry. DeFiVault → 0.8.21; OpenEdition → 0.8.17; Inverse → deixe sem definir |
| `AUDIT_LLM_MODEL` | `openai/gpt-oss-120b` | O default do código (`llama-3.3-70b-versatile`) dá 404 no Groq hoje |
| `AUDIT_WITH_PLUGINS` | `1` | Liga o `unrestricted-write` no pipeline completo |
| `AUDIT_CERTORA_TIMEOUT` | ≥600 | Suba para contratos grandes |

**Sempre caminho absoluto. Sempre `src/`, nunca `out/`.** Mutantes e temporários ficam
ao lado do original — o Prover recusa arquivos fora do diretório do repo.

---

*Documentos relacionados:* `CLAUDE.md` (estado operacional),
`docs/relatorio-final-pibic-2026.md` (entregável),
`docs/unrestricted-write-detector.md`, `docs/certora-cookbook.md`,
`docs/certora-lessons.md`, `docs/session-context.md` (histórico mai–ago/2026).
