# Certora Lessons For The Agent

Data: 2026-05-23

Este documento registra regras oficiais do Certora/CVL e erros reais observados no pipeline. A ideia nao e deixar a LLM "adivinhar melhor"; e transformar cada falha repetida em memoria executavel: catalogo, validador, teste e prompt mais estreito.

## Fontes Oficiais

- Methods block: https://docs.certora.com/en/latest/docs/cvl/methods.html
- Mudancas do CVL 2: https://docs.certora.com/en/latest/docs/cvl/cvl2/changes.html
- Statements: https://docs.certora.com/en/latest/docs/cvl/statements.html
- Expressions e `lastReverted`: https://docs.certora.com/en/latest/docs/cvl/expr.html
- Built-in rules: https://docs.certora.com/en/latest/docs/cvl/builtin.html
- Cookbook local para a LLM: `docs/certora-cookbook.md`

## Regras Que Viraram Pipeline

- `methods{}` deve ser deterministico. A LLM pode sugerir rules, mas o bloco de methods deve ser reconstruido a partir da interface Solidity real.
- Em CVL 2, cada entrada de `methods{}` comeca com `function` e termina com `;`.
- `methods{}` contem assinaturas, nao corpos Solidity.
- Nao usar `payable` em entrada de methods; `address payable` vira `address`.
- Getters simples podem ser `envfree`; funcoes `view/pure` so devem ser
  `envfree` quando nao leem ambiente restrito como `msg.sender`, `msg.value`,
  `tx.origin`, `block.timestamp` ou `block.number`.
- Chamadas `envfree` nao recebem `env`.
- Nao existe wrapper `rules { ... }`; cada `rule` e top-level.
- Statements soltos apos `// VULN_XXX` devem ser envolvidos em `rule nome { ... }`.
- `lastReverted` deve ser checado logo apos a chamada com `@withrevert`.
- Em regra de zero address, a pre-condicao `require x == 0;` precisa existir, senao a rule prova algo diferente do que queremos.
- Duplicar `env e` dentro da mesma rule e erro; quando a LLM mistura um teste de revert e um teste de estado, o pipeline deve remover o preambulo incorreto ou dividir a rule.
- Rule de `tx-origin`/auth nao pode chamar funcao aleatoria. Ela deve chamar uma funcao realmente protegida por `onlyOwner`, escolhida deterministicamente pela interface do contrato.
- A avaliacao deve ler os `certora*.log` antes de confiar em `comparison_t1.json`.
  Se houver erro bloqueante de spec, o run nao pode ser reportado como `passed`.
- Certora precisa do nome do contrato interno, nao do nome do arquivo. Arquivos
  como `SimpleBank_FIXED.sol` podem conter `contract SimpleBank`; o pipeline deve
  detectar isso no source antes de chamar `certoraRun`.

## Erros Observados

| Erro Certora | Causa | Acao do Pipeline |
| --- | --- | --- |
| `unexpected token near rules` | LLM criou `rules {}` | `remover_wrapper_rules` |
| `methods block entries must end with ;` | Methods invalido para CVL 2 | `substituir_methods_block` |
| `unexpected token near {` em methods | Corpo Solidity dentro de methods | `substituir_methods_block` / `normalizar_methods_com_corpo` |
| `unexpected token near env` | Statements fora de `rule` | `envolver_blocos_vuln_sem_rule` |
| `Redeclaring variables is not supported` | Dois mini-testes na mesma rule | `remover_prefixo_revert_duplicado` |
| `address x = 0` | Inicializacao invalida/fragil em CVL | `corrigir_spec` + `inserir_requires_zero_address` |
| `lastReverted` enganoso | Outra chamada sobrescreveu `lastReverted` | manter chamada `@withrevert` adjacente ao assert |
| Auth rule chama funcao publica comum | LLM escolheu alvo errado para `tx-origin` | `aplicar_auth_probe_rules` |
| `declared envfree but depends on the environment` | methods marcou funcao dependente de ambiente como `envfree` | reconstruir methods sem `envfree` para essa funcao e bloquear o run antigo |
| `Failed to find a contract named` | Certora recebeu nome do arquivo em vez do contrato interno | detectar `contract Name` no Solidity e passar esse nome ao `certoraRun` |

## Sobre Reentrancy

Nao vale gastar todo o projeto tentando fazer Certora provar toda reentrancia gerica. Uma divisao melhor:

- Slither detecta padroes de chamada externa antes de escrita de estado.
- O repair agent aplica CEI ou `nonReentrant`.
- Um check estatico do pipeline confirma ordem das escritas antes da chamada externa.
- Certora entra quando houver propriedade formal clara.
- Para read-only reentrancy, avaliar `use builtin rule viewReentrancy;`, que e uma built-in rule oficial do Certora.

## Como O Agente Deve Aprender

1. Toda falha de Certora gera `certora_error_analysis.json`.
2. Cada padrao novo entra em `agent/core/certora_error_catalog.py`.
3. Cada correcao entra em `agent/tools/spec_validator.py`.
4. Cada caso vira teste unitario offline.
5. So depois disso vale gastar Groq/Certora de novo.

Esse ciclo evita torrar tokens para a LLM redescobrir sintaxe de CVL.

## O Verificador Local — Um Oraculo De Graca (2026-11-17)

`certoraRun --compilation_steps_only` para antes de **enviar** o job, nao antes de
**verificar**: o `emv.jar` roda na maquina e imprime vereditos de regra reais. Isso foi
validado com um par original/mutante em `runs/oracle_validation_20261116/` — mesma spec,
original `Verified`, mutante AOR `Violated` com contraexemplo, nenhuma URL de job nos logs,
menos de 1 min cada.

Por que importa: `agent/mutant_detection.py` mediu que **36 dos 46** mutantes do DeFiVault
nao produzem nenhum achado no Slither (AOR, BOR, UOR, EED e PKR tem detectabilidade zero).
Um defeito que o instrumento nao ve nunca chega ao estagio de reparo, logo o benchmark nao
cobra o agente por ele. O oraculo formal cobra, sem gastar cota de nuvem.

Como ler o log:

- `Verified: <regra>` e `Violated: <regra>` sao as linhas de veredito. A tabela de
  resultados diz `Not violated`, que lida com essas duas palavras significa o contrario.
- `<regra>-rule_not_vacuous` aparece `Violated` sempre que a regra e **alcancavel**. E o
  sanity check: fica fora da conta (`parse_local_verdict` separa em `sanity`).
- Sem nenhuma linha de veredito, o resultado e `error`, nao "verificado".

No codigo:

- `tools/certora_cli.certora_argv` e o **unico** lugar que monta uma linha de comando do
  Prover. Tres invocacoes feitas a mao perderam, cada uma, um detalhe diferente:
  `--solc_allow_path` (o Prover recusa fontes fora dos diretorios permitidos), as flags de
  otimizador do Foundry (sem elas, "Stack too deep" em contrato que compila no projeto) e
  um `--packages` por remapping.
- `tools/certora_cli.verify_locally` escreve o log em arquivo em vez de capturar na
  memoria: com `capture_output`, um timeout descarta tudo que o Prover ja havia impresso.
- `agent/mutant_oracle.py` roda uma spec congelada contra todos os mutantes. Se a spec nao
  verifica no **original**, ele aborta sem reportar nada: qualquer mutante apareceria morto
  pelo mesmo motivo que o original.

Spec de oraculo (`specs/oracle/DeFiVault.spec`, 19 regras): o contrato promete que saldos
andam exatamente o valor pedido, que o lock e o teto de saque valem, que so o dono
administra e que a whitelist barra deposito e saque. Nenhuma regra fala de um defeito
especifico — e isso que permite rodar a mesma spec em todo mutante. **Regra congelada:**
nenhuma regra pode ser adicionada, apertada ou afrouxada depois de se conhecer o resultado
de um mutante.
