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
