# Guia De Apresentacao E Demo - Pipeline De Auditoria

Data: 2026-05-28

Branch: `feature/pipeline-guardrails`

## Mensagem Principal

O projeto implementa um agente hibrido para auditoria e correcao de contratos
inteligentes:

```text
Slither -> normalizacao -> LLM/planejamento -> CVL -> Certora -> diagnostico
-> correcao -> patch_guard -> revalidacao
```

A ideia importante para apresentar:

> A LLM nao corrige o contrato "no chute". Ela opera dentro de um pipeline com
> analise estatica, verificacao formal, correcoes deterministicas e guardrails
> de patch.

## Estado Atual Do Pipeline

O pipeline hoje faz:

1. Roda Slither no contrato.
2. Normaliza achados para classes conhecidas.
3. Filtra achados que nao tem propriedade formal confiavel.
4. Planeja regras formais.
5. Gera spec CVL.
6. Valida o contrato original com Certora.
7. Corrige somente vulnerabilidades confirmadas.
8. Usa `patch_guard` para bloquear patch amplo, truncado ou fora do escopo.
9. Revalida com Certora e Slither.
10. Gera comparacao final: resolvidas, persistentes e inconclusivas.

Classes ja exercitadas:

- `missing-zero-check`;
- `tx-origin`;
- `suicidal`;
- `arbitrary-send-eth`;
- `unchecked-lowlevel`;
- `erc2771-multicall-context`.

Classes que ainda exigem cuidado:

- reentrancia;
- vulnerabilidades economicas;
- oraculos;
- invariantes contabeis complexas;
- `tx.origin` quando usado como politica EOA/allowlist, nao como autorizacao
  simples.

## Contratos Principais Para Mostrar

| Contrato | Tipo | Tamanho | Run | Resultado |
| --- | --- | ---: | --- | --- |
| `EnterpriseTreasury300.sol` | controlado/stress | 327 linhas | `runs/20260527_095632_EnterpriseTreasury300` | 9/9 resolvidos |
| Forgotten Runes `ForgottenRunesWarriorsMinter.sol` | real Code4rena | 631 linhas | `runs/20260527_105459_ForgottenRunesWarriorsMinter` | 2/2 resolvidos |
| Inverse `Market.sol` | real Code4rena | 621 linhas | `runs/20260528_093346_Market` | 3/3 resolvidos |
| Caviar `PrivatePool.sol` | real Code4rena | 794 linhas | `runs/20260528_101335_PrivatePool` | 0 candidatos acionaveis |
| Solmate `WETH.sol` | real/controle negativo | pequeno | `runs/20260527_102842_WETH` | 0 candidatos acionaveis |
| Escher `FixedPrice.sol` | real/triagem `selfdestruct` | 112 linhas | `runs/20260528_093456_FixedPrice` | 0 candidatos apos ajuste |

## Contrato Real Maior Corrigido: Inverse `Market.sol`

Este e o melhor caso para mostrar correcao real de ponta a ponta.

Arquivo:

```text
smart-audt/contracts/real/inverse/src/Market.sol
```

Run:

```text
runs/20260528_093346_Market
```

O que havia de errado:

- `setGov(address)` aceitava `address(0)`;
- `setLender(address)` aceitava `address(0)`;
- `setPauseGuardian(address)` aceitava `address(0)`.

Esses tres enderecos controlam papeis criticos:

- `gov`: governanca;
- `lender`: endereco autorizado para recall;
- `pauseGuardian`: guardiao de pausa.

O Slither identificou `missing-zero-check` nessas funcoes. O Certora confirmou
que chamadas com `address(0)` nao revertiam. Depois disso o pipeline aplicou
patch deterministico minimo.

Patch aplicado:

```solidity
function setGov(address _gov) public onlyGov {
    require(_gov != address(0), "Zero address"); // FIX VULN_023
    gov = _gov;
}

function setLender(address _lender) public onlyGov {
    require(_lender != address(0), "Zero address"); // FIX VULN_026
    lender = _lender;
}

function setPauseGuardian(address _pauseGuardian) public onlyGov {
    require(_pauseGuardian != address(0), "Zero address"); // FIX VULN_020
    pauseGuardian = _pauseGuardian;
}
```

Resultado:

```text
3/3 resolvidos
patch_guard: 3 hunks, 0 erros, 0 avisos
Certora fixed: aprovado
Slither fixed: achados corrigidos nao persistem
```

Comandos para mostrar esse caso sem rerodar o pipeline:

```bash
cat runs/20260528_093346_Market/comparison_t1.json
cat runs/20260528_093346_Market/patch_guard_t0.json
sed -n '126,152p' agent/agent_outputs/Market_FIXED.sol
```

## Contrato De 794 Linhas: Caviar `PrivatePool.sol`

Este e o melhor caso para mostrar que o pipeline escala para contrato real maior
e tambem sabe parar.

Arquivo:

```text
smart-audt/contracts/real/caviar/src/PrivatePool.sol
```

Run:

```text
runs/20260528_101335_PrivatePool
```

Resultado:

```text
0 achados normalizados acionaveis
0 candidatos formais
0 static-confirmed
```

Interpretacao:

O contrato de 794 linhas compilou com Slither usando imports reais e
`remappings.txt` de Foundry, mas nao tinha achado dentro das classes que o
pipeline hoje trata com confianca. Entao ele parou antes de:

- chamar LLM;
- rodar Certora;
- gerar patch.

Isso e um controle negativo importante:

> O agente nao inventou vulnerabilidade so porque o contrato era grande.

Comando seguro para demo ao vivo, sem gastar Groq:

```bash
python3 agent/main.py --contract smart-audt/contracts/real/caviar/src/PrivatePool.sol
```

Esse comando deve parar na etapa 1 com 0 candidatos. Ele nao deve chamar LLM.

Comandos para mostrar artefatos salvos:

```bash
cat runs/20260528_101335_PrivatePool/etapa1_vulns.json
cat runs/20260528_101335_PrivatePool/metadata.json
```

## Contrato Controlado Maior: `EnterpriseTreasury300.sol`

Arquivo:

```text
smart-audt/contracts/EnterpriseTreasury300.sol
```

Run:

```text
runs/20260527_095632_EnterpriseTreasury300
```

Resultado:

```text
9/9 resolvidos
```

Classes resolvidas:

- 5 `missing-zero-check`;
- 1 `tx-origin`;
- 1 `suicidal`;
- 1 `arbitrary-send-eth`;
- 1 `unchecked-lowlevel`.

Comando para mostrar:

```bash
cat runs/20260527_095632_EnterpriseTreasury300/comparison_t1.json
```

## Forgotten Runes

Arquivo:

```text
smart-audt/contracts/real/runes/contracts/ForgottenRunesWarriorsMinter.sol
```

Run:

```text
runs/20260527_105459_ForgottenRunesWarriorsMinter
```

Achados:

- `setVaultAddress(address)` aceitava `address(0)`;
- `setWethAddress(address)` aceitava `address(0)`.

Resultado:

```text
2/2 resolvidos
```

Comando:

```bash
cat runs/20260527_105459_ForgottenRunesWarriorsMinter/comparison_t1.json
```

## Controles Negativos Importantes

### Solmate `WETH.sol`

Run:

```text
runs/20260527_102842_WETH
```

Resultado:

```text
0 candidatos acionaveis
```

Uso na apresentacao:

> O pipeline tambem foi testado contra contrato real conhecido e nao inventou
> patch.

### Escher `FixedPrice.sol`

Run:

```text
runs/20260528_093456_FixedPrice
```

Resultado:

```text
0 candidatos apos ajuste
```

Ponto importante:

O contrato usa `selfdestruct`, mas isso nao era a mesma classe `suicidal` que o
pipeline corrige. O pipeline foi ajustado para nao transformar `selfdestruct`
interno em uma vulnerabilidade falsa chamada `destroy`.

## O Que Rodar Na Hora Da Demo

### Opcao Recomendada: Sem Gastar Groq

Mostrar runs salvos:

```bash
cat runs/20260528_093346_Market/comparison_t1.json
cat runs/20260528_093346_Market/patch_guard_t0.json
sed -n '126,152p' agent/agent_outputs/Market_FIXED.sol
```

Rodar um caso seguro ao vivo:

```bash
python3 agent/main.py --contract smart-audt/contracts/real/caviar/src/PrivatePool.sol
```

Por que esse e seguro:

- ele para na etapa 1;
- nao chama LLM;
- nao gasta Groq;
- mostra contrato real grande compilando.

### Opcao Com Correcao Ao Vivo

Rodar:

```bash
python3 agent/main.py --contract smart-audt/contracts/real/inverse/src/Market.sol
```

Aviso:

- esse caso pode chamar Groq na etapa de planejamento formal;
- use apenas se houver token/chave disponivel;
- para apresentacao, e mais seguro mostrar o run ja salvo.

## Ordem Recomendada Dos Slides

1. Problema: LLM sozinha alucina e pode gerar patch inseguro.
2. Arquitetura: Slither -> LLM -> CVL -> Certora -> patch -> guard -> revalidacao.
3. Guardrails: normalizacao, spec deterministica, patch deterministico,
   `patch_guard`.
4. Resultado controlado: `EnterpriseTreasury300`, 9/9.
5. Resultado real corrigido: Inverse `Market`, 3/3.
6. Resultado real maior sem achado: Caviar `PrivatePool`, 794 linhas, 0
   candidatos.
7. Limites: reentrancia, vulnerabilidades economicas, dependencias externas,
   `tx.origin` semantico.
8. Proximos passos.

## Frases Boas Para A Apresentacao

> O objetivo nao e substituir auditoria humana, mas reduzir trabalho repetitivo
> e criar um ciclo verificavel de hipotese, confirmacao formal, correcao e
> revalidacao.

> O pipeline so corrige depois que uma propriedade e confirmada, e o patch ainda
> passa por um guardrail de minimalidade.

> Casos negativos sao tao importantes quanto os positivos: eles mostram que o
> agente nao esta apenas inventando vulnerabilidades.

> A LLM e usada onde agrega raciocinio, mas padroes mecanicos foram movidos para
> regras deterministicas para economizar tokens e reduzir variancia.

## Arquivos De Relatorio Relacionados

- `docs/pipeline-findings-report-20260528.md`
- `docs/retests/enterprise-treasury300-retest-20260527.md`
- `docs/retests/real-code-forgotten-runes-20260527.md`
- `docs/retests/real-code-inverse-market-20260528.md`
- `docs/retests/real-code-caviar-privatepool-20260528.md`
- `docs/retests/real-code-escher-selfdestruct-triage-20260528.md`
- `docs/retests/real-code-astaria-dependency-blocker-20260528.md`
