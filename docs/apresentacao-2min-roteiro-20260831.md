# Roteiro — Apresentação de 2 minutos + demo

Data: 2026-08-31
Slides: `docs/apresentacao-2min-slides.pdf` (gerado por `docs/gerar_slides_apresentacao.py`)

---

## Parte 1 — Fala (≈ 2 min, ritmo de ~160 palavras/min)

Marcações de tempo são um guia para não perder o ritmo, não para decorar.
Troque de slide no colchete `[slide N]`.

**[0:00] [slide 1 — título]**

> Olá! Meu nome é Gustavo Ferreira Leite de Barros, sou estudante do Centro de
> Informática da Universidade Federal de Pernambuco, e esta pesquisa investiga
> como tornar contratos inteligentes mais seguros utilizando inteligência
> artificial e verificação formal.

**[0:15] [slide 2 — o problema]**

> Contratos inteligentes são programas executados em uma blockchain. Eles
> permitem automatizar transferências financeiras e outros serviços digitais
> sem depender de uma instituição intermediária. Porém, uma falha em seu
> código pode ser explorada, provocando ataques e prejuízos financeiros.

**[0:30]**

> Outro desafio é o gás, que representa o custo de execução das operações na
> blockchain. Desenvolvedores procuram otimizar seus contratos para reduzir
> esse custo, mas uma alteração no código pode modificar o comportamento
> original ou introduzir novas vulnerabilidades.

**[0:45] [slide 3 — a pipeline]**

> Para enfrentar esse problema, desenvolvemos uma pipeline automática de
> análise e correção.

**[0:50] [slide 4 — detecção]**

> Primeiro, utilizamos o Slither para examinar o código e detectar possíveis
> vulnerabilidades. Depois, um modelo de inteligência artificial interpreta os
> resultados, identifica os problemas relevantes e auxilia na criação de
> propriedades de segurança.

**[1:00] [slide 5 — verificação formal]**

> Essas propriedades são analisadas pelo Certora Prover, uma ferramenta de
> verificação formal. Diferentemente de testes tradicionais, que avaliam
> apenas alguns exemplos, a verificação formal procura analisar
> matematicamente os possíveis comportamentos do contrato.

**[1:15]**

> Quando uma propriedade é violada, a ferramenta apresenta um contraexemplo.
> Com essa informação, a inteligência artificial diagnostica a causa da falha
> e produz uma versão corrigida do código.

**[1:25] [slide 6 — ciclo de correção]**

> A correção não é aceita imediatamente. O novo contrato passa novamente
> pelas ferramentas de análise e verificação. Se o problema permanecer, o
> sistema realiza outra tentativa, formando um ciclo automático de correção e
> validação.

**[1:35] [slide 7 — estudo de caso]**

> Como estudo de caso, utilizamos o DeFiVault, um contrato que simula um
> cofre de finanças descentralizadas. A pipeline identificou e corrigiu
> problemas de controle de acesso, endereços inválidos, transferências
> inseguras e risco de reentrância.

**[1:50] [slide 8 — resultado / slide 9 — fechamento]**

> O diferencial da pesquisa é combinar a capacidade de geração da
> inteligência artificial com as evidências da verificação formal, buscando
> tornar a auditoria de contratos inteligentes mais automática, segura e
> confiável.

**[2:00]**

> Obrigado!

---

## Parte 2 — Contrato "rodando" em paralelo, enquanto você fala

### Opção A — gravar um vídeo final (voz + tela juntas)

`docs/apresentacao-2min-tela.mp4` já vem pronto: 88.5s, sem áudio, mostrando
uma execução **real e já validada** do pipeline sobre o `DeFiVault.sol` (run
`20260524_232148_DeFiVault`, 5/5 vulnerabilidades corrigidas em 1 iteração) —
Slither encontrando os achados, seleção dos candidatos formalizáveis, geração
da spec CVL, o Certora **violando** as 5 propriedades no original, o
diagnóstico linha a linha, o `patch_guard` validando o patch, e o Certora
**verificando** tudo no contrato corrigido. Foi renderizado quadro a quadro a
partir dos dados reais (`docs/_replay_content.py`), não é uma captura de
tela — por isso não depende do seu desktop nem de rede/LLM/Certora ao vivo.

Passos:

1. Regrave sua narração separada (celular, app de voz) assistindo o vídeo
   tocando, seguindo a [Parte 1](#parte-1--fala-2-min-ritmo-de-160-palavrasmin)
   ou a cola solta em `docs/apresentacao-2min-cola.md`.
2. Me manda o caminho do arquivo de áudio.
3. Eu junto os dois:
   ```bash
   docs/juntar_video_audio.sh docs/apresentacao-2min-tela.mp4 SEU_AUDIO.m4a final.mp4
   ```
   Se o áudio começar antes/depois do vídeo, me diga quantos segundos de
   diferença que eu ajusto (`juntar_video_audio.sh` aceita um offset).

Para regerar o vídeo em outro ritmo:

```bash
python3 docs/gerar_video_demo.py --speed 2 -o docs/apresentacao-2min-tela.mp4   # ~44s
python3 docs/gerar_video_demo.py --speed 0.7 -o docs/apresentacao-2min-tela.mp4 # ~126s
```

### Opção B — terminal ao vivo, sem gravar nada

Abra um segundo terminal (ou divida a tela: slides de um lado, terminal do
outro) e, junto com a introdução, dispare:

```bash
python3 docs/demo_replay_defivault.py
```

Mesmo conteúdo do vídeo, mas impresso ao vivo no terminal em vez de
renderizado — útil se for apresentar presencialmente sem gravação. Aceita o
mesmo `--speed`.

---

## Parte 3 — Demo sequencial, se sobrar tempo depois da fala

**Não rode o pipeline completo ao vivo.** Sem `GROQ_API_KEY` real e com
`CERTORAKEY` ainda no placeholder (`minha-chave`), uma chamada real ao LLM ou
ao Certora Prover falha ou trava a demo. Use artefatos já validados e
salvos em `runs/` — é determinístico, rápido e não depende de rede.

### 1. Mostrar o contrato pequeno (o que a plateia vai auditar)

```bash
cat smart-audt/contracts/SimpleBank.sol
```

125 linhas, com 5 vulnerabilidades propositais já comentadas no código
(`VULN_001` a `VULN_005`) — reentrância, dois `missing-zero-check`,
`tx-origin` e `arbitrary-send-eth`. Boa para ler na tela em segundos.

### 2. Mostrar o Slither rodando de verdade (rápido, sem rede)

```bash
cd agent && python3 -c "
from tools.slither_cli import run_slither_raw
import json
r = run_slither_raw('../smart-audt/contracts/SimpleBank.sol')
print(len(r['results']['detectors']), 'achados brutos do Slither')
"
```

Isso executa o Slither de verdade sobre o contrato na hora — mostra a
ferramenta "funcionando" sem depender de LLM nem de Certora.

### 3. Mostrar o resultado já validado do pipeline completo (DeFiVault)

```bash
cat runs/20260524_232148_DeFiVault/comparison_t1.json
```

Saída: 5 vulnerabilidades confirmadas → 5 corrigidas, em 1 iteração.

### 4. Mostrar o patch aplicado (antes/depois, minimalista)

```bash
diff -u smart-audt/contracts/DeFiVault.sol \
        smart-audt/contracts/DeFiVault_FIXED.sol | grep -A2 -B2 FIX
```

Mostra as linhas exatas que a pipeline inseriu — `require` de endereço zero,
`msg.sender` no lugar de `tx.origin`, reordenação checks-effects-interactions
em `withdraw`/`claimReward`. Nada além disso foi tocado no contrato.

### Se sobrar tempo e houver credenciais válidas

```bash
python3 agent/main.py --contract smart-audt/contracts/SimpleBank.sol
```

Roda o ciclo completo ao vivo (Slither → LLM → CVL → Certora → diagnóstico →
correção → revalidação). Só tente isso com `GROQ_API_KEY` e `CERTORAKEY`
reais exportados — confirme com um teste antes da apresentação, não na hora.

---

## Frases de apoio (se a plateia perguntar)

- **"A IA corrige sozinha?"** — Não. O LLM só corrige depois que o Certora
  confirma matematicamente que a propriedade foi violada, e o patch passa por
  um `patch_guard` que rejeita edições fora do escopo da vulnerabilidade.
- **"E se o contrato for grande e não tiver vulnerabilidade conhecida?"** — O
  pipeline para na primeira etapa e não inventa achado; isso já foi testado
  em contratos reais de centenas de linhas (ex. Caviar `PrivatePool.sol`,
  794 linhas, 0 candidatos, 0 chamadas ao LLM).
- **"Por que não só usar a LLM direto no contrato?"** — Porque LLM sozinha
  alucina. A verificação formal é o que torna a correção verificável, não só
  plausível.
