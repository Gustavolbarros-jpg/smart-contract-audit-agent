# Roteiro — Apresentação de 2 minutos + demo

Data: 2026-09-03

O vídeo final é `docs/apresentacao-2min-tela.mp4` (108.5s, **mudo**): 20s de
card de abertura (nome/tema) + 88.5s do pipeline rodando no `DeFiVault.sol`.
Gerado por `python3 docs/gerar_video_demo.py` a partir de dados reais de uma
run salva — não é gravação de tela, é renderizado quadro a quadro
(`docs/_replay_content.py`).

**Como gravar sua narração:** toque o vídeo e fale em cima dele, seguindo os
tempos abaixo (são o instante em que cada trecho aparece na tela — fale um
pouco antes ou durante, não precisa ser cirúrgico). Grave num único take
contínuo do início ao fim do vídeo.

---

## Parte 1 — O que falar, timestamp por timestamp

**[0:00 – 0:20] card de abertura (nome/tema na tela)**

> Olá! Meu nome é Gustavo Ferreira Leite de Barros, sou estudante do Centro
> de Informática da Universidade Federal de Pernambuco. Minha pesquisa
> investiga como tornar contratos inteligentes mais seguros combinando
> inteligência artificial e verificação formal. Em vez de só explicar, vou
> mostrar a ferramenta rodando de verdade em um contrato real.

**[0:21] Slither analisando o DeFiVault.sol**

> Primeiro, o Slither examina o contrato inteiro e aponta os pontos
> suspeitos: controle de acesso, endereços não validados, chamadas externas
> arriscadas.

**[0:30] Seleção dos candidatos formalizáveis**

> Nem todo achado vira correção. Só os que dá pra provar matematicamente
> passam pra próxima etapa — cinco, neste contrato.

**[0:39] Geração da especificação CVL**

> Essas cinco propriedades viram uma especificação formal, na linguagem CVL,
> que o Certora Prover consegue verificar.

**[0:48 – 0:51] Certora entra no contrato original**

> Agora o Certora Prover analisa o contrato original.

**[0:51 – 1:04] As 5 propriedades violadas (FAIL, em vermelho)**

> E aqui está: as cinco propriedades realmente falham. Não é suposição — é
> prova matemática de que o contrato tem essas brechas.

**[1:04 – 1:18] Diagnóstico linha a linha (LLM)**

> Com a violação confirmada, a IA entra: lê a causa raiz de cada uma e
> propõe a correção exata — trocar `tx.origin` por `msg.sender`, validar
> endereço zero, e assim por diante.

**[1:18 – 1:27] patch_guard validando o escopo do patch**

> Antes de aceitar, um guardrail confere se o patch mexeu só no necessário.
> Nada de reescrever o contrato inteiro.

**[1:27 – 1:30] Certora revalida o contrato corrigido**

> O contrato corrigido volta pro Certora.

**[1:30 – 1:40] As 5 propriedades verificadas (VERIFIED, em verde)**

> Dessa vez, as cinco propriedades passam. Verificadas matematicamente, não
> só testadas.

**[1:40 – 1:48] resultado final**

> Cinco de cinco corrigidas, em uma única iteração. Essa é a ferramenta: ela
> gera a correção **e** prova que funciona. Obrigado!

---

## Parte 2 — Gravar e juntar

`docs/apresentacao-2min-tela.mp4` já vem pronto: **108.5s, sem áudio**
(20s de abertura com nome/tema + 88.5s do pipeline rodando no
`DeFiVault.sol`, run `20260524_232148_DeFiVault`, 5/5 vulnerabilidades
corrigidas em 1 iteração). Renderizado quadro a quadro a partir de dados
reais (`docs/_replay_content.py`), não é captura de tela — não depende do
seu desktop nem de rede/LLM/Certora ao vivo.

Passos:

1. Toque `docs/apresentacao-2min-tela.mp4` e grave sua narração à parte
   (celular, app de voz), lendo a [Parte 1](#parte-1--o-que-falar-timestamp-por-timestamp)
   em cima — um único take contínuo do início ao fim do vídeo.
2. Me manda o arquivo de áudio (caminho, se já estiver salvo aqui no
   laptop).
3. Eu junto os dois:
   ```bash
   docs/juntar_video_audio.sh docs/apresentacao-2min-tela.mp4 SEU_AUDIO.m4a final.mp4
   ```
   Se o áudio começar antes/depois do vídeo, me diga quantos segundos de
   diferença que eu ajusto (`juntar_video_audio.sh` aceita um offset).

Pra regerar o vídeo em outro ritmo (a Parte 1 muda de tempos junto, eu
recalculo se pedir):

```bash
python3 docs/gerar_video_demo.py --speed 2 -o docs/apresentacao-2min-tela.mp4   # ~54s
python3 docs/gerar_video_demo.py --speed 0.7 -o docs/apresentacao-2min-tela.mp4 # ~155s
```

### Sem gravar nada — terminal ao vivo

Se for apresentar presencialmente em vez de mandar vídeo gravado:

```bash
python3 docs/demo_replay_defivault.py
```

Mesmo conteúdo, impresso ao vivo no terminal (sem o card de abertura).
Aceita o mesmo `--speed`.

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
