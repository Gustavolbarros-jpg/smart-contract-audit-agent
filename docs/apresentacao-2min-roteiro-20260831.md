# Roteiro — Apresentação de 2 minutos + demo

Data: 2026-09-03

O vídeo final tem duas partes que viram **arquivos separados** e só se
juntam no fim:

1. **Abertura** — você, de câmera (webcam/celular), falando a introdução.
   Não tem timestamp: é uma tomada sua, do seu jeito, quantos segundos
   precisar.
2. **Demo** — `docs/apresentacao-2min-tela.mp4` (88.5s, **mudo**), o
   pipeline rodando no `DeFiVault.sol`. Renderizado quadro a quadro a
   partir de dados reais (`docs/_replay_content.py`), não é gravação de
   tela. Você narra por cima (áudio só, sem câmera) seguindo os timestamps
   abaixo — pode ser um take contínuo ou em pedaços, ver Parte 2.

---

## Parte 1 — O que falar

### Abertura (sua câmera, sem timestamp)

> Olá! Meu nome é Gustavo Ferreira Leite de Barros, sou estudante do Centro
> de Informática da Universidade Federal de Pernambuco. Minha pesquisa
> investiga como tornar contratos inteligentes mais seguros combinando
> inteligência artificial e verificação formal. Em vez de só explicar, vou
> mostrar a ferramenta rodando de verdade em um contrato real.

### Demo — narração em cima de `apresentacao-2min-tela.mp4` (88.5s)

**[0:01.5] Slither analisando o DeFiVault.sol**

> Primeiro, o Slither examina o contrato inteiro e aponta os pontos
> suspeitos: controle de acesso, endereços não validados, chamadas externas
> arriscadas.

**[0:10.5] Seleção dos candidatos formalizáveis**

> Nem todo achado vira correção. Só os que dá pra provar matematicamente
> passam pra próxima etapa — cinco, neste contrato.

**[0:19.5] Geração da especificação CVL**

> Essas cinco propriedades viram uma especificação formal, na linguagem CVL,
> que o Certora Prover consegue verificar.

**[0:28.5 – 0:31.5] Certora entra no contrato original**

> Agora o Certora Prover analisa o contrato original.

**[0:31.5 – 0:44.5] As 5 propriedades violadas (FAIL, em vermelho)**

> E aqui está: as cinco propriedades realmente falham. Não é suposição — é
> prova matemática de que o contrato tem essas brechas.

**[0:44.5 – 0:58.5] Diagnóstico linha a linha (LLM)**

> Com a violação confirmada, a IA entra: lê a causa raiz de cada uma e
> propõe a correção exata — trocar `tx.origin` por `msg.sender`, validar
> endereço zero, e assim por diante.

**[0:58.5 – 1:07.5] patch_guard validando o escopo do patch**

> Antes de aceitar, um guardrail confere se o patch mexeu só no necessário.
> Nada de reescrever o contrato inteiro.

**[1:07.5 – 1:10.5] Certora revalida o contrato corrigido**

> O contrato corrigido volta pro Certora.

**[1:10.5 – 1:20.5] As 5 propriedades verificadas (VERIFIED, em verde)**

> Dessa vez, as cinco propriedades passam. Verificadas matematicamente, não
> só testadas.

**[1:20.5 – 1:28.5] resultado final**

> Cinco de cinco corrigidas, em uma única iteração. Essa é a ferramenta: ela
> gera a correção **e** prova que funciona. Obrigado!

---

## Parte 2 — Gravar e juntar (3 passos)

**1. Grave a narração da demo** — um único áudio contínuo assistindo
`docs/apresentacao-2min-tela.mp4` tocar, OU 10 áudios curtos (um por
trecho da Parte 1) — como preferir, os dois têm script pronto:

```bash
# opção A: um audio so, contínuo
docs/juntar_video_audio.sh docs/apresentacao-2min-tela.mp4 SEU_AUDIO.m4a demo_com_audio.mp4

# opção B: 10 audios curtos, cada um no timestamp certo (Parte 1: Slither..Fechamento)
python3 docs/juntar_partes_audio.py --intro-seconds 0 \
    parte1.m4a parte2.m4a parte3.m4a parte4.m4a parte5.m4a \
    parte6.m4a parte7.m4a parte8.m4a parte9.m4a parte10.m4a \
    -o demo_com_audio.mp4
```

**2. Grave a abertura** — você de câmera (webcam/celular), falando a
introdução da Parte 1. Vira 1 arquivo de vídeo só, com o áudio já dentro.

**3. Me manda os dois arquivos** (o de câmera + o `demo_com_audio.mp4`,
ou os arquivos de áudio soltos se preferir eu rodar o passo 1) e eu junto
tudo:

```bash
python3 docs/juntar_abertura_camera.py SUA_ABERTURA.mp4 demo_com_audio.mp4 -o final.mp4
```

Esse script normaliza resolução/fps automaticamente — não importa se sua
câmera grava vertical, em outra resolução, etc.

Pra regerar o vídeo da demo em outro ritmo (a Parte 1 muda de tempos
junto, eu recalculo se pedir):

```bash
python3 docs/gerar_video_demo.py --intro-seconds 0 --speed 2 -o docs/apresentacao-2min-tela.mp4   # ~44s
python3 docs/gerar_video_demo.py --intro-seconds 0 --speed 0.7 -o docs/apresentacao-2min-tela.mp4 # ~126s
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
