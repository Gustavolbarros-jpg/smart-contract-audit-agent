# Artigos-base — links de download e como retomar a conversa

> **Status: os 3 PDFs já foram baixados** e estão nesta pasta (`3765753.pdf` = CodeXplain,
> `3765751.pdf` = MANDO-LLM, `3764867.pdf` = CCIHunter). A análise dos métodos completos
> está em [`docs/comparativo-abordagem-atual-vs-artigos.md`](../comparativo-abordagem-atual-vs-artigos.md).
> Os links abaixo ficam como referência de origem.

Referente à sessão de **24/07/2026** em que definimos os 3 artigos da **ACM TOSEM** como base
para generalizar o modelo de IA do pipeline. Os PDFs vieram por WhatsApp (foto em `tests/image.png`);
os números dos arquivos (`3765753`, `3765751`, `3764867`) são os DOIs da ACM.

Resumo técnico de cada artigo e o mapeamento para as limitações do pipeline:
[`docs/referencias-generalizacao-modelo.md`](../referencias-generalizacao-modelo.md).

## Links de download (PDF direto)

| # | Artigo | PDF direto | Acesso |
|---|---|---|---|
| 1 | **CodeXplain** — *From Cryptic to Clear: Training on LLM Explanations to Detect Smart Contract Vulnerabilities* | https://dl.acm.org/doi/pdf/10.1145/3765753 | Paywall ACM |
| 2 | **MANDO-LLM** — *Heterogeneous Graph Transformers with LLMs for Smart Contract Vulnerability Detection* | https://dl.acm.org/doi/pdf/10.1145/3765751 | **Aberto (CC-BY)** |
| 3 | **CCIHunter** — *Enhancing Smart Contract Code–Comment Inconsistencies Detection via Two-Stage Pre-Training* | https://dl.acm.org/doi/pdf/10.1145/3764867 | Paywall ACM |

### Páginas dos artigos (com botão "PDF" no topo)

Use estas se o link direto pedir verificação do Cloudflare:

1. CodeXplain — https://dl.acm.org/doi/10.1145/3765753
2. MANDO-LLM — https://dl.acm.org/doi/10.1145/3765751
3. CCIHunter — https://dl.acm.org/doi/10.1145/3764867

### Observações sobre o acesso

- Só o **MANDO-LLM (nº 2)** é gratuito; os outros dois pedem pagamento ou login institucional.
- Se a universidade tiver assinatura da ACM Digital Library, faça login pelo portal da instituição
  ou acesse pela rede/VPN dela — aí o download libera.
- Caminho mais rápido: os 3 PDFs já estão no seu WhatsApp. Abrir o
  [WhatsApp Web](https://web.whatsapp.com) nesta máquina e baixar de lá.
- **Onde salvar:** `docs/referencias/` (esta pasta). Com os PDFs aqui, dá para ler o texto integral
  e aprofundar o documento de generalização — hoje ele foi montado só a partir dos abstracts e
  metadados oficiais (API do Semantic Scholar).

### Código relacionado

- MANDO-Project (MANDO-HGT, versão anterior) — https://github.com/MANDO-Project/ge-sc-transformer

## Como retomar aquela conversa

A sessão é local do Claude Code (não existe URL de chat). Para reabrir **com todo o contexto**:

```bash
cd /home/gflb/TesteCertora
claude --resume d2bce592-6d0d-4241-9632-96a929be8a74
```

Ou `claude --resume` sem argumento para escolher a sessão numa lista.

| Item | Valor |
|---|---|
| Session ID | `d2bce592-6d0d-4241-9632-96a929be8a74` |
| Data | 24/07/2026, 00:26 → 02:04 (UTC) |
| Transcript | `~/.claude/projects/-home-gflb-TesteCertora/d2bce592-6d0d-4241-9632-96a929be8a74.jsonl` |
| Assunto | Identificação dos 3 artigos da foto + estratégia de generalização do modelo |

Sessão imediatamente seguinte (continuação sobre o pipeline, 24/07 02:07):
`claude --resume 33e0a06d-6fb2-4d52-81b3-9ae2dfcc86c3`

> O contexto essencial dessa conversa também está persistido na memória
> (`reference-papers-generalizacao`), então sessões novas já começam sabendo disso —
> o `--resume` só é necessário se você quiser reler a discussão original.
