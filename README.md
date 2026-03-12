# Smart Contract Security Audit Pipeline
### Automated Formal Verification for Gas Optimization Safety

> **Iniciação Científica — CIn/UFPE**  
> Abordagem Experimental para Comprovação de Otimização de Gás em Contratos Inteligentes Solidity

---

## Authors

| Name | ORCID | Contact |
|------|-------|---------|
| Gustavo Ferreira Leite de Barros | — | gustavo.lbarros1@gmail.com |
| Alexandre Cabral Mota | [0000-0003-4416-8123](https://orcid.org/0000-0003-4416-8123) | acm@cin.ufpe.br |
| Juliano Manabu Iyoda | [0000-0001-7137-8287](https://orcid.org/0000-0001-7137-8287) | jmi@cin.ufpe.br |

---

## Overview

This repository contains the artifacts from the research project
**"Automated Formal Verification for Gas Optimization Safety in Solidity Smart Contracts"**,
developed at the Centro de Informática (CIn) — Universidade Federal de Pernambuco (UFPE).

The core contribution is an **autonomous 5-stage pipeline** that combines static analysis,
formal verification, and LLM orchestration to:

1. Detect security vulnerabilities in Solidity contracts (via Slither)
2. Generate formal CVL specifications automatically (via LLM)
3. Verify those properties mathematically (via Certora Prover)
4. Diagnose root causes of violations with structured output
5. Generate and validate corrected contracts in a self-healing loop

The pipeline guarantees that **gas optimization refactorings preserve the original contract semantics** —
a contract that fails formal verification is not a valid candidate for gas optimization.

---

## Artifact Structure

```
.
├── agent/                        # Main pipeline source code
│   ├── orchestrator.py           # Main entry point — runs the full pipeline
│   ├── tools/
│   │   ├── slither_cli.py        # Slither integration + JSON normalization
│   │   └── certora_cli.py        # Certora Prover integration
│   ├── llm/
│   │   ├── client.py             # Groq API client (Llama 3.3 70B)
│   │   └── schemas.py            # Pydantic schemas for structured LLM output
│   └── prompts/
│       └── system_prompts.py     # All system prompts used in the pipeline
│
├── smart-audt/
│   └── contracts/
│       ├── DeFiVault.sol         # Original contract (case study)
│       └── DeFiVault_FIXED.sol   # Auto-corrected contract (pipeline output)
│
├── TesteCertora/
│   └── specs/
│       └── DeFiVault.spec        # CVL specification (manually validated)
│
├── agent_outputs/                # Generated at runtime (not committed)
│   ├── etapa1_vulns.json         # Normalized Slither output
│   ├── DeFiVault.spec            # Generated CVL spec
│   ├── certora_original_log.txt  # Certora log for original contract
│   ├── etapa4_analise.json       # Vulnerability analysis (confirmed/not_confirmed)
│   ├── diagnostico_t0.json       # Root cause diagnosis
│   ├── certora_fix_log_t1.txt    # Certora log for corrected contract
│   └── comparacao_t1.json        # Before/after comparison
│
└── README.md
```

---

## Requirements

### 1. Python 3.10+

```bash
python3 --version
```

### 2. Slither

```bash
pip install slither-analyzer
slither --version
```

### 3. Certora Prover CLI 8.1.1

```bash
pip install certora-cli==8.1.1
certoraRun --version
```

> Certora requires a valid license key set as environment variable:
> ```bash
> export CERTORAKEY="your_key_here"
> ```

### 4. Solidity Compiler (solc 0.8.21)

```bash
pip install solc-select
solc-select install 0.8.21
solc-select use 0.8.21
```

### 5. Groq API Key (LLM)

```bash
export GROQ_API_KEY="your_groq_key_here"
```

> Free API key available at: https://console.groq.com

### 6. Install Python dependencies

```bash
cd agent/
pip install -r requirements.txt
```

---

## Running the Pipeline

```bash
cd agent/
export GROQ_API_KEY="your_key"
export CERTORAKEY="your_key"

python3 orchestrator.py
```

The pipeline will:

1. **Stage 1** — Run Slither on `DeFiVault.sol` and normalize output to `etapa1_vulns.json`
2. **Stage 3** — Load the validated CVL spec from `TesteCertora/specs/DeFiVault.spec`
3. **Certora (original)** — Verify original contract and save log
4. **Stage 4** — Analyze Certora log; classify each vulnerability as `confirmed`, `confirmed_static`, `not_confirmed`, or `inconclusive`
5. **Stage 5** — Generate structured diagnosis and corrected contract `DeFiVault_FIXED.sol`
6. **Stage 6 (loop, up to 3x)** — Re-run Certora on corrected contract; compare results; re-diagnose if violations persist

Expected final output:

```
✅ Pipeline concluído.
   Contrato corrigido: ../smart-audt/contracts/DeFiVault_FIXED.sol
   Vulnerabilidades resolvidas: VULN_003, VULN_004, VULN_011, VULN_012, VULN_013
```

---

## Case Study Results

Contract analyzed: **DeFiVault.sol** (190 lines, Solidity ^0.8.21)

| ID | Type | Function | Certora Rule | Status | Counterexample |
|----|------|----------|-------------|--------|----------------|
| VULN_003 | `missing-zero-check` | `transferOwnership` | `zero_check_transferOwnership` | ✅ Resolved | `to = 0x0` |
| VULN_004 | `missing-zero-check` | `emergencyWithdraw` | `zero_check_emergencyWithdraw` | ✅ Resolved | `to = 0x0` |
| VULN_011 | `tx-origin` | `onlyOwner` | `tx_origin_onlyOwner` | ✅ Resolved | `tx.origin = DeFiVault` |
| VULN_012 | `suicidal` | `destroy` | `suicidal_destroy` | ✅ Resolved | `tx.origin = DeFiVault` |
| VULN_013 | `arbitrary-send-eth` | `emergencyWithdraw` | `arbitrary_send_eth` | ✅ Resolved | `to = DeFiVault` |

All 5 violations confirmed on original contract → all 5 resolved in `DeFiVault_FIXED.sol` (1 self-healing iteration).

---

## Pipeline Architecture

```
DeFiVault.sol
      │
      ▼
┌─────────────┐     JSON normalizado
│   Slither   │ ──────────────────────► etapa1_vulns.json
└─────────────┘     (~60% menos tokens via pre-processing)
      │
      ▼
┌─────────────────┐
│  CVL Spec load  │ ◄── DeFiVault.spec (validado manualmente)
└─────────────────┘
      │
      ▼
┌──────────────────┐    log + contraexemplos
│  Certora Prover  │ ──────────────────────► certora_original_log.txt
└──────────────────┘
      │
      ▼
┌──────────────────────┐
│  LLM Analysis        │   confirmed / confirmed_static
│  (Llama 3.3 70B)     │   not_confirmed / inconclusive
└──────────────────────┘
      │
      ▼
┌──────────────────────┐    root cause + exact line + fix
│  LLM Diagnosis       │ ──────────────────────────────► diagnostico_t0.json
└──────────────────────┘
      │
      ▼
┌──────────────────────┐
│  DeFiVault_FIXED.sol │ ◄── minimal corrections only
└──────────────────────┘
      │
      ▼
┌─────────────────────────────────────────┐
│  Self-Healing Loop (up to 3 iterations) │
│  Certora → Compare → Re-diagnose        │
└─────────────────────────────────────────┘
      │
      ▼
   RESOLVED / PERSISTENT / INCONCLUSIVE
```

---

## Important Notes

- **CVL spec is fixed** — the spec is loaded from `TesteCertora/specs/DeFiVault.spec` (manually validated). LLM-generated specs had syntax errors; the fixed spec approach ensures reliable verification.
- **Solidity strings must be ASCII only** — non-ASCII characters in `require()` messages cause Certora compilation errors.
- **`contract_name_override`** — `certora_cli.py` accepts an override for the internal contract name when the filename differs (e.g., `DeFiVault_FIXED.sol` contains contract `DeFiVault`).

---

## Related Work

This pipeline is developed in the context of the research on gas optimization correctness by Villarim et al.:

> Manoel Felipe Araújo Villarim, Juliano Manabu Iyoda, Márcio Lopes Cornélio, Alexandre Cabral Mota.
> *"Ensuring Gas Optimisation Correctness by Behavioral Equivalence"*
> CIn — UFPE.

---

## License

Academic research artifact — CIn/UFPE, 2025–2026.