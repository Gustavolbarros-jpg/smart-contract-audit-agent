# Session Context

This file is a compact handoff note for resuming the project after context loss.

## Current Goal

Build and refine a self-healing smart-contract audit pipeline that:

- runs Slither;
- normalizes Slither findings into stable vulnerability classes;
- uses an LLM through Groq/OpenAI-compatible API for planning, CVL/spec generation, diagnosis, and repair;
- uses Certora where the property is suitable for formal verification;
- uses deterministic/static validation where Certora is not the right tool;
- repairs confirmed vulnerabilities;
- reruns validation after each patch;
- stores run artifacts for later analysis instead of deleting them.

The user wants generalization across Solidity 0.8 contracts in this repo, not hardcoded fixes for one contract and not syntax/version conversion experiments.

## Repository State

- Working branch: `develop`.
- Main pipeline entrypoint: `python3 agent/main.py --contract <path>`.
- List known contracts: `python3 agent/main.py --list-contracts`.
- List only benchmark contracts: `python3 agent/main.py --list-benchmarks`.
- Filter contracts by registry group: `python3 agent/main.py --list-contracts --contract-group <benchmark|exploratory|manual|scratch>`.
- Evaluation snapshot command: `python3 agent/evaluate.py`.
- Evaluation with exploratory contracts: `python3 agent/evaluate.py --include-exploratory`.
- Evaluation snapshots are now written to `docs/evaluations/evaluation-results-YYYYMMDD_HHMMSS.md`.
- `--output <path>` can still be used to force a specific evaluation output path.

Do not overwrite historical reports by default. Create new Markdown reports/snapshots when documenting new experiments.

## Important User Preferences

- Speak Portuguese with the user.
- Do not focus on reentrancy for now.
- Use Solidity 0.8 contracts already in the repo.
- Do not use old Solidity 0.4/0.7 examples unless the user explicitly changes direction.
- Do not make everything manual. The goal is still an agentic LLM pipeline, but with deterministic guardrails where the decision can be made reliably.
- Avoid deleting files or cleaning aggressively without explicit permission.
- Preserve run artifacts under `runs/` for later analysis.

## Pipeline Architecture

Current intended flow:

1. Toolchain preflight checks Solidity compatibility.
2. Slither runs and writes raw/static evidence.
3. `agent/core/slither_normalizer.py` converts Slither output into a compact vulnerability schema.
4. `agent/core/vulnerability_catalog.py` decides each class strategy:
   - formalizable with Certora;
   - static-confirmed;
   - static/manual review only.
5. `agent/core/formal_candidate.py` filters formal candidates.
6. `agent/core/formal_plan.py` sanitizes LLM formalization plans.
7. `agent/core/spec_patterns.py` provides general CVL examples.
8. `agent/tools/spec_validator.py` repairs common CVL syntax mistakes deterministically.
9. Certora is run for suitable formal properties.
10. Static-confirmed findings are validated by rerunning Slither/static normalization after the fix.
11. The LLM diagnoses confirmed findings and patches the Solidity code.
12. `agent/core/patch_guard.py` checks that the patch is minimal before final validation:
   - blocks modified original string literals;
   - blocks public/external signature changes;
   - blocks removed/renamed state variables;
   - warns about comments or hunks outside the confirmed vulnerability region.
13. If the patch guard blocks:
   - the pipeline first tries deterministic autorepair for obvious unrelated string changes;
   - then it can ask the LLM for a minimal revision with the compact guard report.
14. The pipeline compares original and fixed findings and stores artifacts in `runs/<timestamp>_<Contract>/`.

## LLM Setup

Current code uses Groq through an OpenAI-compatible client:

- file: `agent/llm/client.py`
- base URL: `https://api.groq.com/openai/v1`
- model: `llama-3.3-70b-versatile`

The `.env` loader was made tolerant of malformed lines. Do not print or expose `.env` secrets.

## Strong Current Classes

The pipeline currently works best for:

- `missing-zero-check`
- `tx-origin`
- `suicidal`
- clear `arbitrary-send-eth`
- `unchecked-lowlevel` as static-confirmed Slither flow
- `erc2771-multicall-context` as static-confirmed composition pattern
- `low-level-calls` contextual triage:
  - checked return values stay non-actionable;
  - ignored/unchecked low-level calls can fall back to `unchecked-lowlevel`.

Reentrancy, timestamp/block-number, and `unprotected-critical-update` are preserved
as evidence/static review for now instead of being forced into weak or overly broad
automatic repairs.

## Completed Step-By-Step Work

1. Minimal diff checker:
   - Implemented in `agent/core/patch_guard.py`.
   - Integrated in `agent/orchestrator.py`.
   - Stores `patch_guard_tN.json` artifacts.
   - Supports retry and deterministic string-literal autorepair.
   - Validated on ERC2771: the raw LLM patch changed unrelated revert strings,
     the guard blocked it, autorepair restored the strings, and the clean patch passed.

2. ERC2771 multicall variants:
   - `trustedForwarder` direct variable.
   - `_forwarder` / different forwarder names.
   - `isTrustedForwarder(msg.sender)`.
   - OpenZeppelin-style `ERC2771Context`.
   - Equivalent guards such as `require(!isTrustedForwarder(msg.sender), ...)`.

3. Larger/exploratory Solidity 0.8 run:
   - `VulnerableBankToken` was run.
   - Result: `no_actionable_candidates`.
   - The run remains useful as a negative/control case.

4. Benchmark/manual separation:
   - Implemented in `agent/core/contract_registry.py`.
   - Documented in `docs/benchmark-contracts.md`.
   - Groups: `benchmark`, `exploratory`, `manual`, `scratch`.

5. First additional general rule:
   - `low-level-calls` contextual analysis was improved.
   - Checked calls stay evidence-only.
   - Ignored/captured-but-unchecked calls fall back to `unchecked-lowlevel`.

6. First exploratory source-pattern rule after organizing benchmarks:
   - `unprotected-critical-update` detects public/external writes to critical
     state variables without owner/admin-style authorization.
   - `TimelockVault.extendLock(uint256)` validates this class.
   - Latest run: `runs/20260524_182037_TimelockVault`.
   - Result from the earlier experiment: `1/1` resolved; patch guard accepted the minimal authorization check.
   - Current policy: this class is review-only, not `static_confirmed`, because the
     detector is still name-based and has known false-positive risk.
   - The heuristic was tightened to ignore accumulators such as `feePaid += msg.value`,
     `totalFeesCollected += fee`, and user-scoped mappings such as `userDelay[msg.sender]`.
   - It still preserves review evidence for admin-like setters such as `extendLock`
     and `setProtocolFee` when they lack owner/admin authorization.
   - Latest policy-validation run: `runs/20260524_192853_TimelockVault`.
   - Current result after demotion: `no_actionable_candidates`.

## Recent ERC2771 Work

Problem found:

- `ERC2771MulticallVulnerable.sol` originally produced no useful formal/static-confirmed candidates.
- Slither reported generic pieces:
  - `calls-loop`
  - `low-level-calls`
  - `assembly`
  - `missing-zero-check` in constructor
  - etc.
- The actual security issue is the composition of ERC2771 calldata-suffix sender recovery with `delegatecall`-based `multicall`.

Implemented:

- New catalog type: `erc2771-multicall-context`.
- It is `formalizable=False`, `static_confirmed=True`.
- Repair strategy: `block_forwarded_delegatecall_multicall`.
- Normalizer fallback detects:
  - `trustedForwarder`;
  - `_forwarder` and other forwarder-like variable names;
  - `isTrustedForwarder(msg.sender)`;
  - OpenZeppelin-style `ERC2771Context`;
  - `_msgSender()` / calldata suffix sender recovery;
  - `multicall(bytes[])`;
  - `delegatecall` inside `multicall`;
  - absence of a guard blocking forwarded multicalls.
- Prompt repair playbook tells the LLM to add a minimal guard:
  - `require(msg.sender != trustedForwarder, "forwarded multicall disabled");`

Validation run:

- Latest successful run directory: `runs/20260524_192015_ERC2771MulticallVulnerable`.
- Result: `1/1` resolved.
- The initial LLM patch changed unrelated strings.
- Patch guard blocked it.
- Deterministic autorepair restored the original strings.
- Final patch kept only the ERC2771 guard in `multicall`.
- Evaluation snapshot includes the result:
  - `docs/evaluations/evaluation-results-20260524_192309_614517.md`

Important caveat now handled:

- The LLM correctly added the ERC2771 guard, but also changed unrelated error strings.
- The patch guard now catches this class of mistake before validation.
- Obvious unrelated string edits are restored deterministically.

## Current Evaluation Summary

Current benchmark snapshot includes:

- `SimpleBank`: `4/4`
- `King`: `4/4`
- `CrowdfundingVault`: `4/4`
- `DeFiVault`: `5/5`
- `ERC2771MulticallVulnerable`: `1/1`

Exploratory snapshot also includes:

- `TimelockVault`: `no_actionable_candidates` after `unprotected-critical-update` demotion.
- `VulnerableBankToken`: `no_actionable_candidates`

Current snapshots:

- Core benchmark: `docs/evaluations/evaluation-results-20260524_212448_765961.md`
- Benchmark + exploratory: `docs/evaluations/evaluation-results-20260524_212405_405911.md`

Recent Certora/spec lesson:

- `CrowdfundingVault` previously had invalid `envfree` annotations for
  `createCampaign`, `timeLeft`, and `isSuccessful`.
- The pipeline now removes `envfree` from functions that read restricted
  environment fields such as `msg.sender` or `block.timestamp`.
- Logs with invalid `envfree` now count as blocking spec errors.

Older `docs/evaluation-results.md` may still exist, but new evaluations should be snapshot files.

## Tests

Primary local test command:

```bash
python3 tests/test_certora_learning.py
```

Latest result:

- `51 tests OK`

Also run when editing:

```bash
git diff --check
```

## Key Files

- `agent/main.py`: CLI entrypoint.
- `agent/orchestrator.py`: end-to-end pipeline orchestration.
- `agent/llm/client.py`: Groq/OpenAI-compatible client and `.env` loading.
- `agent/prompts/system_prompts.py`: English LLM prompts.
- `agent/core/vulnerability_catalog.py`: vulnerability class policy.
- `agent/core/contract_registry.py`: benchmark/exploratory/manual/scratch contract grouping.
- `agent/core/patch_guard.py`: minimal-diff patch guard and deterministic patch autorepair.
- `agent/core/slither_normalizer.py`: deterministic Slither normalization and fallbacks.
- `agent/core/static_analysis.py`: static-confirmed support and post-fix analysis.
- `agent/core/formal_candidate.py`: formal candidate filtering.
- `agent/core/formal_plan.py`: formal plan sanitization.
- `agent/core/spec_patterns.py`: general CVL examples.
- `agent/core/contract_context.py`: deterministic contract interface summary and methods block.
- `agent/tools/spec_validator.py`: deterministic CVL repair.
- `agent/evaluate.py`: creates evaluation snapshot reports from the registry-backed default suite.
- `tests/test_certora_learning.py`: regression tests for the pipeline rules.
- `docs/benchmark-contracts.md`: contract grouping and evaluation suite documentation.

## Next Steps

Recommended next steps, in order:

1. Keep the codebase organized around the registry-backed benchmark suite.
2. Avoid adding a contract size limit for now; the goal is still to eventually handle new contracts.
3. Before adding more rules, use the current benchmark/exploratory split to choose the next target deliberately.
4. Add new general vulnerability classes one at a time, with:
   - source/static evidence;
   - repair strategy;
   - post-fix validation;
   - patch guard coverage;
   - tests and, when possible, a validation contract.
5. Candidate future classes, not yet started:
   - unprotected critical parameter update;
   - user-controlled arbitrary external call;
   - signature replay / missing nonce-domain checks;
   - stale oracle or missing freshness checks.
6. Keep creating new evaluation snapshots after meaningful experiments.
