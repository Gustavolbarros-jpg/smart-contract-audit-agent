# Evaluation Plan

This file tracks the contracts used to evaluate whether the pipeline
generalizes beyond one hand-tuned example.

## Current Scope

Reentrancy findings are currently preserved as Slither/static-review evidence
but are not sent to Certora. The active formalization scope is:

- `missing-zero-check`
- `tx-origin`
- `suicidal`
- `arbitrary-send-eth` when the target function and policy are clear
- `unchecked-lowlevel` is handled as static-confirmed and validated by rerunning Slither
- `erc2771-multicall-context` is handled as static-confirmed composition evidence

`low-level-calls` is now triaged contextually:

- checked return values stay evidence-only;
- ignored or captured-but-unchecked return values can fall back to `unchecked-lowlevel`.

## CLI

List available local contracts:

```bash
python3 agent/main.py --list-contracts
```

List only the benchmark suite:

```bash
python3 agent/main.py --list-benchmarks
```

Filter by registry group:

```bash
python3 agent/main.py --list-contracts --contract-group exploratory
python3 agent/main.py --list-contracts --contract-group manual
python3 agent/main.py --list-contracts --contract-group scratch
```

List small local contracts:

```bash
python3 agent/main.py --list-contracts --max-lines 45
```

Run one contract without copying the final fixed file back to
`smart-audt/contracts`:

```bash
python3 agent/main.py --contract smart-audt/contracts/SimpleBank.sol
```

Copy the validated fixed contract back only when intentionally desired:

```bash
python3 agent/main.py --contract smart-audt/contracts/SimpleBank.sol --copy-final
```

## Local Test Set

The local test set is now managed by `agent/core/contract_registry.py` and
documented in `docs/benchmark-contracts.md`.

Benchmark group:

- `smart-audt/contracts/SimpleBank.sol`
- `smart-audt/contracts/King.sol`
- `smart-audt/contracts/CrowdfundingVault.sol`
- `smart-audt/contracts/DeFiVault.sol`
- `smart-audt/contracts/ERC2771MulticallVulnerable.sol`

Exploratory group:

- `smart-audt/contracts/TimelockVault.sol`
- `smart-audt/contracts/AnotherVulnerableBank.sol`
- `smart-audt/contracts/VulnerableBankToken.sol`

Manual/corrected examples and scratch files are excluded from default
evaluation unless explicitly selected.

## Solidity 0.8 Evaluation Set

Use Solidity 0.8 contracts already present in this repository before adding
external real-world contracts. This keeps the experiment focused on the current
pipeline toolchain and avoids changing contract syntax just to make a test run.

Suggested order:

1. Run the registry benchmark suite with `python3 agent/evaluate.py`.
2. Include exploratory contracts with `python3 agent/evaluate.py --include-exploratory`.
3. Use exploratory failures or no-actionable results to decide the next general rule.
4. Promote an exploratory contract into `benchmark` only after it has a stable,
   tested vulnerability class and validation flow.

External real contracts should be added only if they compile with the current
Solidity 0.8 toolchain. Do not port old contracts to 0.8 just to make them fit.

## Metrics To Record

For each run, record:

- Slither findings by type.
- Formal candidates selected.
- Findings skipped and why.
- Certora confirmed findings.
- Fixed findings after validation.
- Inconclusive rules.
- Whether the generated spec required deterministic repair.
