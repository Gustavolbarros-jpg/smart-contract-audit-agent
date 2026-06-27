# Evaluation Results

Generated from the latest available run artifact for each selected contract.

| Contract | Latest run | Status | Findings | Selected | Confirmed | Resolved | Rate | Notes |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
| SimpleBank | `20260523_153927_SimpleBank` | passed | 12 | 4 | 4 | 4 | 4/4 | missing-zero-check, tx-origin |
| King | `20260523_161639_King` | passed | 9 | 4 | 4 | 4 | 4/4 | arbitrary-send-eth, missing-zero-check, tx-origin |
| CrowdfundingVault | `20260524_150940_CrowdfundingVault` | passed | 16 | 4 | 4 | 4 | 4/4 | tx-origin, unchecked-lowlevel |
| DeFiVault | `20260523_163319_DeFiVault` | passed | 19 | 5 | 5 | 5 | 5/5 | arbitrary-send-eth, missing-zero-check, suicidal, tx-origin |
| ERC2771MulticallVulnerable | `20260524_163845_ERC2771MulticallVulnerable` | passed | 8 | 1 | 1 | 1 | 1/1 | erc2771-multicall-context |
| TimelockVault | `20260524_182037_TimelockVault` | passed | 2 | 1 | 1 | 1 | 1/1 | unprotected-critical-update |
| AnotherVulnerableBank | `20260524_184219_AnotherVulnerableBank` | no_actionable_candidates | 2 | 0 | 0 | 0 |  |  |
| VulnerableBankToken | `20260524_171859_VulnerableBankToken` | no_actionable_candidates | 3 | 0 | 0 | 0 |  |  |

## Current Interpretation

The pipeline is currently strongest for `missing-zero-check`, `tx-origin`, `suicidal`, and clear `arbitrary-send-eth` cases. Reentrancy and timestamp/block-number findings are preserved as static-review evidence instead of being sent to Certora. `unchecked-lowlevel` is handled as a static-confirmed Slither flow and validated by rerunning Slither. `erc2771-multicall-context` is now handled as a static-confirmed composition pattern because Slither reports only the low-level pieces. `unprotected-critical-update` remains exploratory/static-review until its name-based heuristic has stronger negative coverage.
