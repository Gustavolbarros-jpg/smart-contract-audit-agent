# arbitrary-send-erc20: Certora check of the CVL pattern

`Vault.sol` lets the caller choose the `from` of `token.transferFrom`; `VaultFixed.sol` pulls from
`msg.sender`. `erc20_ghost.spec` is the pattern in `agent/core/spec_patterns.py`: it summarizes
`transferFrom` so no token contract or `--link` is needed, which is how the pipeline runs Certora.

```
SOLC_VERSION=0.8.20 certoraRun Vault.sol:Vault --verify Vault:erc20_ghost.spec
SOLC_VERSION=0.8.20 certoraRun VaultFixed.sol:VaultFixed --verify VaultFixed:erc20_ghost.spec
```

Result when the pattern was promoted (certora-cli 8.1.1, Prover run locally):

| contract | rule | non-vacuity (`rule_not_vacuous`) |
|---|---|---|
| Vault | Violated (counterexample found) | n/a |
| VaultFixed | Not violated (verified) | Not violated, sat (a witness exists) |

A truly vacuous rule shows `rule_not_vacuous | Violated | (unsat)` instead; that was checked with a
deliberately contradictory rule. The Prover's closing "Failures summary" also names
`rule_not_vacuous` for `VaultFixed`; the table above is what was relied on, and the banner was not
explained.

## Check on real contracts: not promoted

The 7 `arbitrary-send-erc20` findings in the real projects (3 files) were read by hand. None is a
clear vulnerability: `astaria/TransferProxy.tokenTransferFrom` is guarded by `requiresAuth`;
`maia/FlywheelCore.claimRewards` and `setFlywheelRewards` pull from the rewards contract, the second
one `onlyOwner`; `maia/BranchPort.bridgeOut` and `bridgeOutMultiple` are `requiresBridgeAgent`. All
seven use `safeTransferFrom`, which the `_.transferFrom` summary does not intercept. This rule says
"the source must be the caller", which these designs violate on purpose, so it would raise alarms on
correct code. The catalog entry therefore keeps `formalizable: False`. The Certora run on the real
files was not made: the conclusion follows from the code and from the summary not matching the call.
