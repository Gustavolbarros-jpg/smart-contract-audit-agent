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

Validated on this one pair only, not on a real project contract.
