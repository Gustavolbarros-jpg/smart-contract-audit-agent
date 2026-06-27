# Certora CVL Cookbook For The Agent

This cookbook is intentionally general. It is not a set of DeFiVault-specific
answers. The agent should use these as reusable shapes, then bind them to the
actual function names, getters, and parameters found in the current contract.

## Ground Rules

- `methods {}` contains declarations only. No function bodies.
- In CVL 2, method entries end with `;`.
- Public Solidity variables are called through generated getters.
- Envfree functions are called without `env`.
- Mutating functions are called with `env e`.
- `lastReverted` must be asserted immediately after the `@withrevert` call.
- Zero address is `0`, not `address(0)`.
- If there is no objective property, skip the rule instead of inventing one.

## Missing Zero Check

Use when a function accepts an address parameter and Slither reports that the
zero address is not rejected.

```cvl
// VULN_XXX - missing-zero-check
rule zero_address_targetFunction {
  env e;
  address x;
  require x == 0;
  targetFunction@withrevert(e, x);
  assert lastReverted;
}
```

Avoid proving that every input reverts. The zero-address precondition is part
of the property.

## Authorization / tx.origin

Use a real owner-only function. Do not test a random public function.

```cvl
// VULN_XXX - tx-origin
rule auth_reverts_when_msg_sender_not_owner {
  env e;
  require e.msg.sender != owner();
  ownerOnlyFunction@withrevert(e);
  assert lastReverted;
}
```

The pipeline may override the chosen function with an actual owner-only probe
such as `pause()`.

## Selfdestruct

Call the Solidity function that reaches `selfdestruct`; do not model
selfdestruct directly.

```cvl
// VULN_XXX - suicidal
rule destroy_reverts_for_non_owner {
  env e;
  require e.msg.sender != owner();
  destroy@withrevert(e);
  assert lastReverted;
}
```

## Arbitrary ETH Send

Use only when the target function and authorization/recipient policy are clear.

```cvl
// VULN_XXX - arbitrary-send-eth
rule unauthorized_recipient_reverts {
  env e;
  address to;
  uint256 amount;
  require e.msg.sender != owner();
  emergencyWithdraw@withrevert(e, to, amount);
  assert lastReverted;
}
```

Do not invent variables such as `authorizedRecipient` unless the contract has
that concept.

## Reentrancy

Reentrancy from Slither is usually a static CEI issue first. Certora can help
only when a clear state property exists.

```cvl
// VULN_XXX - reentrancy-eth
rule state_changes_after_withdraw {
  env e;
  uint256 amount;
  mathint before = balances(e.msg.sender);
  require before >= amount;
  withdraw(e, amount);
  mathint after = balances(e.msg.sender);
  assert after < before;
}
```

Avoid:

- expecting a normal withdraw/claim function to revert just because Slither
  found reentrancy;
- swapping target functions between vulnerability IDs;
- treating a weak revert rule as proof of CEI.

## Timestamp / Block Number

Only formalize if the formal plan gives a real business invariant. Weak rules
for timestamp/block-number can produce misleading confidence.

```cvl
// VULN_XXX - timestamp
rule timestamp_property_example {
  env e;
  // Replace with a contract-specific objective assertion.
  satisfy e.block.timestamp >= 0;
}
```

If this is all the agent can write, the finding should be skipped or sent to
manual/static review.

## Unchecked Low-Level Calls

This is currently a static-confirmed Slither flow, not a generic CVL rule.
Slither reports the ignored return value; the pipeline asks the LLM to patch
the Solidity code and validates the fix by rerunning Slither.

Expected Solidity repair shape:

```solidity
(bool success, ) = target.call{value: amount}("");
require(success, "call failed");
```

If the function has multiple ignored low-level calls, each call must have its
own success variable and `require`.
