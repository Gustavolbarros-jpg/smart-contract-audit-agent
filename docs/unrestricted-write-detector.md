# Detector `unrestricted-write`

Custom Slither 0.11.3 detector in `agent/slither_plugins/unrestricted_write.py`, run through
`run_unrestricted_write(contract_path)` in `agent/tools/slither_plugin_runner.py`. It is
registered on a private `Slither` instance only; the global `slither` CLI and the pipeline
(`slither_cli.py`, `slither_normalizer.py`, `orchestrator.py`) are untouched. Wiring it in
is a separate, reviewed step.

Output: Slither JSON detector results (`check = "unrestricted-write"`, `impact = "High"`,
`confidence = "Medium"`, `description`, `elements` with `name`, `type` and
`source_mapping.lines`). Each result has three elements: the function, the state
variable, and the node that writes it. Wrapped as `{"results": {"detectors": [...]}}`, they
go straight into `normalize_slither_json` (covered by a test). That normalizer computes
`line` as the min-max over all elements, so the range starts at the variable's declaration.

## What it flags

A function that meets all five conditions:

1. is `public`/`external`, not `view`/`pure`, not a constructor (`receive`/`fallback` count);
2. has **no caller check** on its path: not in its body, not in its modifiers, and not in
   any internal function they call (followed transitively). A caller check is a
   `require`/`assert`, or an `if` whose branch reverts (or `return`s, but only in the
   function or a modifier). Its condition must do one of three things:
   - compare the caller (`msg.sender`, `tx.origin`, or a value derived from them,
     including through helpers such as `_msgSender()`) with `==`/`!=` against anything
     that is not itself the caller;
   - read a `bool` mapping entry keyed by the caller (`admin[msg.sender]`,
     `roles[R][msg.sender]`);
   - call a `view`/`pure` function returning `bool` with the caller as an argument
     (`isOwner(msg.sender)`, `hasRole(R, msg.sender)`).

   Caller-carrying parameters are tracked across internal calls, so `_check(msg.sender)`
   is recognised inside `_check`. A write inside `if (msg.sender == owner) { ... }` is
   guarded even though the `if` has no revert (decided by CFG dominance);
3. is not **payment-gated**: no guard compares `msg.value` against a state variable
   (`require(msg.value > highestBid)`). In that case the caller buys the write, as in an
   auction or King-of-the-hill;
4. is not **one-shot**: it does not check a `bool` state flag that it sets to a constant
   which no other function ever sets to a different value (the `initialize` latch);
5. **overwrites** (`=`, `delete`, struct assignment) a **privileged** state variable,
   at a location not keyed by the caller. Writes through mappings, struct fields and
   storage pointers (`Proposal storage p = proposals[id]; p.executed = true`) are
   resolved to the underlying state variable.

## How "privileged" is decided

No variable or modifier name is used anywhere in the decision, not even as a tie-break.
A state variable is privileged if the contract itself treats it as such in one of three ways:

| reason in the description | rule |
|---|---|
| `compared against the caller` | **authority**: the non-caller side of a caller comparison reads it as a whole value (not a mapping/array element), or it is a mapping whose caller-keyed `bool` entry gates execution. A deny-list (`require(!blocked[msg.sender])`) also counts, but passing it does not count as a caller check. |
| `receives ether` | **fund sink**: a whole-value state variable that is the destination of `transfer`, `send`, or a low-level `call` with value. |
| `otherwise written only by caller-guarded functions or the constructor` | **admin-set**: at least one *other* writer exists, and every other writer (non-caller-keyed writes) is a constructor, a caller-checked function, or writes inside a caller-guarded branch. |

The third rule is what makes a missing `onlyOwner` on `setRewardRate(uint)` detectable:
`rewardRate` is never compared to anyone, but the constructor is its only other writer.

## What it deliberately does not flag

- **Writes keyed by the caller**: `balances[msg.sender] = x`, `whitelist[msg.sender] = true`
  (self-registration). The caller can only change its own entry.
- **Read-modify-write updates**: `total += x`, `x = x + 1`, `counter++`. (`arr.push(v)` is *not* one of them: an
  append fills a new slot, so an unguarded push onto an admin-maintained array is reported.)
  Accumulators are shared by user flows and admin flows (`feesAccumulated` is written by
  `deposit` and reset by `collectFees`), and counting them caused false positives on
  every deposit function.
- **Functions that write no state**: an unguarded `selfdestruct`, ether transfer, or
  arbitrary call. Slither's own `suicidal`, `arbitrary-send-eth` and
  `controlled-delegatecall` cover those.
- **Membership gates removed from user functions**: `onlyWhitelisted`/`onlyRegistered` on
  `deposit`/`withdraw`. Those functions write only caller-keyed entries and accumulators,
  so dropping the gate is an authorization bug but not a write to privileged state.
- **`view`/`pure` functions** and **constructors**.

## Known false-negative shapes

1. Read-modify-write on privileged or per-user state: an unguarded
   `creditReward(user, amount) { rewardCredits[user] += amount; }`, an unguarded
   `mint(user, amount) { balances[user] += amount; }`
   (`ERC2771MulticallVulnerable.mint`, which is never reported), and
   `approveProposal { p.approvals += 1; }`.
2. Self-grant of a role: `function becomeAdmin() { admins[msg.sender] = true; }` is
   caller-keyed, so it is not reported.
3. Any caller check counts as protection, however weak the role: a function gated only by
   `onlyWhitelisted` (a role anyone can join) that overwrites `owner` is not reported.
   `tx.origin == owner` also counts as a check (Slither's `tx-origin` reports that weakness).
4. Existence, not dominance, for `require`: a caller `require` that sits after the write,
   or on another branch, still counts as protection.
5. A privileged variable with no other writer, never compared to the caller and never
   sent ether: `function setX(uint v) external { x = v; }` where only `setX` writes `x`.
   Nothing in the contract says `x` is privileged.
6. A one-shot latch over any non-`bool` flag (for example OpenZeppelin `Initializable`'s
   `uint8 _initialized`) is not recognised, so the function is analysed as an ordinary
   one. This is untested here because no OpenZeppelin sources are available offline, and
   it can also produce a false positive (FP 2).
7. The payment gate accepts any `msg.value` vs state comparison, so a takeover behind a
   token payment (`require(msg.value >= fee)`) is not reported.
8. ERC20-style sinks (`token.transfer(feeCollector, x)`) do not make `feeCollector` a
   fund sink; only native ether transfers do.
9. Library calls with storage parameters, and inline assembly writes (`sstore`), are not
   resolved to a state variable.

## Known false-positive shapes

1. An unguarded function that legitimately overwrites a variable an admin function also
   overwrites (a public "poke" that resets a timestamp also set by an admin).
2. An `initialize()` latched by a non-`bool` flag or by a modifier that writes the flag
   with a non-constant value (see FN 6).
3. A variable that the contract treats as privileged but that has no effect (it is never
   read). `TimelockVault.extendLock` overwrites the constructor-set `unlockTime` for any
   caller, but no function reads `unlockTime`. It is reported, and it is a real
   unrestricted write; whether it matters depends on off-chain readers.
Reentrancy locks are not false positives. Writes made inside modifiers are excluded from
the function's writes, and a variable that one function sets to two different constants
(`locked = true; ...; locked = false` in the body) is treated as transient. The
`BodyLock.sol` fixture pins this.

## Measured results (2026-11-04, Slither 0.11.3, solc 0.8.26)

Reproduce with `python3 -m pytest -q tests/test_unrestricted_write.py`, which runs about
70 s and compiles every fixture and mutant.

**Fixtures** (`tests/fixtures/unrestricted_write/`, 13 contracts): 5/5 positive functions
flagged; 0 of 33 negative entry points flagged. Constructors are excluded from the count.
Every exemption is load-bearing: disabling the caller check, the payment gate, the
one-shot latch or the guarded-branch rule makes the corresponding negative fixture report
a finding.

**Mutation (`mutate_md`, unlimited, all 19 top-level `smart-audt/contracts/*.sol`)**:
80 distinct mutants. One duplicate was dropped: in `EnterpriseTreasury300`, "removed from
`_depositFor`" edits `depositFor`'s header, because `mutate_md` locates a function by the
first occurrence of its name. The touched function is identified by the mutated line,
not by the description.

| subset | flagged |
|---|---|
| all MD mutants | 38/80 |
| removed modifier checks the caller (`msg.sender`/`tx.origin` in its body) | 38/58 |
| … and the touched function writes state (Slither `all_state_variables_written`) | 38/50 |

The misses in the last row:

- 10 are membership gates removed from user functions (`onlyWhitelisted` on
  `DeFiVault{,_FIXED}.deposit/withdraw/claimReward`, `onlyRegistered` on
  `SimpleBank{,_FIXED}.deposit/withdraw`). These are deliberately out of scope (see above).
- 2 are read-modify-write false negatives (FN 1): `EnterpriseTreasury300.creditReward`
  and `approveProposal`.

The other rows add the non-access modifiers (`notPaused`, `whenNotPaused`, `notFrozen`,
`nonReentrant`, and `whenNotLocked` on view functions) and the access-modifier removals on
functions that write no state (`emergencyWithdraw`, `destroy`, `claimPrize`,
`sweepTreasury`, `notifyPartner`, `destroyTreasury`). No mutant produced a finding on any
function other than the touched one.

**Originals**: 1 finding across 112 public/external state-mutating functions in the 18
contracts that compile: `TimelockVault.extendLock` (see FP 3). All 13 originals that
`mutate_md` mutates have zero findings. `TreasuryVault.sol` does not compile with any solc (a
stray `x` after the closing brace, `TreasuryVault.sol:20`), so it is reported as a
`SlitherRunError` and skipped.

`tests/test_unrestricted_write.py` pins all of this: the exact flagged set per fixture,
the exact set of touched functions flagged per mutated contract, zero findings on every
mutated contract's original, and the `TimelockVault` finding.
