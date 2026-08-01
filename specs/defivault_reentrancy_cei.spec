/*
 * Checks-Effects-Interactions as a verifiable property — DRAFT, NOT YET VALIDATED.
 *
 * Written for smart-audt/contracts/DeFiVault.sol. Cannot be run in the current
 * environment (CERTORAKEY is the literal placeholder "minha-chave"), so treat every
 * rule here as unverified until a prover run confirms it.
 *
 * Why this file exists
 * --------------------
 * reentrancy-eth is `formalizable: False` in the catalog, and the existing
 * specs/reentrancy_corrected.spec never tested reentrancy at all — its rules assert
 * revert conditions (cannot deposit zero, cannot overdraw). The pattern in
 * core/spec_patterns.py is similarly weak: asserting a balance decreased does not
 * prove ordering.
 *
 * Reentrancy is not a property of a single state value; it is a property of the
 * *order* between an external call and a storage write. That ordering is not visible
 * to a rule that only inspects pre- and post-state, which is why the earlier attempts
 * could not express it. It is observable through opcode and storage hooks.
 *
 * The property
 * ------------
 * For every externally callable method: no tracked storage slot may be written after
 * control has left the contract through a CALL. That is exactly Checks-Effects-
 * Interactions, and violating it is what makes DeFiVault.claimReward exploitable —
 * rewards[] and totalRewards are updated on lines 120-121, after the call on line 117.
 *
 * What must be validated before this is trusted
 * ---------------------------------------------
 *  1. Hook syntax is version-sensitive; the CALL hook signature and the Sstore hook
 *     form must be checked against the installed Certora Prover.
 *  2. Ghost initialization: the rules below assume ghosts start false and require it
 *     explicitly. Confirm the prover does not carry state between rules.
 *  3. Expected outcome: against DeFiVault.sol these rules must FAIL (the bug is real),
 *     and against DeFiVault_FIXED.sol they must PASS. A rule that passes on both is
 *     vacuous and worse than no rule — that check is the acceptance criterion.
 *  4. Confirm the CALL hook does not also fire for the prover's own dispatch.
 */

methods {
    function balances(address) external returns (uint256) envfree;
    function rewards(address) external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function totalRewards() external returns (uint256) envfree;
    function paused() external returns (bool) envfree;
}

// True once control has left the contract through a CALL.
ghost bool externalCallMade;

// True if a tracked slot was written while externalCallMade held.
ghost bool wroteAfterExternalCall;

// Records which slot violated the ordering, to make a counterexample readable.
ghost mathint violatingWrites;

hook CALL(uint g, address addr, uint value, uint argsLen, uint argsOffset,
          uint retLen, uint retOffset) uint rc {
    externalCallMade = true;
}

hook Sstore balances[KEY address user] uint256 newValue (uint256 oldValue) {
    if (externalCallMade && newValue != oldValue) {
        wroteAfterExternalCall = true;
        violatingWrites = violatingWrites + 1;
    }
}

hook Sstore rewards[KEY address user] uint256 newValue (uint256 oldValue) {
    if (externalCallMade && newValue != oldValue) {
        wroteAfterExternalCall = true;
        violatingWrites = violatingWrites + 1;
    }
}

hook Sstore totalDeposits uint256 newValue (uint256 oldValue) {
    if (externalCallMade && newValue != oldValue) {
        wroteAfterExternalCall = true;
        violatingWrites = violatingWrites + 1;
    }
}

hook Sstore totalRewards uint256 newValue (uint256 oldValue) {
    if (externalCallMade && newValue != oldValue) {
        wroteAfterExternalCall = true;
        violatingWrites = violatingWrites + 1;
    }
}

/*
 * Parametric over every method: no tracked write may follow an external call.
 * Expected to fail on claimReward and withdraw in DeFiVault.sol.
 */
rule no_state_write_after_external_call(method f) {
    env e;
    calldataarg args;

    require !externalCallMade;
    require !wroteAfterExternalCall;
    require violatingWrites == 0;

    f(e, args);

    assert !wroteAfterExternalCall,
        "state written after an external call: Checks-Effects-Interactions violated";
}

/*
 * Narrowed to claimReward, which is the known-vulnerable path. Kept separate so a
 * counterexample names the function directly instead of a symbolic method.
 */
rule claim_reward_respects_cei() {
    env e;

    require !externalCallMade;
    require !wroteAfterExternalCall;

    claimReward(e);

    assert !wroteAfterExternalCall,
        "claimReward updates rewards/totalRewards after sending ETH";
}

/*
 * Guards against the rules above being vacuous. If no method can reach an external
 * call at all, the hooks never fire and the CEI rules pass for the wrong reason.
 * This rule is expected to FAIL, and a failure is the proof that the hook works:
 * its counterexample is a method that does perform an external call.
 */
rule sanity_external_call_is_reachable(method f) {
    env e;
    calldataarg args;

    require !externalCallMade;

    f(e, args);

    assert !externalCallMade,
        "SANITY: expected to fail — the counterexample shows the CALL hook firing";
}
