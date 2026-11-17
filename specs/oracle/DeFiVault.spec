// Oracle spec for DeFiVault, written from the ORIGINAL contract.
//
// It states what the contract promises -- balances move by exactly the amount asked, the
// lock and the withdraw cap hold, only the owner administers, the whitelist gates deposits
// and withdrawals -- and says nothing about any particular defect. That is the point: the
// same spec is run against every mutant, and a mutant is killed only because it breaks a
// promise that was already written down.
//
// Frozen: no rule here may be added, tightened or relaxed after a mutant result is known.
// See runs/oracle_validation_20261116/ for the pair that validated the local verifier.

methods {
    function owner() external returns(address) envfree;
    function pendingOwner() external returns(address) envfree;
    function balances(address) external returns(uint256) envfree;
    function rewards(address) external returns(uint256) envfree;
    function whitelist(address) external returns(bool) envfree;
    function lastWithdraw(address) external returns(uint256) envfree;
    function totalDeposits() external returns(uint256) envfree;
    function totalRewards() external returns(uint256) envfree;
    function rewardRate() external returns(uint256) envfree;
    function lockPeriod() external returns(uint256) envfree;
    function maxWithdraw() external returns(uint256) envfree;
    function paused() external returns(bool) envfree;
}

// ─── Withdraw ────────────────────────────────────────────────────────────────

rule withdraw_debits_exactly {
    env e;
    uint256 amount;
    uint256 before = balances(e.msg.sender);

    withdraw(e, amount);

    assert to_mathint(balances(e.msg.sender)) == to_mathint(before) - to_mathint(amount);
}

rule withdraw_debits_total_deposits {
    env e;
    uint256 amount;
    uint256 before = totalDeposits();

    withdraw(e, amount);

    assert to_mathint(totalDeposits()) == to_mathint(before) - to_mathint(amount);
}

rule withdraw_respects_the_cap {
    env e;
    uint256 amount;
    uint256 cap = maxWithdraw();

    withdraw(e, amount);

    assert to_mathint(amount) <= to_mathint(cap);
}

rule withdraw_honours_the_lock {
    env e;
    uint256 amount;
    uint256 last = lastWithdraw(e.msg.sender);
    uint256 lock = lockPeriod();

    withdraw(e, amount);

    assert to_mathint(e.block.timestamp) >= to_mathint(last) + to_mathint(lock);
}

rule withdraw_needs_the_whitelist {
    env e;
    uint256 amount;
    require !whitelist(e.msg.sender);

    withdraw@withrevert(e, amount);

    assert lastReverted;
}

rule withdraw_is_blocked_while_paused {
    env e;
    uint256 amount;
    require paused();

    withdraw@withrevert(e, amount);

    assert lastReverted;
}

// ─── Deposit ─────────────────────────────────────────────────────────────────

rule deposit_credits_exactly {
    env e;
    uint256 before = balances(e.msg.sender);
    require e.msg.value > 0;

    deposit(e);

    assert to_mathint(balances(e.msg.sender)) == to_mathint(before) + to_mathint(e.msg.value);
}

rule deposit_credits_total_deposits {
    env e;
    uint256 before = totalDeposits();
    require e.msg.value > 0;

    deposit(e);

    assert to_mathint(totalDeposits()) == to_mathint(before) + to_mathint(e.msg.value);
}

rule deposit_rejects_zero_value {
    env e;
    require e.msg.value == 0;

    deposit@withrevert(e);

    assert lastReverted;
}

// ─── Whitelist ───────────────────────────────────────────────────────────────

rule join_whitelist_touches_only_the_caller {
    env e;
    address other;
    require other != e.msg.sender;
    bool before = whitelist(other);

    joinWhitelist(e);

    assert whitelist(e.msg.sender);
    assert whitelist(other) == before;
}

// ─── Administração ───────────────────────────────────────────────────────────

rule only_the_owner_pauses {
    env e;
    require e.msg.sender != owner();

    pause@withrevert(e);

    assert lastReverted;
}

rule only_the_owner_sets_the_reward_rate {
    env e;
    uint256 rate;
    require e.msg.sender != owner();

    setRewardRate@withrevert(e, rate);

    assert lastReverted;
}

rule only_the_owner_sets_the_cap {
    env e;
    uint256 cap;
    require e.msg.sender != owner();

    setMaxWithdraw@withrevert(e, cap);

    assert lastReverted;
}

rule only_the_owner_destroys {
    env e;
    require e.msg.sender != owner();

    destroy@withrevert(e);

    assert lastReverted;
}

rule emergency_withdraw_only_pays_the_owner {
    env e;
    address to;
    uint256 amount;
    require to != owner();

    emergencyWithdraw@withrevert(e, to, amount);

    assert lastReverted;
}

// ─── Ownership ───────────────────────────────────────────────────────────────

rule transfer_ownership_rejects_the_zero_address {
    env e;
    address newOwner;
    require newOwner == 0;

    transferOwnership@withrevert(e, newOwner);

    assert lastReverted;
}

rule accept_ownership_needs_the_pending_owner {
    env e;
    require e.msg.sender != pendingOwner();

    acceptOwnership@withrevert(e);

    assert lastReverted;
}

rule accept_ownership_hands_over_the_contract {
    env e;
    require e.msg.sender == pendingOwner();

    acceptOwnership(e);

    assert owner() == e.msg.sender;
}

// ─── Rewards ─────────────────────────────────────────────────────────────────

rule claim_reward_conserves_the_reward_pool {
    env e;
    uint256 claimed_before = rewards(e.msg.sender);
    uint256 pool_before = totalRewards();

    claimReward(e);

    assert to_mathint(rewards(e.msg.sender)) - to_mathint(claimed_before)
        == to_mathint(pool_before) - to_mathint(totalRewards());
}
