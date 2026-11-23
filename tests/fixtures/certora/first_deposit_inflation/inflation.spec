// The pool's share price depends on the balance of a token it does not control, so the
// token is summarised instead of linked: `balanceOf` may return anything, which is
// exactly what a donation to the pool does. No `--link`, no token source needed.

methods {
    function totalShares() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;
    function _.transferFrom(address, address, uint256) external => ALWAYS(true);
    function _.transfer(address, uint256) external => ALWAYS(true);
    function _.balanceOf(address) external => NONDET;
}

// A deposit of a nonzero amount has to leave the depositor holding more shares than
// before. If it can mint nothing, the tokens stay in the pool with no claim attached to
// them -- that surplus is what the first depositor inflates and later withdraws.
rule deposit_never_mints_zero_shares(uint256 amount) {
    env e;
    require amount > 0;
    require e.msg.value == 0;

    uint256 antes = balanceOf(e.msg.sender);
    deposit(e, amount);
    uint256 depois = balanceOf(e.msg.sender);

    assert depois > antes, "a nonzero deposit minted no shares at all";
}
