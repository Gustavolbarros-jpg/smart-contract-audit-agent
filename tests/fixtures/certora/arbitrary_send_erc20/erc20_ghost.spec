// Records the `from` of every ERC20 transferFrom the contract under verification issues,
// so the rule needs neither the token's code nor a --link.
ghost bool sawTransferFrom;
ghost address lastTransferFrom;

function recordTransferFrom(address from) returns bool {
    sawTransferFrom = true;
    lastTransferFrom = from;
    return true;
}

methods {
    function _.transferFrom(address from, address to, uint256 amount) external => recordTransferFrom(from) expect bool;
}

rule deposit_only_pulls_from_the_caller(address from, uint256 amount) {
    env e;
    require !sawTransferFrom;

    deposit@withrevert(e, from, amount);

    assert sawTransferFrom => lastTransferFrom == e.msg.sender, "tokens were pulled from an account that is not the caller";
}
