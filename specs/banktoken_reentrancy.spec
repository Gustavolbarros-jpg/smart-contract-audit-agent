methods {
    function balances(address) external returns uint256 envfree;
    function totalSupply() external returns uint256 envfree;
    function contractBalance() external returns uint256 envfree;

    function deposit() external;
    function withdraw(uint256) external;
}

rule DepositIncreasesBalance {
    env e;
    uint256 amount;
    require amount > 0;
    uint256 before = balances(e.msg.sender);
    deposit(e);
    uint256 after = balances(e.msg.sender);
    assert after == before + amount;
}

rule WithdrawDecreasesBalance {
    env e;
    uint256 amount;
    require amount > 0;
    require balances(e.msg.sender) >= amount;
    uint256 before = balances(e.msg.sender);
    withdraw@withrevert(e, amount);
    assert !lastReverted;
    uint256 after = balances(e.msg.sender);
    assert after == before - amount;
}

rule CannotOverdraw {
    env e;
    uint256 amount;
    require balances(e.msg.sender) < amount;
    withdraw@withrevert(e, amount);
    assert lastReverted;
}

rule NoReentrancyOnWithdraw {
    env e;
    uint256 amount;
    require amount > 0;
    require balances(e.msg.sender) >= amount;
    withdraw@withrevert(e, amount);
    assert !lastReverted;
}

rule TotalSupplyNonNegative {
    env e;
    uint256 supply = totalSupply(e);
    assert supply >= 0;
}

rule ContractBalanceNonNegative {
    env e;
    uint256 bal = contractBalance(e);
    assert bal >= 0;
}
