methods {
    function balances(address) external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
    function contractBalance() external returns (uint256) envfree;
}

rule withdraw_reentrancy_balances_not_increased {
    env e;
    address user;
    uint256 amount;

    require user == e.msg.sender;
    require user != currentContract;
    require amount > 0;
    require balances(user) >= amount;

    uint256 beforeBal = balances(user);

    withdraw(e, amount);

    assert balances(user) == beforeBal - amount;
}

rule withdraw_reentrancy_totalsupply_not_increased {
    env e;
    address user;
    uint256 amount;

    require user == e.msg.sender;
    require user != currentContract;
    require amount > 0;
    require balances(user) >= amount;

    uint256 beforeSupply = totalSupply();

    withdraw(e, amount);

    assert totalSupply() == beforeSupply - amount;
}

rule withdraw_decreases_contract_balance_correctly {
    env e;
    address user;
    uint256 amount;

    require user == e.msg.sender;
    require user != currentContract;
    require amount > 0;
    require balances(user) >= amount;
    require contractBalance() >= amount;

    uint256 beforeBalance = contractBalance();

    withdraw(e, amount);

    assert contractBalance() == beforeBalance - amount;
}