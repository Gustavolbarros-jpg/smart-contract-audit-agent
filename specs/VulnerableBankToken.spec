methods {
    function balances(address) external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
    function owner() external returns (address) envfree;
    function contractBalance() external returns (uint256) envfree;

    function withdraw(uint256) external;
    function deposit() external;
}

rule withdraw_no_reentrancy_eth {
    env e;
    address user;
    uint256 amount;

    require balances(user) >= amount;
    uint256 beforeBal = balances(user);

    withdraw(e, amount);

    assert balances(user) <= beforeBal;
}

rule withdraw_event_consistency {
    env e;
    address user;
    uint256 amount;

    require balances(user) >= amount;
    uint256 beforeSupp = totalSupply();

    withdraw(e, amount);

    assert totalSupply() == beforeSupp;
}

rule withdraw_low_level_call_no_increase {
    env e;
    address user;
    uint256 amount;

    require balances(user) >= amount;

    uint256 beforeBal = contractBalance();

    withdraw(e, amount);

    assert contractBalance() <= beforeBal;
}

rule owner_should_remain_constant {
    env e;
    method f;
    calldataarg args;

    address initial = owner();

    f(e, args);

    assert owner() == initial;
}
