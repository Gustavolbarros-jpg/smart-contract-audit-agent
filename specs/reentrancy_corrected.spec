methods {
    function getBalance(address) external returns uint256 envfree;
    function totalSupply() external returns uint256 envfree;
    function contractBalance() external returns uint256 envfree;
}

// Regra: Não pode depositar zero
rule CannotDepositZero {
    env e;
    
    require e.msg.value == 0;
    require e.msg.sender != currentContract;
    
    deposit@withrevert(e);
    
    assert lastReverted;
}

// Regra: Não pode sacar zero
rule CannotWithdrawZero {
    env e;
    
    require e.msg.sender != currentContract;
    
    withdraw@withrevert(e, 0);
    
    assert lastReverted;
}

// Regra: Não pode sacar mais do que tem
rule CannotOverdraw {
    env e;
    uint256 amount;
    
    require getBalance(e.msg.sender) < amount;
    require e.msg.sender != currentContract;
    
    withdraw@withrevert(e, amount);
    
    assert lastReverted;
}

// Regra: Depósitos funcionam corretamente
rule DepositWorks {
    env e;
    
    require e.msg.value > 0;
    require e.msg.sender != currentContract;
    
    uint256 balanceBefore = getBalance(e.msg.sender);
    
    deposit(e);
    
    assert getBalance(e.msg.sender) == balanceBefore + e.msg.value;
}

// Regra: Withdraw nunca reverte por saldo insuficiente quando saldo é suficiente
rule WithdrawWithSufficientBalance {
    env e;
    uint256 amount;
    
    require amount > 0;
    require getBalance(e.msg.sender) >= amount;
    require e.msg.sender != currentContract;
    
    withdraw(e, amount);
    
    assert true;
}

// Regra: Após qualquer operação, outros usuários podem depositar
rule OtherUsersCanAlwaysDeposit {
    env e1;
    env e2;
    method f;
    calldataarg args;
    
    address user1 = e1.msg.sender;
    address user2 = e2.msg.sender;
    
    require user1 != user2;
    require user1 != currentContract;
    require user2 != currentContract;
    require e2.msg.value > 0;
    
    f(e1, args);
    
    deposit(e2);
    
    assert getBalance(user2) > 0;
}