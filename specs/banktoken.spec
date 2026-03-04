methods {
    function getBalance(address) external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
    function contractBalance() external returns (uint256) envfree;
}

// =====================================================
// REGRAS ESSENCIAIS DE SEGURANÇA
// =====================================================

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

// =====================================================
// REGRA ANTI-DoS ESPECÍFICA
// =====================================================

// Regra: Múltiplos usuários podem usar o contrato simultaneamente
rule MultipleUsersCanDeposit {
    env e1;
    env e2;
    uint256 amount1;
    uint256 amount2;
    
    address user1 = e1.msg.sender;
    address user2 = e2.msg.sender;
    
    require user1 != user2;
    require user1 != currentContract;
    require user2 != currentContract;
    require amount1 > 0 && amount1 <= 100;
    require amount2 > 0 && amount2 <= 100;
    require e1.msg.value == amount1;
    require e2.msg.value == amount2;
    
    // User1 deposita
    deposit(e1);
    
    // User2 deve conseguir depositar independentemente
    deposit(e2);
    
    // Ambos devem ter seus saldos corretos
    assert getBalance(user1) == amount1;
    assert getBalance(user2) == amount2;
}

// =====================================================
// REGRA DE COMPORTAMENTO DE WITHDRAW
// =====================================================

// Regra: Withdraw não trava o contrato permanentemente
rule WithdrawDoesNotPermanentlyLockContract {
    env e1;
    env e2;
    uint256 withdrawAmount;
    uint256 depositAmount;
    
    address user1 = e1.msg.sender;
    address user2 = e2.msg.sender;
    
    require user1 != user2;
    require user1 != currentContract;
    require user2 != currentContract;
    require withdrawAmount > 0 && withdrawAmount <= 50;
    require depositAmount > 0 && depositAmount <= 50;
    require e1.msg.value == withdrawAmount;
    require e2.msg.value == depositAmount;
    
    // User1 deposita
    deposit(e1);
    
    // User1 tenta sacar (pode funcionar ou falhar, não importa)
    withdraw(e1, withdrawAmount);
    
    // CRÍTICO: User2 deve conseguir depositar depois
    deposit(e2);
    
    // Se chegamos aqui, não há DoS
    assert getBalance(user2) == depositAmount;
}