methods {
    function owner() external returns (address) envfree;
    function unlockTime() external returns (uint256) envfree;
}

rule withdraw_arbitrary_send_eth() {
    env e;
    uint256 balance_before = nativeBalances[currentContract];
    address sender = e.msg.sender;
    
    withdraw(e);
    
    uint256 balance_after = nativeBalances[currentContract];
    
    assert balance_after < balance_before => sender == owner(), 
        "ETH sent to arbitrary user in withdraw";
}

rule changeOwner_tx_origin_usage(address newOwner) {
    env e;
    address owner_before = owner();
    
    changeOwner@withrevert(e, newOwner);
    bool reverted = lastReverted;
    
    assert !reverted => e.msg.sender == owner_before, 
        "changeOwner uses tx.origin instead of msg.sender for authorization";
}

rule changeOwner_missing_zero_check(address newOwner) {
    env e;
    require newOwner == 0;
    
    changeOwner@withrevert(e, newOwner);
    bool reverted = lastReverted;
    
    assert reverted, 
        "changeOwner allows zero address without validation";
}

rule withdraw_timestamp_dependency() {
    env e1;
    env e2;
    
    require e1.block.timestamp < unlockTime();
    require e2.block.timestamp >= unlockTime();
    
    withdraw@withrevert(e1);
    bool reverted1 = lastReverted;
    
    withdraw@withrevert(e2);
    bool reverted2 = lastReverted;
    
    assert reverted1 && !reverted2, 
        "withdraw depends on block.timestamp for access control";
}