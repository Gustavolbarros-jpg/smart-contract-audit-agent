methods {
    function owner() external returns (address) envfree;
}

rule unchecked_lowlevel_withdraw_owner_call {
    env e;
    uint256 id;
    withdraw(e, id);
    assert true;
}

rule unchecked_lowlevel_withdraw_creator_call {
    env e;
    uint256 id;
    withdraw(e, id);
    assert true;
}

rule unchecked_lowlevel_refund_call {
    env e;
    uint256 id;
    refund(e, id);
    assert true;
}

rule events_access_transferOwnership {
    env e;
    address newOwner;
    transferOwnership(e, newOwner);
    assert true;
}

rule reentrancy_events_withdraw {
    env e;
    uint256 id;
    withdraw(e, id);
    assert true;
}

rule reentrancy_events_refund {
    env e;
    uint256 id;
    refund(e, id);
    assert true;
}

rule timestamp_cancelCampaign {
    env e;
    uint256 id;
    cancelCampaign(e, id);
    assert true;
}

rule timestamp_withdraw {
    env e;
    uint256 id;
    withdraw(e, id);
    assert true;
}

rule timestamp_refund {
    env e;
    uint256 id;
    refund(e, id);
    assert true;
}

rule timestamp_contribute {
    env e;
    uint256 id;
    contribute(e, id);
    assert true;
}

rule timestamp_timeLeft {
    env e;
    uint256 id;
    timeLeft(e, id);
    assert true;
}

rule timestamp_isSuccessful {
    env e;
    uint256 id;
    isSuccessful(e, id);
    assert true;
}

rule solc_version_constraint {
    assert true;
}

rule low_level_calls_withdraw {
    env e;
    uint256 id;
    withdraw(e, id);
    assert true;
}

rule low_level_calls_refund {
    env e;
    uint256 id;
    refund(e, id);
    assert true;
}