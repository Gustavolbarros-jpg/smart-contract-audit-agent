methods { function admin() external returns (address) envfree; function sweep(address) external; }

rule admin_should_be_immutable(method f) { address admin_before = admin(); env e; calldataarg args;

f(e, args);

assert admin() == admin_before, "Variable admin changed, but it should be immutable";
}

rule sweep_no_arbitrary_send_eth(address to) { env e; uint256 balance_before = nativeBalances[currentContract];

sweep(e, to);

uint256 balance_after = nativeBalances[currentContract];

assert (e.msg.sender == admin() || balance_after == balance_before), 
    "Funds can be swept by a non-admin user";
}

rule sweep_missing_zero_check(address to) { env e; require to == 0;

sweep(e, to);

assert false, "Function sweep allowed execution with a zero address";
}