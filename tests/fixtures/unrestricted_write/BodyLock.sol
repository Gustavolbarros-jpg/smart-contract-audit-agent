// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: withdraw() sets and clears a reentrancy lock in its body. The constructor is
// the lock's only other writer, but no lasting change to the lock survives the call.
contract BodyLock {
    bool private locked;
    mapping(address => uint256) public balances;

    constructor() {
        locked = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(!locked, "reentrant");
        locked = true;
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        locked = false;
    }
}
