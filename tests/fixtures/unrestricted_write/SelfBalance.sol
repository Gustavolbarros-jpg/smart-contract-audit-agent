// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: every public write lands in the caller's own entry or is an accumulator,
// even though an owner-guarded function writes the same accumulator.
contract SelfBalance {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastDeposit;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    function deposit(uint256 x) external payable {
        require(msg.value == x, "value mismatch");
        balances[msg.sender] += x;
        lastDeposit[msg.sender] = block.timestamp;
        totalDeposits += x;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
    }

    function resetTotals() external {
        require(msg.sender == owner, "not owner");
        totalDeposits = 0;
    }
}
