// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract AnotherVulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "Invalid amount");
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(address(this).balance >= amount, "Contract underfunded");

        balances[msg.sender] -= amount;
        totalSupply -= amount;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Transfer failed");
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function owner() external view returns (address) {
        return msg.sender;
    }

    receive() external payable {
        revert("Use deposit()");
    }

    fallback() external payable {
        revert("Use deposit()");
    }
}