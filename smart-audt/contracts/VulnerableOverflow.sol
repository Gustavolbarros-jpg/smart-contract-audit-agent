// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Benchmark: integer-overflow/underflow via unchecked blocks (0.8 sem SafeMath forçado)
contract VulnerableOverflow {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULN: integer-overflow — unchecked permite wrap sem revert
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "not owner");
        unchecked {
            balances[to] += amount;   // overflow wrap
            totalSupply  += amount;
        }
    }

    // VULN: integer-underflow — unchecked sem verificação prévia
    function burn(uint256 amount) external {
        unchecked {
            balances[msg.sender] -= amount;  // underflow wrap
            totalSupply          -= amount;
        }
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
