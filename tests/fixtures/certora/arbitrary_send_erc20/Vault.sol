// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// VULN: `from` is chosen by the caller, so anyone can pull tokens from any user who approved the vault.
contract Vault {
    IToken public token;
    mapping(address => uint256) public deposits;

    constructor(address token_) {
        token = IToken(token_);
    }

    function deposit(address from, uint256 amount) external {
        require(token.transferFrom(from, address(this), amount), "transfer failed");
        deposits[from] += amount;
    }
}
