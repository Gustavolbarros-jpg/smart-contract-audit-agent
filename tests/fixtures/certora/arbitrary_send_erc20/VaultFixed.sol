// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

// Fixed: tokens are pulled from the caller; the `from` argument no longer chooses the source.
contract VaultFixed {
    IToken public token;
    mapping(address => uint256) public deposits;

    constructor(address token_) {
        token = IToken(token_);
    }

    function deposit(address from, uint256 amount) external {
        from;
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        deposits[msg.sender] += amount;
    }
}
