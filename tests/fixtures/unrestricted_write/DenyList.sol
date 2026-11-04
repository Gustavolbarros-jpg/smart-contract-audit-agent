// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// POSITIVE: unblock() removes any address from the deny-list that send() enforces.
// NEGATIVE: blockAccount() is guarded; send() writes only the caller's own entry and an
// accumulator on the recipient's.
contract DenyList {
    address public owner;
    mapping(address => bool) public blocked;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function send(address to, uint256 amount) external {
        require(!blocked[msg.sender], "blocked");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function blockAccount(address account) external {
        require(msg.sender == owner, "not owner");
        blocked[account] = true;
    }

    function unblock(address account) external {
        blocked[account] = false;
    }
}
