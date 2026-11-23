// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// setLimit and grantAdmin are NEGATIVE (role checked); addAdmin is POSITIVE:
// it writes the role mapping that setLimit checks, for any address, with no check.
contract RoleMapping {
    mapping(address => bool) public admin;
    uint256 public limit;

    constructor() {
        admin[msg.sender] = true;
        limit = 100;
    }

    function setLimit(uint256 newLimit) external {
        require(admin[msg.sender], "not admin");
        limit = newLimit;
    }

    function grantAdmin(address account) external {
        require(admin[msg.sender], "not admin");
        admin[account] = true;
    }

    function addAdmin(address account) external {
        admin[account] = true;
    }
}
