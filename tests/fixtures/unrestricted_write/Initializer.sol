// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: initialize() has no caller check but can succeed only once, because it
// checks and sets a flag that nothing resets.
contract Initializer {
    bool private initialized;
    address public owner;
    uint256 public cap;

    function initialize(address initialOwner, uint256 initialCap) external {
        require(!initialized, "already initialized");
        initialized = true;
        owner = initialOwner;
        cap = initialCap;
    }

    function setCap(uint256 newCap) external {
        require(msg.sender == owner, "not owner");
        cap = newCap;
    }
}
