// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: guards written in the body instead of a modifier.
contract InlineRequireOwner {
    address public owner;
    uint256 public fee;

    constructor() {
        owner = msg.sender;
        fee = 10;
    }

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;
    }

    function setFee(uint256 newFee) external {
        if (msg.sender != owner) revert("not owner");
        fee = newFee;
    }
}
