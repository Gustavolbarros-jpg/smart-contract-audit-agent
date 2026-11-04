// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// POSITIVE: setOwner overwrites the variable sweep() compares against msg.sender.
contract UnprotectedSetOwner {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function sweep(address payable to) external {
        require(msg.sender == owner, "not owner");
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
