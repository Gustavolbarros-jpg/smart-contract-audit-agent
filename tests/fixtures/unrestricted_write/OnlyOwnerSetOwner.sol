// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: the same setter, restricted by an onlyOwner modifier.
contract OnlyOwnerSetOwner {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function sweep(address payable to) external onlyOwner {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
