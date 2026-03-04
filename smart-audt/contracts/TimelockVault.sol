// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract TimelockVault {
    address public owner;
    uint256 public unlockTime;

    constructor(uint256 _unlockTime) payable {
        owner = msg.sender;
        unlockTime = _unlockTime;
    }

    function changeOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        require(newOwner != address(0), "zero address");
        owner = newOwner;
    }

    function withdraw() external {
        require(msg.sender == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function extendLock(uint256 newUnlockTime) external {
        unlockTime = newUnlockTime;
    }
}