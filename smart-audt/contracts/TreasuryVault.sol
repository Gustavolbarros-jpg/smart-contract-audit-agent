// SPDX-License-Identifier: MIT
 pragma solidity ^0.8.21;

contract TreasuryVault {
     address public admin; mapping(address => uint256) public balances;

constructor() {
    admin = msg.sender;
}

function deposit() external payable {
    balances[msg.sender] += msg.value;
}

function sweep(address to) external {
    require(msg.sender == admin);
    require(to != address(0));
    payable(to).transfer(address(this).balance);
}
}x