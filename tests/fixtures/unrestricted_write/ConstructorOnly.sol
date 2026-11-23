// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: privileged state is written only by the constructor.
contract ConstructorOnly {
    address public owner;
    address public feeCollector;

    constructor(address collector) {
        owner = msg.sender;
        feeCollector = collector;
    }

    function collect() external {
        require(msg.sender == owner, "not owner");
        payable(feeCollector).transfer(address(this).balance);
    }

    receive() external payable {}
}
