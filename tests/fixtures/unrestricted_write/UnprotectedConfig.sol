// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// POSITIVE: pause() and setFeeCollector() are unguarded.
//   paused       - privileged because its only other writer, unpause(), is guarded
//   feeCollector - privileged because it receives ether in collectFees()
// NEGATIVE: unpause() and collectFees() are guarded.
contract UnprotectedConfig {
    address public owner;
    address public feeCollector;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    function pause() external {
        paused = true;
    }

    function unpause() external {
        require(msg.sender == owner, "not owner");
        paused = false;
    }

    function setFeeCollector(address collector) external {
        feeCollector = collector;
    }

    function collectFees() external {
        require(msg.sender == owner, "not owner");
        payable(feeCollector).transfer(address(this).balance);
    }

    receive() external payable {}
}
