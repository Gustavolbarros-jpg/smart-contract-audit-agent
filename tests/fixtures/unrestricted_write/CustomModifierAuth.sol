// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: the guard is a modifier named `auth` over a variable named `governance`;
// nothing in the detector depends on either name.
contract CustomModifierAuth {
    address public governance;
    address public treasury;

    constructor(address initialTreasury) {
        governance = msg.sender;
        treasury = initialTreasury;
    }

    modifier auth() {
        require(msg.sender == governance, "unauthorized");
        _;
    }

    function setTreasury(address newTreasury) external auth {
        treasury = newTreasury;
    }

    function setGovernance(address newGovernance) external auth {
        governance = newGovernance;
    }

    function release(uint256 amount) external auth {
        payable(treasury).transfer(amount);
    }

    receive() external payable {}
}
