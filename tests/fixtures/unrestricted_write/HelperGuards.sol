// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: caller checks reached through internal helpers and an if-wrapped write.
contract HelperGuards {
    address private _owner;
    uint256 public rate;
    uint256 public cap;
    uint256 public delay;

    constructor() {
        _owner = msg.sender;
        rate = 1;
        cap = 100;
        delay = 1 days;
    }

    function _msgSender() internal view returns (address) {
        return msg.sender;
    }

    function _checkOwner() internal view {
        if (_owner != _msgSender()) revert("not owner");
    }

    function _isOwner(address account) internal view returns (bool) {
        return account == _owner;
    }

    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        _owner = newOwner;
    }

    function setRate(uint256 newRate) external onlyOwner {
        rate = newRate;
    }

    function setCap(uint256 newCap) external {
        require(_isOwner(msg.sender), "not owner");
        cap = newCap;
    }

    function setDelay(uint256 newDelay) external {
        if (msg.sender == _owner) {
            delay = newDelay;
        }
    }
}
