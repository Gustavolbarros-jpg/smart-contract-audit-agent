
// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

contract VulnerableBankToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;
    bool private _locked;

    event Deposit(address indexed from, uint256 value);
    event Withdraw(address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
        _locked = false;
    }

    function contractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function deposit() public payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    modifier nonReentrant() {
        require(!_locked, "reentrant");
        _locked = true;
        _;
        _locked = false;
    }

    function withdraw(uint256 amount) public nonReentrant {
        require(amount > 0, "zero withdraw");
        require(balances[msg.sender] >= amount, "insufficient");
    
        uint256 beforeBal = address(this).balance;

        balances[msg.sender] -= amount;

        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "call failed");

        require(address(this).balance <= beforeBal - amount, "balance changed");

        emit Withdraw(msg.sender, amount);
    }
}

