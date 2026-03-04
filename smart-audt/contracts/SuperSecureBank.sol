// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * @title SuperSecureBank
 * @dev A versão final que previne DoS por falha em chamada externa,
 * revertendo o estado internamente em vez de reverter a transação.
 */
contract SuperSecureBank {
    mapping(address => uint256) private _balances;
    address public owner;
    bool private _locked;

    event Deposit(address indexed from, uint256 value);
    event Withdraw(address indexed to, uint256 value);
    event TransferFailed(address indexed to, uint256 value);

    modifier whenNotLocked() {
        require(!_locked, "Contract is currently locked");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "Reentrant call detected");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function getBalance(address account) external view whenNotLocked returns (uint256) {
        return _balances[account];
    }

    function totalSupply() external view whenNotLocked returns (uint256) {
        return address(this).balance;
    }

    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        _balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Withdraw amount must be greater than zero");
        uint256 userBalance = _balances[msg.sender];
        require(userBalance >= amount, "Insufficient balance");

        _balances[msg.sender] = userBalance - amount;
        
        (bool success, ) = msg.sender.call{value: amount}("");

        // CORREÇÃO FINAL: Em vez de reverter, lidamos com a falha.
        if (!success) {
            // Reembolsa o saldo interno, pois a transferência falhou.
            _balances[msg.sender] = userBalance; 
            emit TransferFailed(msg.sender, amount);
        } else {
            emit Withdraw(msg.sender, amount);
        }
    }

    function contractBalance() external view whenNotLocked returns (uint256) {
        return address(this).balance;
    }
}