// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * @title FullySecuredBank
 * @dev Contrato final corrigido com base em múltiplas auditorias do Certora.
 * Implementa um Reentrancy Guard e garante a integridade do suprimento total.
 */
contract FullySecuredBank {
    mapping(address => uint256) public balances;
    address public owner;

    // Variável de estado para o Reentrancy Guard.
    bool private _locked;

    event Deposit(address indexed from, uint256 value);
    event Withdraw(address indexed to, uint256 value);

    /**
     * @dev Modificador que impede a reentrada em uma função.
     */
    modifier nonReentrant() {
        require(!_locked, "Reentrant call detected");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Retorna o saldo total de Ether do contrato, garantindo integridade.
     * Substitui a variável de estado `totalSupply` para evitar inconsistências.
     */
    function totalSupply() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Deposita fundos no contrato. Protegido contra reentrância.
     */
    function deposit() external payable nonReentrant {
        require(msg.value > 0, "Deposit amount must be greater than zero");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Saca fundos do contrato. Protegido contra reentrância.
     */
    function withdraw(uint256 amount) external nonReentrant {
        // --- Checks ---
        require(amount > 0, "Withdraw amount must be greater than zero");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // --- Effects ---
        balances[msg.sender] -= amount;
        
        // --- Interaction ---
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdraw(msg.sender, amount);
    }

    // helper de visualizacao
    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}