// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * @title SafeBankToken
 * @dev Contrato corrigido para prevenir ataques de reentrância
 * seguindo o padrão Checks-Effects-Interactions.
 */
contract SafeBankToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    event Deposit(address indexed from, uint256 value);
    event Withdraw(address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Função de saque segura.
     * 1. Checks: Verifica se o valor é positivo e se o usuário tem saldo.
     * 2. Effects: Atualiza o saldo do usuário e o totalSupply ANTES da chamada externa.
     * 3. Interaction: Envia o Ether para o msg.sender.
     */
    function withdraw(uint256 amount) external {
        // --- Checks ---
        require(amount > 0, "Amount must be greater than zero");
        require(balances[msg.sender] >= amount, "insufficient balance");

        // --- Effects ---
        balances[msg.sender] -= amount;
        totalSupply -= amount;

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