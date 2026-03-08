// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * Ethernaut Level 9 — King
 * Vulnerabilidades intencionais para teste do pipeline:
 *
 * 1. DoS via transfer() — se o king atual for um contrato que rejeita ETH,
 *    ninguém mais consegue tomar o trono (transfer reverte, bloqueando o jogo)
 *
 * 2. tx.origin no onlyOwner — owner usa tx.origin em vez de msg.sender
 *
 * 3. missing-zero-check — _king pode ser address(0) no constructor
 *
 * 4. arbitrary-send-eth — owner pode drenar o prize via claimPrize()
 *    sem validação de destinatário
 */
contract King {

    address public king;
    uint256 public prize;
    address public owner;

    event NewKing(address indexed newKing, uint256 prize);
    event PrizeClaimed(address indexed by, uint256 amount);

    constructor(address initialKing) payable {
        // VULN: missing-zero-check — initialKing pode ser address(0)
        owner = msg.sender;
        king  = initialKing;
        prize = msg.value;
    }

    // Modifier com tx.origin — VULN: tx-origin
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    /**
     * Para tomar o trono, envie ETH >= prize atual.
     * O prize vai para o king anterior via transfer().
     * VULN: DoS — se king anterior for contrato sem receive(), transfer() reverte
     * e ninguém mais consegue chamar esta função.
     */
    receive() external payable {
        require(msg.value >= prize, "not enough ETH");

        // VULN: DoS via transfer — king malicioso bloqueia aqui
        payable(king).transfer(msg.value);

        king  = msg.sender;
        prize = msg.value;

        emit NewKing(msg.sender, msg.value);
    }

    /**
     * Owner pode reclamar o prize acumulado para qualquer endereço.
     * VULN: arbitrary-send-eth — sem validação do destinatário
     */
    function claimPrize(address payable to) external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "nothing to claim");
        // VULN: arbitrary-send-eth
        to.transfer(amount);
        emit PrizeClaimed(to, amount);
    }

    /**
     * Owner pode forçar um novo king sem pagar prize.
     * VULN: missing-zero-check — newKing pode ser address(0)
     */
    function forceKing(address newKing) external onlyOwner {
        king = newKing;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}