// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/**
 * SimpleBank — Contrato vulnerável para teste do pipeline
 *
 * Vulnerabilidades intencionais:
 * VULN_001: reentrancy-eth em withdraw() — estado atualizado DEPOIS da call
 * VULN_002: missing-zero-check em setFeeCollector() — endereço zero aceito
 * VULN_003: missing-zero-check em transferOwnership() — endereço zero aceito
 * VULN_004: tx-origin em onlyOwner modifier
 * VULN_005: arbitrary-send-eth em collectFees() — sem validação do destinatário
 */
contract SimpleBank {

    address public owner;
    address public feeCollector;

    mapping(address => uint256) public balances;
    mapping(address => bool)    public registered;

    uint256 public totalDeposits;
    uint256 public feesAccumulated;
    uint256 public feePercent;   // ex: 10 = 1%
    bool    public frozen;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event FeesCollected(address indexed to, uint256 amount);
    event OwnershipTransferred(address indexed from, address indexed to);

    constructor(uint256 _feePercent) {
        owner        = msg.sender;
        feeCollector = msg.sender;
        feePercent   = _feePercent;
    }

    // VULN_004: tx.origin em vez de msg.sender
    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    modifier notFrozen() {
        require(!frozen, "frozen");
        _;
    }

    modifier onlyRegistered() {
        require(registered[msg.sender], "not registered");
        _;
    }

    function register() external {
        registered[msg.sender] = true;
    }

    function deposit() external payable notFrozen onlyRegistered {
        require(msg.value > 0, "zero deposit");
        uint256 fee    = (msg.value * feePercent) / 1000;
        uint256 net    = msg.value - fee;
        balances[msg.sender] += net;
        feesAccumulated      += fee;
        totalDeposits        += net;
        emit Deposited(msg.sender, net);
    }

    // VULN_001: reentrancy — estado atualizado DEPOIS da call externa
    function withdraw(uint256 amount) external notFrozen onlyRegistered {
        require(balances[msg.sender] >= amount, "insufficient");
        require(amount > 0, "zero amount");

        // call ANTES de atualizar estado = janela de reentrância
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");

        // Estado atualizado DEPOIS — VULN_001
        balances[msg.sender] -= amount;
        totalDeposits        -= amount;

        emit Withdrawn(msg.sender, amount);
    }

    // VULN_005: arbitrary-send-eth — envia para qualquer endereço sem validação
    function collectFees(address payable to) external onlyOwner {
        uint256 amount = feesAccumulated;
        require(amount > 0, "no fees");
        feesAccumulated = 0;
        // VULN_005: to pode ser qualquer endereço
        to.transfer(amount);
        emit FeesCollected(to, amount);
    }

    // VULN_002: missing-zero-check
    function setFeeCollector(address newCollector) external onlyOwner {
        // sem require(newCollector != address(0))
        feeCollector = newCollector;
    }

    // VULN_003: missing-zero-check
    function transferOwnership(address newOwner) external onlyOwner {
        // sem require(newOwner != address(0))
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function freeze() external onlyOwner {
        frozen = true;
    }

    function unfreeze() external onlyOwner {
        frozen = false;
    }

    function setFeePercent(uint256 newFee) external onlyOwner {
        feePercent = newFee;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function isRegistered(address user) external view returns (bool) {
        return registered[user];
    }
}