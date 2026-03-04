// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender; // FIX: era tx.origin — sem vulnerabilidade CVL nesta etapa,
                            // corrigido pois é base para as correções de VULN_004/005
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        // VULN_001: not_confirmed — não alterado
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");

        balances[msg.sender] = 0;
    }

    // VULN_004 — tx-origin: substituído tx.origin por msg.sender
    // VULN_002 — arbitrary-send-eth: autorização agora via msg.sender == owner
    // VULN_006 — missing-zero-check: adicionado require(to != address(0))
    function emergencyWithdraw(address payable to) external {
        require(msg.sender == owner, "not owner"); // FIX VULN_004 + VULN_002
        require(to != address(0), "zero address"); // FIX VULN_006
        to.transfer(address(this).balance);
    }

    // VULN_005 — tx-origin: substituído tx.origin por msg.sender
    // VULN_003 — suicidal: autorização agora via msg.sender == owner
    function destroy() external {
        require(msg.sender == owner, "not owner"); // FIX VULN_005 + VULN_003
        selfdestruct(payable(owner));
    }
}