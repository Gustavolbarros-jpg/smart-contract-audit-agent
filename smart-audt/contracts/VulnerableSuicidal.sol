// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Benchmark: suicidal — selfdestruct sem restrição de acesso
contract VulnerableSuicidal {
    address public owner;
    uint256 public balance;

    constructor() payable {
        owner = msg.sender;
        balance = msg.value;
    }

    function deposit() external payable {
        balance += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balance >= amount, "insufficient");
        balance -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // VULN: suicidal — qualquer um pode destruir o contrato
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
