// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBankTokenCorrected {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool private locked;

    modifier nonReentrant {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }

    function deposit() external payable {
        require(msg.value > 0, "Cannot deposit zero"); // ✅ ADICIONE ESTA LINHA
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "Cannot withdraw zero"); // ✅ ADICIONE ESTA LINHA
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        totalSupply -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }

    function contractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}