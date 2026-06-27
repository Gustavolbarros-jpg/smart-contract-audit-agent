// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC2771MulticallVulnerable {
    address public trustedForwarder;
    mapping(address => uint256) public balances;

    constructor(address _forwarder) {
        trustedForwarder = _forwarder;
    }

    function _msgSender() internal view returns (address sender) {
        if (msg.sender == trustedForwarder) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            return msg.sender;
        }
    }

    function transfer(address to, uint256 amount) public {
        address sender = _msgSender();
        require(balances[sender] >= amount, "Saldo insuficiente");
        balances[sender] -= amount;
        balances[to] += amount;
    }

    function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success, "Multicall falhou");
            results[i] = result;
        }
        return results;
    }

    function mint(address user, uint256 amount) public {
        balances[user] += amount;
    }
}