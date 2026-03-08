// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract DeFiVault {

    // ─── Storage ───────────────────────────────────────────
    address public owner;
    address public pendingOwner;

    mapping(address => uint256) public balances;
    mapping(address => uint256) public rewards;
    mapping(address => bool)    public whitelist;
    mapping(address => uint256) public lastWithdraw;

    uint256 public totalDeposits;
    uint256 public totalRewards;
    uint256 public rewardRate;      // rewards por segundo
    uint256 public lockPeriod;      // segundos de lock após depósito
    uint256 public maxWithdraw;     // limite por saque
    bool    public paused;

    // ─── Events ────────────────────────────────────────────
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event Paused(address indexed by);
    event OwnershipTransferred(address indexed from, address indexed to);

    // ─── Constructor ───────────────────────────────────────
    constructor(uint256 _rewardRate, uint256 _lockPeriod, uint256 _maxWithdraw) {
        owner       = msg.sender;
        rewardRate  = _rewardRate;
        lockPeriod  = _lockPeriod;
        maxWithdraw = _maxWithdraw;
    }

    // ─── Modifiers ─────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner"); // FIX VULN_009 e VULN_011
        _;
    }

    modifier notPaused() {
        require(!paused, "paused");
        _;
    }

    modifier onlyWhitelisted() {
        require(whitelist[msg.sender], "not whitelisted");
        _;
    }

    // ─── Whitelist ─────────────────────────────────────────

    function joinWhitelist() external {
        whitelist[msg.sender] = true;
    }

    function removeFromWhitelist(address user) external onlyOwner {
        whitelist[user] = false;
    }

    // ─── Deposit ───────────────────────────────────────────
    function deposit() external payable notPaused onlyWhitelisted {
        require(msg.value > 0, "zero deposit");

        balances[msg.sender]  += msg.value;
        totalDeposits         += msg.value;
        lastWithdraw[msg.sender] = block.timestamp;

        emit Deposited(msg.sender, msg.value);
    }

    // ─── Withdraw ──────────────────────────────────────────
    function withdraw(uint256 amount) external notPaused onlyWhitelisted {
        require(balances[msg.sender] >= amount, "insufficient");
        require(amount > 0, "zero amount");

        require(
            block.timestamp >= lastWithdraw[msg.sender] + lockPeriod,
            "locked"
        );

        require(amount <= maxWithdraw, "exceeds max");

        balances[msg.sender] -= amount;
        totalDeposits        -= amount;
        lastWithdraw[msg.sender] = block.timestamp;

        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "transfer failed");

        emit Withdrawn(msg.sender, amount);
    }

    // ─── Rewards ───────────────────────────────────────────
    function calculateReward(address user) public view returns (uint256) {
        uint256 elapsed = block.timestamp - lastWithdraw[user];
        return (balances[user] * rewardRate * elapsed) / 1e18;
    }

    function claimReward() external notPaused onlyWhitelisted {
        uint256 reward = calculateReward(msg.sender);
        require(reward > 0, "no reward");
        require(totalRewards >= reward, "insufficient rewards");

        rewards[msg.sender]  += reward;
        totalRewards         -= reward;

        (bool success, ) = payable(msg.sender).call{value: reward}("");
        require(success, "transfer failed");

        emit RewardClaimed(msg.sender, reward);
    }

    // ─── Admin ─────────────────────────────────────────────

    function pause() external onlyOwner {
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause() external onlyOwner {
        paused = false;
    }

    function setRewardRate(uint256 newRate) external onlyOwner {
        rewardRate = newRate;
    }

    function setMaxWithdraw(uint256 newMax) external onlyOwner {
        maxWithdraw = newMax;
    }

    function setLockPeriod(uint256 newPeriod) external onlyOwner {
        lockPeriod = newPeriod;
    }

    // ─── Ownership transfer ────────────────────────────────
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "new owner is zero"); // FIX VULN_003
        pendingOwner = newOwner;
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnershipTransferred(owner, pendingOwner);
        owner        = pendingOwner;
        pendingOwner = address(0);
    }

    // ─── Fund management ───────────────────────────────────
    function emergencyWithdraw(address payable to, uint256 amount) external onlyOwner {
        require(to != address(0), "destination is zero"); // FIX VULN_004
        require(amount <= address(this).balance, "insufficient balance");
        require(to == owner, "Invalid recipient"); // FIX VULN_013
        (bool success, ) = to.call{value: amount}("");
        require(success, "transfer failed");
    }

    // ─── Destroy ───────────────────────────────────────────
    function destroy() external onlyOwner {
        require(msg.sender == owner, "not owner"); // FIX VULN_012
        selfdestruct(payable(owner));
    }

    // ─── View ──────────────────────────────────────────────
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function isWhitelisted(address user) external view returns (bool) {
        return whitelist[user];
    }

    receive() external payable {
        totalDeposits += msg.value;
    }
}