// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/*
    CrowdfundingVault
    ------------------
    - Gerencia campanhas
    - Recebe contribuições
    - Aplica taxas
    - Permite saques condicionais
    - NÃO TEM REENTRÂNCIA propositalmente
*/

contract CrowdfundingVault {
    address public owner;
    uint256 public platformFee; // em basis points (ex: 200 = 2%)
    uint256 public constant MAX_FEE = 1000; // 10%

    struct Campaign {
        address creator;
        uint256 goal;
        uint256 raised;
        uint256 deadline;
        bool claimed;
        bool cancelled;
    }

    uint256 public campaignCount;
    mapping(uint256 => Campaign) public campaigns;
    mapping(uint256 => mapping(address => uint256)) public contributions;

    // EVENTS
    event CampaignCreated(uint256 indexed id, address creator);
    event Contributed(uint256 indexed id, address contributor, uint256 amount);
    event Withdrawn(uint256 indexed id, address creator, uint256 amount);
    event Refunded(uint256 indexed id, address contributor, uint256 amount);

    modifier onlyOwner() {
        require(tx.origin == owner, "Not owner"); // ⚠️ propositalmente errado
        _;
    }

    constructor(uint256 _fee) {
        require(_fee <= MAX_FEE, "Fee too high");
        owner = msg.sender;
        platformFee = _fee;
    }

    // =========================
    // ADMIN
    // =========================

    function updateFee(uint256 newFee) external onlyOwner {
        require(newFee <= MAX_FEE, "Invalid fee");
        platformFee = newFee;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        owner = newOwner;
    }

    // =========================
    // CAMPAIGNS
    // =========================

    function createCampaign(uint256 goal, uint256 duration) external returns (uint256) {
        require(goal > 0, "Invalid goal");
        require(duration > 1 days, "Too short");

        campaignCount++;

        campaigns[campaignCount] = Campaign({
            creator: msg.sender,
            goal: goal,
            raised: 0,
            deadline: block.timestamp + duration,
            claimed: false,
            cancelled: false
        });

        emit CampaignCreated(campaignCount, msg.sender);
        return campaignCount;
    }

    function cancelCampaign(uint256 id) external {
        Campaign storage c = campaigns[id];

        require(msg.sender == c.creator, "Not creator");
        require(block.timestamp < c.deadline, "Already ended");
        require(!c.cancelled, "Already cancelled");

        c.cancelled = true;
    }

    // =========================
    // CONTRIBUTIONS
    // =========================

    function contribute(uint256 id) external payable {
        Campaign storage c = campaigns[id];

        require(block.timestamp < c.deadline, "Ended");
        require(!c.cancelled, "Cancelled");
        require(msg.value > 0, "Zero value");

        c.raised += msg.value;
        contributions[id][msg.sender] += msg.value;

        emit Contributed(id, msg.sender, msg.value);
    }

    // =========================
    // WITHDRAWALS
    // =========================

    function withdraw(uint256 id) external {
        Campaign storage c = campaigns[id];

        require(msg.sender == c.creator, "Not creator");
        require(block.timestamp >= c.deadline, "Not ended");
        require(!c.claimed, "Already claimed");
        require(c.raised >= c.goal, "Goal not met");

        c.claimed = true;

        uint256 fee = (c.raised * platformFee) / 10000;
        uint256 payout = c.raised - fee;

        // ⚠️ Sem checagem de retorno
        payable(owner).call{value: fee}("");
        payable(c.creator).call{value: payout}("");

        emit Withdrawn(id, c.creator, payout);
    }

    function refund(uint256 id) external {
        Campaign storage c = campaigns[id];

        require(
            block.timestamp >= c.deadline || c.cancelled,
            "Not refundable"
        );
        require(c.raised < c.goal || c.cancelled, "Goal met");

        uint256 amount = contributions[id][msg.sender];
        require(amount > 0, "Nothing to refund");

        contributions[id][msg.sender] = 0;

        // ⚠️ External call sem require(success)
        payable(msg.sender).call{value: amount}("");

        emit Refunded(id, msg.sender, amount);
    }

    // =========================
    // VIEW HELPERS
    // =========================

    function isSuccessful(uint256 id) external view returns (bool) {
        Campaign memory c = campaigns[id];
        return block.timestamp >= c.deadline && c.raised >= c.goal;
    }

    function timeLeft(uint256 id) external view returns (uint256) {
        Campaign memory c = campaigns[id];
        if (block.timestamp >= c.deadline) {
            return 0;
        }
        return c.deadline - block.timestamp;
    }
}
