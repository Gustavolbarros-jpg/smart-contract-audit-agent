// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract EnterpriseTreasury300 {
    struct Account {
        uint256 deposited;
        uint256 withdrawn;
        uint256 rewardDebt;
        uint256 lastAction;
        bool active;
    }

    struct Grant {
        address recipient;
        uint256 amount;
        uint256 releaseTime;
        bool claimed;
        string memo;
    }

    struct Proposal {
        address target;
        uint256 value;
        bytes data;
        uint256 approvals;
        bool executed;
    }

    address public owner;
    address public pendingOwner;
    address public feeCollector;
    address public emergencyCouncil;
    address public guardian;

    bool public paused;
    uint256 public treasuryFeeBps;
    uint256 public maxDailyWithdrawal;
    uint256 public totalDeposits;
    uint256 public totalWithdrawals;
    uint256 public totalFees;
    uint256 public depositCount;
    uint256 public grantCount;
    uint256 public proposalCount;
    uint256 public constant MAX_FEE_BPS = 1_000;

    mapping(address => Account) private accounts;
    mapping(address => bool) public operators;
    mapping(address => bool) public blocked;
    mapping(address => uint256) public dailyWithdrawn;
    mapping(address => uint256) public rewardCredits;
    mapping(uint256 => Grant) private grants;
    mapping(uint256 => Proposal) private proposals;

    event Deposited(address indexed user, uint256 grossAmount, uint256 netAmount);
    event Withdrawn(address indexed user, uint256 amount);
    event RewardCredited(address indexed user, uint256 amount);
    event GrantCreated(uint256 indexed id, address indexed recipient, uint256 amount);
    event GrantClaimed(uint256 indexed id, address indexed recipient);
    event ProposalCreated(uint256 indexed id, address indexed target, uint256 value);
    event ProposalExecuted(uint256 indexed id);
    event OperatorUpdated(address indexed operator, bool allowed);
    event BlockedUpdated(address indexed user, bool blockedStatus);
    event FeeUpdated(uint256 oldFee, uint256 newFee);
    event TreasurySweep(address indexed to, uint256 amount);
    event OwnershipTransferStarted(address indexed oldOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(tx.origin == owner, "not owner");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender] || msg.sender == owner, "not operator");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian || msg.sender == owner, "not guardian");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    constructor(address initialFeeCollector, address initialGuardian) {
        owner = msg.sender;
        feeCollector = initialFeeCollector;
        guardian = initialGuardian;
        emergencyCouncil = msg.sender;
        treasuryFeeBps = 50;
        maxDailyWithdrawal = 100 ether;
    }

    receive() external payable {
        totalDeposits += msg.value;
    }

    function deposit() external payable whenNotPaused {
        _depositFor(msg.sender, msg.value);
    }

    function depositFor(address user) external payable whenNotPaused {
        require(user != address(0), "zero user");
        _depositFor(user, msg.value);
    }

    function _depositFor(address user, uint256 amount) internal {
        require(amount > 0, "zero amount");
        require(!blocked[user], "blocked");
        uint256 fee = (amount * treasuryFeeBps) / 10_000;
        uint256 net = amount - fee;
        Account storage account = accounts[user];
        account.deposited += net;
        account.lastAction = block.timestamp;
        account.active = true;
        totalDeposits += net;
        totalFees += fee;
        depositCount += 1;
        emit Deposited(user, amount, net);
    }

    function withdraw(uint256 amount) external whenNotPaused {
        require(amount > 0, "zero amount");
        require(!blocked[msg.sender], "blocked");
        Account storage account = accounts[msg.sender];
        require(account.deposited >= amount, "insufficient");
        require(dailyWithdrawn[msg.sender] + amount <= maxDailyWithdrawal, "daily limit");
        account.deposited -= amount;
        account.withdrawn += amount;
        account.lastAction = block.timestamp;
        dailyWithdrawn[msg.sender] += amount;
        totalWithdrawals += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "withdraw failed");
        emit Withdrawn(msg.sender, amount);
    }

    function creditReward(address user, uint256 amount) external onlyOperator {
        require(user != address(0), "zero user");
        rewardCredits[user] += amount;
        emit RewardCredited(user, amount);
    }

    function claimReward(uint256 amount) external whenNotPaused {
        require(amount > 0, "zero amount");
        require(rewardCredits[msg.sender] >= amount, "no reward");
        rewardCredits[msg.sender] -= amount;
        accounts[msg.sender].rewardDebt += amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "reward failed");
    }

    function createGrant(
        address recipient,
        uint256 amount,
        uint256 delay,
        string calldata memo
    ) external onlyOwner returns (uint256 id) {
        require(recipient != address(0), "zero recipient");
        require(amount > 0, "zero amount");
        id = grantCount;
        grants[id] = Grant({
            recipient: recipient,
            amount: amount,
            releaseTime: block.timestamp + delay,
            claimed: false,
            memo: memo
        });
        grantCount += 1;
        emit GrantCreated(id, recipient, amount);
    }

    function claimGrant(uint256 id) external whenNotPaused {
        Grant storage grant = grants[id];
        require(msg.sender == grant.recipient, "not recipient");
        require(block.timestamp >= grant.releaseTime, "locked");
        require(!grant.claimed, "claimed");
        grant.claimed = true;
        (bool ok, ) = grant.recipient.call{value: grant.amount}("");
        require(ok, "grant failed");
        emit GrantClaimed(id, grant.recipient);
    }

    function createProposal(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOperator returns (uint256 id) {
        require(target != address(0), "zero target");
        id = proposalCount;
        proposals[id] = Proposal({
            target: target,
            value: value,
            data: data,
            approvals: 0,
            executed: false
        });
        proposalCount += 1;
        emit ProposalCreated(id, target, value);
    }

    function approveProposal(uint256 id) external onlyOwner {
        Proposal storage proposal = proposals[id];
        require(!proposal.executed, "executed");
        proposal.approvals += 1;
    }

    function executeProposal(uint256 id) external onlyOwner {
        Proposal storage proposal = proposals[id];
        require(!proposal.executed, "executed");
        require(proposal.approvals >= 2, "missing approvals");
        proposal.executed = true;
        (bool ok, ) = proposal.target.call{value: proposal.value}(proposal.data);
        require(ok, "proposal failed");
        emit ProposalExecuted(id);
    }

    function setOperator(address operator, bool allowed) external onlyOwner {
        require(operator != address(0), "zero operator");
        operators[operator] = allowed;
        emit OperatorUpdated(operator, allowed);
    }

    function setBlocked(address user, bool blockedStatus) external onlyGuardian {
        require(user != address(0), "zero user");
        blocked[user] = blockedStatus;
        emit BlockedUpdated(user, blockedStatus);
    }

    function setFee(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= MAX_FEE_BPS, "fee too high");
        emit FeeUpdated(treasuryFeeBps, newFeeBps);
        treasuryFeeBps = newFeeBps;
    }

    function setMaxDailyWithdrawal(uint256 newLimit) external onlyOwner {
        require(newLimit > 0, "zero limit");
        maxDailyWithdrawal = newLimit;
    }

    function setFeeCollector(address newCollector) external onlyOwner {
        feeCollector = newCollector;
    }

    function setEmergencyCouncil(address newCouncil) external onlyOwner {
        emergencyCouncil = newCouncil;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }

    function pause() external onlyGuardian {
        paused = true;
    }

    function unpause() external onlyGuardian {
        paused = false;
    }

    function sweepTreasury(address payable to, uint256 amount) external onlyOwner {
        require(amount <= address(this).balance, "insufficient treasury");
        to.transfer(amount);
        emit TreasurySweep(to, amount);
    }

    function notifyPartner(address target, bytes calldata payload) external onlyOwner {
        target.call(payload);
    }

    function destroyTreasury() external onlyOwner {
        selfdestruct(payable(owner));
    }

    function accountOf(address user) external view returns (uint256 deposited, uint256 withdrawn, uint256 rewardDebt, bool active) {
        Account storage account = accounts[user];
        return (account.deposited, account.withdrawn, account.rewardDebt, account.active);
    }

    function grantOf(uint256 id) external view returns (address recipient, uint256 amount, uint256 releaseTime, bool claimed) {
        Grant storage grant = grants[id];
        return (grant.recipient, grant.amount, grant.releaseTime, grant.claimed);
    }

    function proposalOf(uint256 id) external view returns (address target, uint256 value, uint256 approvals, bool executed) {
        Proposal storage proposal = proposals[id];
        return (proposal.target, proposal.value, proposal.approvals, proposal.executed);
    }

    function availableBalance(address user) external view returns (uint256) {
        return accounts[user].deposited + rewardCredits[user];
    }

    function netTreasuryBalance() external view returns (uint256) {
        return address(this).balance - totalFees;
    }

    function canWithdraw(address user, uint256 amount) external view returns (bool) {
        if (paused || blocked[user]) {
            return false;
        }
        if (accounts[user].deposited < amount) {
            return false;
        }
        return dailyWithdrawn[user] + amount <= maxDailyWithdrawal;
    }

    function projectedFee(uint256 amount) external view returns (uint256) {
        return (amount * treasuryFeeBps) / 10_000;
    }

    function isOperatorOrOwner(address user) external view returns (bool) {
        return operators[user] || user == owner;
    }
}
