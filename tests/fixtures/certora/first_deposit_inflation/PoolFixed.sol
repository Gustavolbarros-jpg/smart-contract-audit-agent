// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// The same pool with the one-argument change the code already supports: `tokenToShares`
/// is asked to round up, so a nonzero deposit can no longer mint zero shares. Nothing
/// else differs from Pool.sol -- not a signature, not a state variable.
contract PoolFixed {
    IERC20 public loanToken;
    uint256 public totalShares;

    mapping(address => uint256) public balanceOf;

    constructor(address _loanToken) {
        loanToken = IERC20(_loanToken);
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "Amount must be greater than zero");

        uint256 _shares;
        if (totalShares == 0) {
            _shares = amount;
        } else {
            _shares = tokenToShares(amount, loanToken.balanceOf(address(this)), totalShares, true);
        }

        require(loanToken.transferFrom(msg.sender, address(this), amount), "TransferFrom failed");
        balanceOf[msg.sender] += _shares;
        totalShares += _shares;
    }

    function tokenToShares(
        uint256 _tokenAmount,
        uint256 _supplied,
        uint256 _sharesTotalSupply,
        bool roundUpCheck
    ) internal pure returns (uint256) {
        if (_supplied == 0) return _tokenAmount;
        uint256 shares = (_tokenAmount * _sharesTotalSupply) / _supplied;
        if (roundUpCheck && shares * _supplied < _tokenAmount * _sharesTotalSupply) shares++;
        return shares;
    }

    function withdraw(uint256 shares) external {
        require(shares > 0, "Shares must be greater than zero");
        require(balanceOf[msg.sender] >= shares, "Insufficient balance");

        uint256 tokenAmount = (shares * loanToken.balanceOf(address(this))) / totalShares;

        balanceOf[msg.sender] -= shares;
        totalShares -= shares;

        require(loanToken.transfer(msg.sender, tokenAmount), "Transfer failed");
    }
}
