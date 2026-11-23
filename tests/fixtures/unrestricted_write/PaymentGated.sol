// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

// NEGATIVE: bid() overwrites a fund-sink address with no caller check, but only for a
// caller who outbids a stored price; the write is sold, not unrestricted (auction shape).
contract PaymentGated {
    address public owner;
    address public highestBidder;
    uint256 public highestBid;

    constructor() {
        owner = msg.sender;
        highestBidder = msg.sender;
    }

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        payable(highestBidder).transfer(highestBid);
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function reset(address bidder) external {
        require(msg.sender == owner, "not owner");
        highestBidder = bidder;
    }
}
