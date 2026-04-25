// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Token {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() { owner = msg.sender; }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }

    function adminBurn(address from, uint256 amount) external {
        require(balances[from] >= amount, "Insufficient balance");
        balances[from] -= amount;
        totalSupply -= amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
