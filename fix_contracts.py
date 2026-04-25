from pathlib import Path

base = Path("tests/contracts")
base.mkdir(parents=True, exist_ok=True)

base.joinpath("bank.sol").write_text(
"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Bank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
""", encoding="utf-8")

base.joinpath("token.sol").write_text(
"""// SPDX-License-Identifier: MIT
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
""", encoding="utf-8")

base.joinpath("safe_token.sol").write_text(
"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract SafeToken {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    bool private _locked;

    modifier nonReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() { owner = msg.sender; }

    function mint(address to, uint256 amount) external onlyOwner {
        balances[to] += amount;
        totalSupply += amount;
    }

    function adminBurn(address from, uint256 amount) external onlyOwner {
        require(balances[from] >= amount, "Insufficient balance");
        balances[from] -= amount;
        totalSupply -= amount;
    }

    function transfer(address to, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
""", encoding="utf-8")

print("All 3 contract files written successfully.")
for f in base.iterdir():
    lines = f.read_text(encoding="utf-8").splitlines()
    print(f"  {f.name}: line1={lines[0]!r}  line2={lines[1]!r}")
