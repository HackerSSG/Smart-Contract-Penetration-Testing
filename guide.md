# Web 3.0 and Smart Contracts

**Web 3.0** is the next generation of the internet, designed to be more decentralized, user-focused, and secure. Unlike Web 2.0, which relies on centralized platforms (like social media networks or online stores), Web 3.0 uses blockchain technology to give users control over their data and digital assets. It supports decentralized applications (dApps) and smart contracts.

---

## What is a Smart Contract in Web 3?

A **Smart Contract** is a self-executing contract where the terms of the agreement are written directly into code. These contracts run on blockchain networks (like Ethereum) and are automatically executed when certain conditions are met. They eliminate the need for intermediaries such as lawyers or banks, making transactions more secure, transparent, and efficient.

---

## Example of a Smart Contract

Imagine you’re renting an apartment using Web 3.0:

1. You and the landlord agree on a rental contract, but instead of signing a paper document, a smart contract is created on the Ethereum blockchain.
2. The smart contract contains the terms:
   - You need to pay $1000 for the first month's rent.
   - The landlord will give you the apartment keys once the payment is confirmed.
3. Once you send the $1000 in cryptocurrency (like Ethereum), the smart contract automatically checks if the payment is received.
4. If payment is received, the contract releases a digital key to you.

This process is automated, transparent, and doesn’t require a third-party intermediary.

---

## Smart Contract Example (Solidity)

```solidity
// Simple Smart Contract for Rent Agreement

pragma solidity ^0.8.0;

contract RentAgreement {
    address public landlord;
    address public tenant;
    uint public rentAmount = 1000;  // Rent amount in Ether
    bool public rentPaid = false;

    constructor(address _tenant) {
        landlord = msg.sender;  // The creator of the contract is the landlord
        tenant = _tenant;
    }

    // Function to pay rent
    function payRent() public payable {
        require(msg.sender == tenant, "Only the tenant can pay rent");
        require(msg.value == rentAmount, "Incorrect rent amount");
        
        rentPaid = true;  // Mark rent as paid
    }

    // Function to release apartment keys (simplified as a message)
    function releaseKeys() public view returns (string memory) {
        require(rentPaid, "Rent has not been paid yet");
        return "Keys released to the tenant!";
    }
}
```
## How It Works:

1. The landlord deploys the contract and sets the tenant's address.
2. The tenant pays the rent via the payRent() function.
3. Once the rent is paid, the releaseKeys() function confirms that the apartment keys can be given to the tenant.

# 20 Bugs in Smart Contracts

1. **Reentrancy Attack**
2. **Integer Overflow/Underflow**
3. **Timestamp Dependence**
4. **Gas Limit and Loops**
5. **Unchecked Call Return Values**
6. **Access Control Issues**
7. **Transaction Ordering Dependency (TOD) / Front-Running**
8. **Delegatecall Injection**
9. **Denial of Service (DoS) with Block Gas Limit**
10. **Untrusted Input**
11. **Default Visibility of State Variables**
12. **Unsafe External Calls**
13. **Insecure Randomness Generation**
14. **Poorly Managed Ownership**
15. **Improper Error Handling**
16. **Lack of Checks for Overflows in Arrays**
17. **Unprotected Functions**
18. **Unintended Token Transfers**
19. **Excessive Permissions for Contract Owners**
20. **Self-Destruct (Suicide) Vulnerabilities**

-------------------------------------------------------------------------------------
# 1-Reentrancy Attack in Smart Contracts

A **Reentrancy Attack** occurs when a contract makes an external call to another contract, and that external contract calls back into the original contract before the first execution is completed. This can lead to unexpected behaviors, such as draining funds or modifying contract state multiple times within a single transaction.

## How It Works:
1. Contract A sends funds to Contract B (via a call).
2. Contract B calls back into Contract A before the initial call to Contract A finishes.
3. Contract A executes unintended logic, potentially allowing Contract B to withdraw more funds than intended.

## Example Vulnerability:
```solidity
// Vulnerable contract example
contract Vulnerable {
    mapping(address => uint) public balances;

    // Function to withdraw funds
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        
        // Transfer funds to the caller
        msg.sender.call{value: _amount}(""); 
        
        // Update balance after transfer (vulnerable)
        balances[msg.sender] -= _amount;
    }
}
```
## Attack Scenario:
- The attacker deploys a malicious contract that exploits the vulnerability by repeatedly calling the `withdraw` function before the balance is updated.

## Where It Can Be Found:
- Common in contracts that perform **external calls** (e.g., `call`, `delegatecall`, `send`, or `transfer`) before updating the contract state (e.g., balances).
- Particularly found in contracts handling **fund transfers**.

## Prevention:
- **Checks-Effects-Interactions Pattern**: Always update the contract state (e.g., balances) before making external calls.
- Use the **pull-over-push pattern** for transfers (where users withdraw funds instead of sending them directly).
```solidity
// Secure contract using Checks-Effects-Interactions pattern
contract Secure {
    mapping(address => uint) public balances;

    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);

        // Update balance before transferring
        balances[msg.sender] -= _amount;

        // Transfer funds to the caller
        payable(msg.sender).transfer(_amount);
    }
}
```
-------------------------------------------------------------------
# 2-Integer Overflow/Underflow Attack

### Attack Scenario:
- **Integer Overflow** occurs when a value exceeds the maximum value a variable can store, while **Integer Underflow** occurs when a value goes below the minimum. This can lead to unexpected behavior, such as incorrect calculations or vulnerabilities in token transfers.
  
For example, a contract that doesn't properly check for overflow/underflow may allow an attacker to manipulate the contract by providing extreme values (like `2^256 - 1`), causing the variable to wrap around and potentially break the contract logic.

### Real-Life Scenario:
Imagine a simple **bank contract** that allows users to deposit and withdraw tokens. The contract is supposed to track the balance of each user, but it lacks proper checks for overflow/underflow. An attacker could attempt to withdraw more than they have by triggering an **underflow**, or deposit an extremely large number, causing the balance to overflow.

### Vulnerable Code Example:

```solidity
pragma solidity ^0.8.0;

contract Bank {
    mapping(address => uint) public balances;

    // Deposit funds into the contract
    function deposit(uint _amount) public {
        balances[msg.sender] += _amount;  // No check for overflow
    }

    // Withdraw funds from the contract
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;  // No check for underflow
    }
}
```
### How the Attack Works:

If the deposit function allows a user to deposit an extremely large value, such as 2^256 - 1, it could cause the balance to overflow.
An attacker could exploit this overflow by depositing a small amount, then withdrawing more than they should, triggering an underflow (e.g., withdrawing 1 when the balance is 0).

### Prevention:

Use SafeMath to ensure that mathematical operations do not cause overflow or underflow by automatically checking values.
Validate inputs to ensure that no invalid values (like excessively large deposits or negative withdrawals) are processed.

## Fixed Code Using SafeMath:
```solidity
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract SecureBank {
    using SafeMath for uint;
    mapping(address => uint) public balances;

    // Deposit funds into the contract with SafeMath
    function deposit(uint _amount) public {
        balances[msg.sender] = balances[msg.sender].add(_amount);  // Safe addition
    }

    // Withdraw funds from the contract with SafeMath
    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] = balances[msg.sender].sub(_amount);  // Safe subtraction
    }
}
```
### Why This Fix Works:

SafeMath ensures that all arithmetic operations are checked for overflow/underflow, preventing the vulnerabilities from occurring.
The **add** and **sub** functions from SafeMath automatically throw errors if the operation would cause an overflow or underflow.

This ensures that only valid transactions are processed, making the contract much more secure.

---------------------------------------------------------------------------------------------------------------
# 3-Timestamp Dependence Attack

### Attack Scenario:
- **Timestamp Dependence** occurs when a contract relies on the **block timestamp** for critical logic, such as calculating deadlines or triggering actions. Block timestamps can be manipulated by miners, as they have some flexibility in setting the timestamp of a block within a range of a few seconds. This can introduce vulnerabilities where an attacker can manipulate the behavior of the contract by influencing the block's timestamp.

### Real-Life Scenario:
Imagine a **crowdsale contract** that allows users to contribute to a token sale. The contract might use the block timestamp to determine when the sale ends. If an attacker can influence the timing of the sale, they could manipulate the outcome and possibly front-run or delay their own contributions to gain an unfair advantage.

### Vulnerable Code Example:

```solidity
pragma solidity ^0.8.0;

contract Crowdsale {
    uint public saleEndTime;
    uint public rate;  // Number of tokens per Ether
    mapping(address => uint) public contributions;

    constructor(uint _duration, uint _rate) {
        saleEndTime = block.timestamp + _duration;  // Dependence on timestamp
        rate = _rate;
    }

    // Function to contribute to the crowdsale
    function contribute() public payable {
        require(block.timestamp < saleEndTime, "Sale has ended");  // Timestamp dependent
        uint tokens = msg.value * rate;
        contributions[msg.sender] += tokens;
    }

    // Function to check if sale has ended
    function saleEnded() public view returns (bool) {
        return block.timestamp > saleEndTime;  // Timestamp dependent
    }
}
```

## How the Attack Works:

The contract relies on block.timestamp to determine the end of the sale.
Miners have the ability to manipulate the block timestamp within a small range.
An attacker could manipulate the timing of a block to influence the crowdsale end time, allowing them to contribute just before the sale ends or delay the sale’s end to make additional contributions.

## Prevention:

Avoid relying solely on the block timestamp for critical logic that determines outcomes, especially for deadlines or timing-based actions.
Consider using block numbers for certain time-sensitive actions, as block numbers are less likely to be manipulated by miners.
Use oracle services to get a more reliable and external source of time if precise timing is required.

## Fixed Code Using Block Number:
```solidity
pragma solidity ^0.8.0;

contract SecureCrowdsale {
    uint public saleEndBlock;
    uint public rate;
    mapping(address => uint) public contributions;

    constructor(uint _duration, uint _rate) {
        saleEndBlock = block.number + _duration;  // Use block number instead of timestamp
        rate = _rate;
    }

    // Function to contribute to the crowdsale
    function contribute() public payable {
        require(block.number < saleEndBlock, "Sale has ended");  // Block number dependent
        uint tokens = msg.value * rate;
        contributions[msg.sender] += tokens;
    }

    // Function to check if sale has ended
    function saleEnded() public view returns (bool) {
        return block.number > saleEndBlock;  // Block number dependent
    }
}

```
## Why This Fix Works:
Block numbers are harder to manipulate than timestamps, as they are directly tied to the network’s block production rate.
By using block numbers, the contract ensures that the sale cannot be manipulated by altering timestamps.
In scenarios where more precise timing is needed, using a trusted external oracle for time data can provide a more secure solution.

This approach reduces the risk of an attacker exploiting the contract by manipulating timestamps.

-----------------------------------------------------------------------------------------------------------
# 4-Gas Limit and Loops Attack

### Attack Scenario:
- **Gas Limit and Loops** issues occur when a contract performs a loop without considering the gas limit. Every transaction on the Ethereum network has a gas limit, which is the maximum amount of computational work a contract can perform. If a contract has a loop (such as iterating over an array or mapping) and the loop can run too many times, it may consume more gas than is allowed for a transaction. This can cause the transaction to fail, potentially making the contract unusable or leaving it open for a denial-of-service (DoS) attack.

For example, a contract that iterates over a large array to check conditions or make changes to each element can run into issues when the number of elements grows, leading to excessive gas usage.

### Real-Life Scenario:
Imagine a contract that allows users to transfer tokens to multiple addresses at once (a "batch transfer" function). If the array of addresses grows too large, the gas required to execute the loop may exceed the gas limit, causing the transaction to fail and the contract to be unusable for large batches.

### Vulnerable Code Example:

```solidity
pragma solidity ^0.8.0;

contract BatchTransfer {
    mapping(address => uint) public balances;

    // Function to transfer tokens to multiple addresses
    function batchTransfer(address[] memory recipients, uint amount) public {
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;  // Transfer tokens to each address
        }
    }
}
```
## How the Attack Works:

The contract has a loop in the batchTransfer function that iterates over all addresses in the recipients array.
If the array of recipients is too large, the loop will consume too much gas, causing the transaction to fail.
An attacker could exploit this by creating a large list of addresses, preventing others from using the contract or causing the contract to run out of gas.

## Prevention:

Limit the Number of Iterations: Restrict the size of arrays or the number of iterations in loops to prevent excessive gas consumption.
Split the Functionality: Use multiple transactions to handle large batches instead of one big transaction.
Check Gas Usage: Consider adding checks to ensure the contract won't run out of gas before completing a loop.

## Fixed Code with Iteration Limit:

```solidity
pragma solidity ^0.8.0;

contract SecureBatchTransfer {
    mapping(address => uint) public balances;

    uint public constant MAX_BATCH_SIZE = 100;  // Maximum number of recipients per batch

    // Function to transfer tokens to multiple addresses with a limit on batch size
    function batchTransfer(address[] memory recipients, uint amount) public {
        require(recipients.length <= MAX_BATCH_SIZE, "Batch size exceeds limit");
        for (uint i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;  // Transfer tokens to each address
        }
    }
}
```
## Why This Fix Works:

Limiting the batch size ensures that the contract won’t run into gas limit issues, as fewer iterations mean lower gas consumption.
Splitting large batches into smaller transactions can also prevent the gas limit from being exceeded and make the contract more scalable.

By restricting the number of iterations or splitting tasks across multiple transactions, we can protect the contract from running into gas limit problems and ensure it works efficiently even with a large number of recipients.

-----------------------------------------------------------------------------------------------------------

# 5-Unchecked Call Return Values Attack

### Attack Scenario:
- **Unchecked Call Return Values** refer to the scenario where a contract calls an external function but does not properly check the return value or the success of that call. In Ethereum smart contracts, external calls (such as calling other contracts or transferring funds) return a boolean value indicating whether the operation succeeded. If a contract does not handle this return value properly, it may lead to unexpected behavior or vulnerabilities, such as failing to properly transfer funds or incorrectly assuming a call was successful.

For example, if a contract calls another contract's function to transfer tokens but does not check whether the transfer was successful, it could unintentionally allow funds to be lost or not transferred as intended.

### Real-Life Scenario:
Imagine a contract that sends Ether to an external address. If the call fails (e.g., due to insufficient gas or the recipient's contract rejecting the call), the contract might not properly handle the failure and could continue executing, leading to funds being lost or state inconsistencies.

### Vulnerable Code Example:

```solidity
pragma solidity ^0.8.0;

contract FundTransfer {
    // Function to transfer Ether to an external address
    function transferFunds(address payable recipient, uint amount) public {
        recipient.transfer(amount);  // No check on success
    }
}
```

## How the Attack Works:

The transferFunds function sends Ether to a recipient address using the transfer function.
However, the return value of the transfer function is not checked. If the transfer fails for any reason (e.g., the recipient is a contract that rejects the transfer), the contract will continue executing, and the transaction will appear successful even though the transfer failed.
An attacker could exploit this by targeting a vulnerable contract with a recipient address that causes a failure in the transfer, resulting in unexpected behavior or loss of funds.

## Prevention:

Always check the return value of external calls to ensure they succeed. If the return value indicates failure, handle the error appropriately (e.g., revert the transaction).
For calls that do not return a value (like transfer), use try/catch or require statements to ensure the operation was successful.
Consider using the call method instead of transfer for better error handling.

## Fixed Code with Return Value Check:

```solidity
pragma solidity ^0.8.0;

contract SecureFundTransfer {
    // Function to transfer Ether to an external address with success check
    function transferFunds(address payable recipient, uint amount) public {
        (bool success, ) = recipient.call{value: amount}("");  // Use call and check success
        require(success, "Transfer failed");  // Revert if transfer fails
    }
}
```
## Why This Fix Works:

The call method returns a boolean success value that indicates whether the call was successful.
The contract checks the success value using require(). If the transfer fails (e.g., due to insufficient gas or a revert in the recipient contract), the transaction will revert, ensuring that the contract’s state remains consistent and no funds are lost.

By properly handling the return value of external calls, we can prevent unintended behavior and ensure that the contract interacts safely with other contracts.
