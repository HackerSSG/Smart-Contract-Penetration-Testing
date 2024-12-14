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
