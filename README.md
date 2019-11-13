# Awesome Blockchain Security

The purpose of this document is to gather public information on vulnerabilities introduced on Blockchains node software. 

## Bitcoin Core
- Language: C++

### Inflation bug
* https://bitcoincore.org/en/2018/09/20/notice/
* https://medium.com/@awemany/600-microseconds-b70f87b0b2a6

### Leaf Node weakness in Bitcoin Merkle Tree Design

This document describes a weakness in Bitcoin Design that reduces the security of SPV proofs and therefore SPV Wallets.

* https://bitslog.com/2018/06/09/leaf-node-weakness-in-bitcoin-merkle-tree-design/

### RPC service enable connections from other process

It is possible for another user on the system to quietly bind the IPv4 localhost port, and forward requests to the IPv6 localhost port, intercepting the request, response, and authentication credentials.
Note: This is a super low vulnerability, but it is good practice to add this kind of things in documentations.

* https://medium.com/@lukedashjr/cve-2018-20587-advisory-and-full-disclosure-a3105551e78b

### Combined output Overflow

On August 15 2010, it was discovered that block 74638 contained a transaction that created 184,467,440,737.09551616 bitcoins for three different addresses.
Two addresses received 92.2 billion bitcoins each, and whoever solved the block got an extra 0.01 BTC that did not exist prior to the transaction. This was possible because the code used for checking transactions before including them in a block didn't account for the case of outputs so large that they overflowed when summed.

* https://en.bitcoin.it/wiki/Value_overflow_incident

### Network-wide DoS using malleable signatures in alerts

An attacker build new signatures at a high rate by changing the signature of an alert still in circulation and therefore increasing dramatically the number of valid alerts spreading across the network. This leads to halting all Bitcoin nodes in the network by RAM exhaustion in approximately 4 hours.
* https://en.bitcoin.it/wiki/CVE-2012-4684 & https://en.bitcoin.it/wiki/CVE-2012-4683

### New DoS vulnerability by Forcing Continuous Hard Disk Seek/Read Activity

* https://en.bitcoin.it/wiki/CVE-2013-2293

### Multiple DoS Vulnerabilties 

* https://en.bitcoin.it/wiki/CVE-2012-3789

## CosmosSDK 
- Language: Go

### Security Advisory 05-30-2019 

A high severity vulnerability in the staking module was patched on the Cosmos network which allowed malicious actors to bypass token slashing for bad behavior. 

* https://forum.cosmos.network/t/critical-cosmossdk-security-advisory-updated/2211/11

### Advisory 09-30-2019

This vulnerability would have allowed for an attacker to carry out a Denial of Service attack against public sentry nodes on Tendermint-powered networks.

https://forum.cosmos.network/t/vulnerability-coordination-retrospective-cosmos-mainnet-security-advisory-magenta-09-30-2019/2850

## CPP-Ethereum 
Language: C++

### Talos Inteligence report - CPP-Ethereum libevm create2 Information Leak Vulnerability

* https://talosintelligence.com/vulnerability_reports/TALOS-2017-0503

### Talos Inteligence report - CPP-Ethereum JSON-RPC Denial Of Service Vulnerabilities

* https://talosintelligence.com/vulnerability_reports/TALOS-2017-0471

### Talos Inteligence report - CPP-Ethereum JSON-RPC miner_start improper authorization Vulnerability

* https://talosintelligence.com/vulnerability_reports/TALOS-2017-0469

## EOS
- Language: C++

### Remote code execution in node

* http://blogs.360.cn/post/eos-node-remote-code-execution-vulnerability.html

### Buffer Overflow Vulnerability in EOS's WAVM Library and also in latest WAVM Library Parent Repository

* https://hackerone.com/reports/363209

### Heap Buffer Overflow Vulnerability in EOS's forked repository of Binaryen Library and also in latest Binaryen Library Parent Repository

* https://hackerone.com/reports/363195

## Monero 
Language: C++

### Usage of memcmp may allow timing attacks
* https://hackerone.com/reports/363680

### Wallet balance bug enable theft from exchanges

* https://hackerone.com/reports/377592

### Attacker can trick monero wallet into reporting it received twice with alternative tx_keypubs

* https://hackerone.com/reports/379049

### JSON request to RPC triggers Stack Overflow in RPC Server

* https://hackerone.com/reports/390499

### DoS for remote nodes using Slow Loris attack

* https://hackerone.com/reports/390499

### Unauthorized access of Monero wallet by an unprivileged process

The RPC wallet service is not being authorized against the node service. This would allow other proccesess to take RPC wallet service's place.

* https://hackerone.com/reports/462442

### Zero-amount miner TX + RingCT allows monero wallet to receive arbitrary amount of monero

By mining a specially crafted block, that still passes daemon verification an attacker can create a miner transaction that appears to the wallet to include sum of XMR picked by the attacker. This can be exploited to steal money from exchanges.

* https://hackerone.com/reports/501585

## GoEthereum 
- Language: Go

### EVM dynamic array maybe occupy large memory 

* https://github.com/ethereum/go-ethereum/issues/18289

### Big hashes in BlockHashes can fill process memory 

* https://github.com/ethereum/go-ethereum/issues/251

### Remote DoS by memory exhaustion in the TxPool using MsgTxTy

* https://github.com/ethereum/go-ethereum/issues/252

### SEC-1 JSON RPC and WebSockets bind to all interfaces

* https://github.com/ethereum/go-ethereum/issues/328

### SEC-2 RPC services do not require authentication

* https://github.com/ethereum/go-ethereum/issues/329

### SEC-3 JSON RPC interface vulnerable to CSRF

* https://github.com/ethereum/go-ethereum/issues/330

### SEC-4 JSON RPC interface allows all origins

* https://github.com/ethereum/go-ethereum/issues/331

### SEC-5 Address Collision in secp256k1 key generation

* https://github.com/ethereum/go-ethereum/issues/332

### SEC-6 The Go secp256k1 lib does not validate secret key before generating EC key 

* https://github.com/ethereum/go-ethereum/issues/333

### SEC-7 Negative Value Transactions

* https://github.com/ethereum/go-ethereum/issues/342

### SEC-8 No stack size validation for some op codes

* https://github.com/ethereum/go-ethereum/issues/362

### SEC-11 Uncle validation does not correctly implement is-kin property  

* https://github.com/ethereum/go-ethereum/issues/387

### SEC-10 Uncle validation does not include all parts of block header validity function

* https://github.com/ethereum/go-ethereum/issues/381

### SEC-12 Block header validation function does not validate gas limit

* https://github.com/ethereum/go-ethereum/issues/389

### SEC-13 Parent issue for all uncle validation / logic security issues

* https://github.com/ethereum/go-ethereum/issues/415

### SEC-14 single DB lookup table for all objects pose consensus security risk

* https://github.com/ethereum/go-ethereum/issues/416

### SEC-15 Parent issue for all invalid data structures & missing type validations

* https://github.com/ethereum/go-ethereum/issues/417

### SEC-16 JSON RPC DoS vulnerability for large messages 

* https://github.com/ethereum/go-ethereum/issues/418

### SEC-17 VM out of memory DoS

* https://github.com/ethereum/go-ethereum/issues/419 

### SEC-18 RLP decoder unsafe allocation

* https://github.com/ethereum/go-ethereum/issues/420

### SEC-19 ECDSA recovery id (V) is casted from uint64 to single byte 

* https://github.com/ethereum/go-ethereum/issues/456

### SEC-20 VM program counter overflow

* https://github.com/ethereum/go-ethereum/issues/457

### SEC-21 back parameter in SIGNEXTEND instr uses uint64 instead of unsigned 256 int 

* https://github.com/ethereum/go-ethereum/issues/458

### SEC-22 CALLDATACOPY does not write zero to memory if input data offset exceeds input data size 

* https://github.com/ethereum/go-ethereum/issues/496

### SEC-23 CODECOPY and EXTCODECOPY offset parameter 64 bit overflow 

* https://github.com/ethereum/go-ethereum/issues/497

### SEC-24 Parent issue for ethash / PoW security issues

* https://github.com/ethereum/go-ethereum/issues/499

### SEC-25 ECIES library does not verify whether received point is on curve

* https://github.com/ethereum/go-ethereum/issues/502

### SEC-26 Go defer/recover pattern used to catch VM halting conditions

* https://github.com/ethereum/go-ethereum/issues/503

### SEC-27 Integer overflow in gas cost calculation of precompiled accounts

* https://github.com/ethereum/go-ethereum/issues/504

### SEC-29 Go zero values for missing struct fields in RLP decoding causes caller to panic

* https://github.com/ethereum/go-ethereum/issues/506 

### SEC-30 Unsigned tx handled as tx from the zero address

* https://github.com/ethereum/go-ethereum/issues/507

### SEC-31 Memory DoS by recursive contract calling

* https://github.com/ethereum/go-ethereum/issues/514

### SEC-32 VM memory Set function panic when memory is empty (0)

* https://github.com/ethereum/go-ethereum/issues/515

### SEC-33 New gas limit validation not handling when block's gas limit is lower than parent

* https://github.com/ethereum/go-ethereum/issues/595

### SEC-34 Add check for minGasLimit in new gas limit validation

* https://github.com/ethereum/go-ethereum/issues/597

### SEC-35 BLOCKHASH instruction DoS 
* https://github.com/ethereum/go-ethereum/issues/598

### SEC-36 Block header nonce overflow

* https://github.com/ethereum/go-ethereum/issues/599

### SEC-37 Block header gasUsed field not validated but set for the block

* https://github.com/ethereum/go-ethereum/issues/600

### SEC-38 call depth not decremented after return from CALL or CALLCODE

* https://github.com/ethereum/go-ethereum/issues/601

### SEC-39 Account nonce incremented before tx validation

* https://github.com/ethereum/go-ethereum/issues/602

### SEC-44 EC Recover precompiled contract does not pad input

* https://github.com/ethereum/go-ethereum/issues/1195

### SEC-45 DoS in hash downloader 

* https://github.com/ethereum/go-ethereum/issues/1231 

### SEC-47 Block header mixdigest field not validated 

* https://github.com/ethereum/go-ethereum/issues/1264

### SEC-48 DoS in transaction pool

* https://github.com/ethereum/go-ethereum/issues/1266

### SEC-49 JUMPDEST vulnerability 

* https://github.com/ethereum/go-ethereum/issues/1147

### SEC-50 RLPx AES CTR keystream reusage

* https://github.com/ethereum/go-ethereum/issues/1315

### SEC-51 Peer NewBlockMsg DoS

* https://github.com/ethereum/go-ethereum/issues/1319

### SEC-52 Network DoS from re-broadcast of txs with zero gas price

* https://github.com/ethereum/go-ethereum/issues/1320

### SEC-53 DoS in block_processor on txs with invalid EC sig

* https://github.com/ethereum/go-ethereum/issues/1384

## Multiple chains

### “Fake Stake” attacks on chain-based Proof-of-Stake cryptocurrencies

* https://medium.com/@dsl_uiuc/fake-stake-attacks-on-chain-based-proof-of-stake-cryptocurrencies-b8b05723f806

## Grin 
- Language: Rust

Node security audit

Most vulnerabilities described in the report can be grouped into the following categories, and special care should be taken to prevent these patterns from appearing again in the codebase:

    1- Directory path traversal leading to remote code execution
    2- Memory corruption vulnerabilities in unsafe code blocks located in third-party libraries
    3- Denial of service caused by Rust panics, expects, and unhandled error conditions
    4- Synchronization process denial of service caused by out-of-order P2P messages
    5- Storage-based denial of service caused by failure to clean up temporary files
    6- Node censorship through node ban feature abuse
    7- Failure to ban ill-behaved nodes leading to CPU-based denial of service
    8- Lack of validation of orphan blocks
    9- Insecure file handling leading to local privilege escalation


* https://coinspect.com/doc/CoinspectReportGrin2019.pdf

## Parity Ethereum
- Language: Rust

### RPC call causes panic

* https://github.com/paritytech/parity-ethereum/issues/1881

### [Sec Audit] 005 Integer Overflow while decoding untrusted RLP

* https://github.com/paritytech/parity-ethereum/issues/1277

### [Sec Audit] 004 Parity Panic via Integer Overflow in Block Genesis File

* https://github.com/paritytech/parity-ethereum/issues/1276

### Permissions of key files should be tightened
 
 * https://github.com/paritytech/parity-ethereum/issues/849
 
### Deadlock while syncing + JSONRPC

* https://github.com/paritytech/parity-ethereum/issues/1058
 
## RSK
- Language: Java

### ToB Audit - RSKj Runtime
Some of the most prominent issues are:
1. Resource Leaks in Trie
2. Erroneous Gas computaton in CALL breaks sending ether to a contract
3. Wrong msg.value parameter in create leads to a broken contract

* https://github.com/trailofbits/publications/blob/master/reviews/RSKj.pdf

### DoS through PeerExplorer

* https://hackerone.com/reports/363636

### Attacker can add arbitrary data to the blockchain without paying gas

* https://hackerone.com/reports/396954

## Tron
- Language: Java 

### DOS attack by consuming all CPU and using all available memory

* https://hackerone.com/reports/479144

## Zcash 
- Language: C++

### ZCash Zerocash protocol - Coinspect Audit

The outstanding issues were: 
1. ScriptSig malleability allows 51% attack by invalidating honest miners blocks
2. Erroneous nValueOut range check allows CPU-exhaustion attacks
3. Unlimited number of transaction proofs allows CPU-exhaustion attacks 
4. Improper destination path validation in RPC calls allows arbitrary command execution

* https://coinspect.com/doc/CoinspectReportZcash2016.pdf

### Overwinter - Coinspect Audit
The high risk issues are:
1. Transaction Expiry Enables Node Isolation Attack
2. Transaction Expiry Enables Transaction Flooding at No Cost

* https://coinspect.com/doc/CoinspectReportZcash2018.pdf


### Libsnark, Librustzcash, Zcash-seeder, Zcash-gitian Least Authority Audit

The most prominent issues are:
1. Pow leaks in ​windowed_exp
2. Exponent leaks via ​power​ function
 
* https://leastauthority.com/static/publications/LeastAuthority-Zcash-Implementation-Analysis-and-Overwinter-Specification.pdf


### ZCash Inflation Bug because of incorrect implementation of Zero-knowledge proofs

* https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/

### Ensure Spec mitigates Double Spending by Coliding InternalH
* https://github.com/zcash/zcash/issues/738

### Faerie Gold Vulnerability

This vulnerability would have made it possible to fool a Zcash user into thinking they received a bunch of spendable notes. In fact, when they try to spend the notes they will find that only one of them can be spent.

* https://github.com/zcash/zcash/issues/98
