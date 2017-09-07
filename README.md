# pico-blockchain

Blockchain implementation in Python for fun.

## Features:

 * Human readable JSON-based protocol
 * In/out transactions & fast verification using UTXO
 * Built-in miner
 * P2P communication
 * Syncing the block tree to new clients on connect
 * RSA2048 keys and SHA256 hashes

## Basic usage:

```bash
$ python.py picoblockchain.py <listening port> <peer address:port> <peer address:port> ...
```

For example, to listen on port 44444 and connect to another peer on localhost port 44445, use:

```bash
$ python.py picoblockchain.py 44444 localhost:44445
```

This will automatically generate your address, start a miner and start a prompt where you can issue some commands:

* `send <amount> <address>` to send `amount` coins to `address`
* `address` to view your own address
* `balance` to view your balance
* `reorg` to perform a manual reorganization (recalculation of UTXO)
* `quit` to stop the program

### Pip dependencies:

 * twisted
 * pycrypto
 * simplejson

## What is NOT implemented

 * Variable proof of work difficulty (difficulty is fixed now, so more nodes = more blocks)
 * Spending coins from unverified transactions
 * Disk persistance (quit the program = coins gone)
 * Miner fees
 * Much more

## Help

### It's generating many blocks, really fast
Try increasing the DIFFICULTY on top of the file. You need to do this for all nodes for them to be compatible.
### When I send coins, they don't arrive
Unverified coins do not show up on the balance. Wait for the next block.
### When I restart the program, my coins are gone
Disk persistence is not implemented. Keys are kept in memory and are lost on a restart.

## License

Mozilla Public License Version 2.0
