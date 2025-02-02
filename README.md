# Limited Flow Covenant

![limited_flow_covenant](./assets/limited_flow_covenant.png)

## Architecture

For a simple example we will assume our limited spending condition is "signature from A"
and our "full power" spending condition is "signature from B and C".

### S spend policy

For our simple example `S` will be defined as `pk(A)`

### V covenant policy

`V` must be a taproot policy w/ an unspendable internal key (until musig2 support).

For our simple example we will define the `V` taptree w/ 3 leaves:

 - Locking path: `and(pk(B),pk(C))`
 - Presigning path: `thresh(3,pk(A),pk(B),pk(C))`
 - Recovery path: `thresh(3,pk(A),pk(B),pk(C),after(65_535))`

In theory we do not need a special presigning path but having the spending key
in the presigning set of keys and signing with the spending key only at broadcast time 
bring 2 interesting properties:

 - an attacker getting access to a presigned transaction cannot broadcast it.
 - in case of a loss of key A, presigned transactions cannot be broadcast, avoiding 
 "burning" the coin.

## CLI Usage

### Create a (covenant) chain of (presigned) tx

`lfc create <config_path>`

 - generate & display to user address at `V/0/1`
 - register V descriptor on `cov_keys` signing devices
 - register S descriptor on `spend_key` signing device
 - wait to get a (confirmed) coin at `V/0/0`
 - process chain of txs
 - sign txs w/ signers of `cov_keys` but not w/ `spend_key` signer
 - store presigned txs

### Generate a config file

`lfc conf <conf_path>`

 - Ask user to select account index (V/`?`/*)
 - Ask user to select network (default regtest)
 - Get xpub for `cov_keys` keys
 - Get xpub for `spend_key`
 - Ask user to select min delay between 2 rounds
 - Ask user to select max amount to unlock at each round
 - Ask user to register electrum server address
 - Generate V & S descriptors & check there is no (confirmed/unconfirmed) tx at `V/<index>/0` and `S/<index>/1`
 - Write config file

### Start an unlock round

`lfc unlock <conf_path>`

 - Check if the next presigned tx is broadcastable regarding its timelock
 - Ask user to register spending address
 - Ask user to register a spending amount
 - If there is a change, ask to choose relock it or not
 - Craft `unlock_tx` + `spend_tx`
 - sign `unlock_tx` & `spend_tx` w/ `spend_key`
 - broadcast package `[unlock_tx, spend_tx]`

### Lock

`lfc lock <conf_path>`

 - Broadcast a lock transaction that will replace the chain of unlocking 
 transaction.

 Note: this cannot really be considered as a recovery because it can be RBF'd
 by a spending package pying more fees.

### re Lock

`lfc relock <conf_path>`

 - In case there is a (non-locked) change after a spend:

   - craft a transaction that spend this change to `V/<index>/<x>` where `x`
     should be dynamically determined as `x = first unused address after V/<index>/<last_round>`
   - sign this transaction w/ `spend_key`
   - broadcast the transaction

### spend

`lfc spend <conf_path>`

 - In case there is a (non-locked) change after a spend:

     - Ask user to register spending address
     - Ask user to register a spending amount
     - If there is a change, ask to choose relock it or not
     - Craft transaction
     - sign `spend_key`
     - broadcast transaction
