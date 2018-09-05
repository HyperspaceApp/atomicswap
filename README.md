# Hyperspace-compatible cross-chain atomic swapping

This repository contains utilities to manually perform cross-chain atomic swaps between various supported pairs of cryptocurrencies. At the moment, support exists for the following coins and wallets:

* Space Cash ([Hyperspace Core](https://github.com/HyperspaceApp/Hyperspace))
* Siacoin ([Siacoin Core](https://gitlab.com/NebulousLabs/Sia))

Pull requests implementing support for additional cryptocurrencies and wallets
are encouraged. 

## Build Instructions

Pre-requirements:

  - Go 1.9 or later
  - [dep](https://github.com/golang/dep)

```
$ cd $GOPATH/src/github.com/HyperspaceApp
$ git clone https://github.com/HyperspaceApp/atomicswap && cd atomicswap
$ dep ensure
$ go install ./cmd/...
```

## Theory

## Create Keypairs and Build Transactions

![Workflow 1](/images/schnorr_swap_1.png)

## Sign Refund Transactions and Broadcast Funding Transactions

![Workflow 2](/images/schnorr_swap_2.png)

## Create Adaptor Signatures and Claim Coins

![Workflow 3](/images/schnorr_swap_3.png)

## Command line

Separate command line utilities are provided to handle the transactions required
to perform a cross-chain atomic swap for each supported blockchain.  For a swap
between Bitcoin and Decred, the two utilities `spaceatomicswap` and
`siaatomicswap` are used.  Both tools must be used by both parties performing
the swap.

All of the tools support the same eleven commands.  These commands are:

```
Commands:
  buildkeys
  buildtransactions <local private key> <local participant number> <peer public key> <refund address> <refund height> <claim address> <amount>
  buildnonce <local private key> <message>
  signrefund <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <peer refund transaction>
  verifyrefundsignature <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <local refund transaction> <peer refund signature>
  broadcast <transaction>
  buildadaptor
  signwithadaptor <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor>
  verifyadaptor <local private key> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor signature>
  claimwithadaptor <local signature> <peer signature> <claim transaction> <adaptor point> <adaptor>
  extractsecret <claim signature> <local signature> <peer signature>
```

**`buildkeys`**

The `buildkeys` command is performed by both participants, once for each chain, to create a total of 4 keypairs.


**`buildtransactions <local private key> <local participant number> <peer public key> <refund address> <refund height> <claim address> <amount>`**

The `buildtransactions` command generates the 3 transactions necessary to engage in an atomic swap. Each participant should run this command for the chain from which they will be sending coins.

The 3 transactions are as follows:
  - an initial, pre-signed, funding transaction, sending coins to a joint address
  - an unsigned refund transaction, sending coins to a <refund address> after <refund height> has occurred
  - an unsigned claim transaction, sending coins to your peer's <claim address>

The joint address is automatically built using a combination or your and your peer's public keys on the chain for which these transactions are being generated. The joint address public key is derived using the `<local private key>`, `<local participant number>`, and `<peer public key>` parameters.

The `<local participant number>` should always be 0 for the participant who doesn't build the secret adaptor and 1 for the participant who builds the secret adaptor.

The `<refund height>` should be set as some future point, say 24 hours later, for participant 0, and some much later future point, say 48 hours later, for participant 1.

`<amount>` is the amount of coins the transaction builder wants to send on this chain.
  
**`buildnonce <local private key> <message>`***

The `buildnonce` command builds a public nonce point from a given message. It is used to build a nonce point for the refund transaction.

**`signrefund <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <peer refund transaction>`**

The `signrefund` command generates a signature for the peer's refund transaction. `<nonce point 0>` corresponds to participant 0's nonce point generated from the refund transaction, and `<nonce poin 1>` corresponds to participant 1's nonce point.

**`verifyrefundsignature <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <local refund transaction> <peer refund signature>`**

The `verifyrefundsignature` command verifies that your peer's signature of your refund transaction is valid. If valid, the command will build and print a signed refund transaction that you can broadcast if desired.

**`broadcast <transaction>`**

The `broadcast` command broadcasts a raw transaction. If the transaction has not already been signed, the broadcast will fail.

**`buildadaptor`**

The `buildadaptor` command builds a secret adaptor scalar and a corresponding public elliptic curve point, the adaptor point.

**`signwithadaptor <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor>`**

The `signwithadaptor` command signs a claim transaction using the secret adaptor and the public adaptor point and outsput the signature. This command is used by participant 1 to sign the claim transactions on both chains.

**`verifyadaptor <local private key> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor signature>`**

The `verifyadaptor` command verifies the peer's `<adaptor signature>` is valid for the given `<claim transaction>`. If valid, the command also generates and prints your own adaptor signature.

**`claimwithadaptor <local signature> <peer signature> <claim transaction> <adaptor point> <adaptor>`**

The `claimwithadaptor` command aggregates `<local signature>`, `<peer signature>`, and `<adaptor>` to make a valid signature for `<claim transaction>`. The valid claim signature from `<claim transaction>`, when broadcasted to the network, will leak the `<adaptor>` to your peer - and only to your peer.

**`extractsecret <claim signature> <local signature> <peer signature>`**

The `extractsecret` command subtracts the `<local signature>` and `<peer signature>` from `<claim signature>` to deduce the secret `<adaptor>`. With this, you can call `claimwithadaptor` to retrieve your coins.
