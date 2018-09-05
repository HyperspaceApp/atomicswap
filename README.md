# Hyperspace-compatible cross-chain atomic swapping

On-chain atomic swaps for Hyperspace and other cryptocurrencies

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
  claimwithadaptor <local signature> <peer signature> <adaptor point> <adaptor>
  extractsecret <claim transaction> <local signature> <peer signature>
```
