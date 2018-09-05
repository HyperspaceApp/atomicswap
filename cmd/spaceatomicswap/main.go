// Copyright (c) 2017 The Decred developers
// Copyright (c) 2018 The Hyperspace developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"encoding/base64"


	"github.com/HyperspaceApp/Hyperspace/crypto"
	"github.com/HyperspaceApp/Hyperspace/node/api/client"
	"github.com/HyperspaceApp/Hyperspace/encoding"
	"github.com/HyperspaceApp/Hyperspace/types"
	"github.com/HyperspaceApp/ed25519"
	"github.com/HyperspaceApp/fastrand"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// AdaptorSize is the size, in bytes, of secret adaptors used in adaptor signatures
	AdaptorSize = 32
	// CurvePointSize is the size, in bytes, of a point on the elliptic curve
	CurvePointSize = 32
)

var (
	flagset     = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag = flagset.String("s", "localhost:5580", "host[:port] of Hyperspace RPC server")
	ErrCurvePointWrongLen = errors.New("encoded value has the wrong length to be a curve point")
)

type (
        // PublicKey is an object that can be used to verify signatures.
        PublicKey [PublicKeySize]byte

        // SecretKey can be used to sign data for the corresponding public key.
        PrivateKey [PrivateKeySize]byte

        // Signature proves that data was signed by the owner of a particular
        // public key's corresponding secret key.
        Signature [SignatureSize]byte

	// Adaptor is the type of secret adaptors used in adaptor signatures
	Adaptor [AdaptorSize]byte

	// CurvePoint represents a point on the elliptic curve.
	CurvePoint [CurvePointSize]byte
)


func (cp *CurvePoint) String() string {
	return hex.EncodeToString(cp[:])
}

func (cp *CurvePoint) LoadString(s string) error {
	// *2 because there are 2 hex characters per byte.
	if len(s) != CurvePointSize*2 {
	        return ErrCurvePointWrongLen
	}
	cpBytes, err := hex.DecodeString(s)
	if err != nil {
	        return errors.New("could not unmarshal curve point: " + err.Error())
	}
	copy(cp[:], cpBytes)
	return nil
}



func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: siaatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  buildkeys")
		fmt.Println("  buildtransactions <local private key> <local participant number> <peer public key> <refund address> <refund height> <claim address> <amount>")
		fmt.Println("  buildnoncepoint <local private key> <message>")
		fmt.Println("  signrefund <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <peer refund transaction>")
		fmt.Println("  verifyrefundsignature <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <local refund transaction> <peer refund signature>")
		fmt.Println("  broadcast <transaction>")
		fmt.Println("  buildadaptor")
		fmt.Println("  signwithadaptor <local private key> <local participant number> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor>")
		fmt.Println("  verifyadaptor <local private key> <peer public key> <nonce point 0> <nonce point 1> <adaptor point> <claim transaction> <adaptor signature>")
		fmt.Println("  claimwithadaptor <local signature> <peer signature> <claim transaction> <adaptor point> <adaptor>")
		fmt.Println("  extractsecret <claim transaction> <local signature> <peer signature>")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(context.Context, client.Client) error
}

// offline commands don't require wallet RPC.
type offlineCommand interface {
	command
	runOfflineCommand() error
}

type buildKeysCmd struct {}

type buildTransactionsCmd struct {
	privateKey ed25519.PrivateKey
	participantNum int
	peerPublicKey ed25519.PublicKey
	refundAddress types.UnlockHash
	refundHeight types.BlockHeight
	claimAddress types.UnlockHash
	amount types.Currency
}

type buildNoncePointCmd struct {
	privateKey ed25519.PrivateKey
	message []byte
}

type signRefundCmd struct {
	privateKey ed25519.PrivateKey
	participantNum int
	peerPublicKey ed25519.PublicKey
	noncePoint0 CurvePoint
	noncePoint1 CurvePoint
	refundTransaction types.Transaction
}

type verifyRefundSignatureCmd struct {
	privateKey ed25519.PrivateKey
	participantNum int
	peerPublicKey ed25519.PublicKey
	noncePoint0 CurvePoint
	noncePoint1 CurvePoint
	refundTransaction types.Transaction
	peerRefundSignature Signature
}

type broadcastCmd struct {
	transaction types.Transaction
}

type buildAdaptorCmd struct {}

type verifyAdaptorCmd struct {
	privateKey ed25519.PrivateKey
	peerPublicKey ed25519.PublicKey
	noncePoint0 CurvePoint
	noncePoint1 CurvePoint
	adaptorPoint CurvePoint
	claimTransaction types.Transaction
	adaptorSignature Signature
}

type signWithAdaptorCmd struct {
	privateKey ed25519.PrivateKey
	participantNum int
	peerPublicKey ed25519.PublicKey
	noncePoint0 CurvePoint
	noncePoint1 CurvePoint
	adaptorPoint CurvePoint
	claimTransaction types.Transaction
	adaptor Adaptor
}

type claimWithAdaptorCmd struct {
	localSignature Signature
	peerSignature Signature
	claimTransaction types.Transaction
	adaptorPoint CurvePoint
	adaptor Adaptor
}

type extractSecretCmd struct {
	claimSignature Signature
	localSignature Signature
	peerSignature Signature
}

func main() {
	err, showUsage := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if showUsage {
		flagset.Usage()
	}
	if err != nil || showUsage {
		os.Exit(1)
	}
}

func checkCmdArgLength(args []string, required int) (nArgs int) {
	if len(args) < required {
		return 0
	}
	for i, arg := range args[:required] {
		if len(arg) != 1 && strings.HasPrefix(arg, "-") {
			return i
		}
	}
	return required
}

func run() (err error, showUsage bool) {
	flagset.Parse(os.Args[1:])
	args := flagset.Args()
	if len(args) == 0 {
		return nil, true
	}
	cmdArgs := 0
	switch args[0] {
	case "buildkeys":
		cmdArgs = 0
	case "buildtransactions":
		cmdArgs = 7
	case "buildnoncepoint":
		cmdArgs = 2
	case "signrefund":
		cmdArgs = 6
	case "verifyrefundsignature":
		cmdArgs = 7
	case "broadcast":
		cmdArgs = 1
	case "buildadaptor":
		cmdArgs = 0
	case "verifyadaptor":
		cmdArgs = 7
	case "signwithadaptor":
		cmdArgs = 8
	case "claimwithadaptor":
		cmdArgs = 4
	case "extractsecret":
		cmdArgs = 3
	default:
		return fmt.Errorf("unknown command %v", args[0]), true
	}
	nArgs := checkCmdArgLength(args[1:], cmdArgs)
	flagset.Parse(args[1+nArgs:])
	if nArgs < cmdArgs {
		return fmt.Errorf("%s: too few arguments", args[0]), true
	}
	if flagset.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", flagset.Arg(0)), true
	}

	var cmd command
	switch args[0] {
	case "buildkeys":
		cmd = &buildKeysCmd{}
	case "buildtransactions":
		var privateKey ed25519.PrivateKey
		privateKey = make([]byte, PrivateKeySize)
		var peerPublicKey ed25519.PublicKey
		peerPublicKey = make([]byte, PublicKeySize)
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		copy(privateKey[:], privateKeyBytes[:])
		participantNum64, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			return err, true
		}
		participantNum := int(participantNum64)
		peerPublicKeyBytes, err := encoding.HexStringToBytes(args[3])
		if err != nil {
			return err, true
		}
		copy(peerPublicKey[:], peerPublicKeyBytes[:])
		var refundAddress types.UnlockHash
		err = refundAddress.LoadString(args[4])
		if err != nil {
			return err, true
		}
		height, err := strconv.ParseUint(args[5], 10, 64)
		if err != nil {
			return err, true
		}
		var claimAddress types.UnlockHash
		err = claimAddress.LoadString(args[6])
		if err != nil {
			return err, true
		}
		amountF64, err := strconv.ParseFloat(args[7], 64)
		if err != nil {
			return err, true
		}
		hastings := types.SiacoinPrecision.MulFloat(amountF64)
		cmd = &buildTransactionsCmd{
			privateKey: privateKey,
			participantNum: participantNum,
			peerPublicKey: peerPublicKey,
			refundAddress: refundAddress,
			refundHeight: types.BlockHeight(height),
			amount: hastings,
			claimAddress: claimAddress,
		}
	case "buildnoncepoint":
		var privateKey ed25519.PrivateKey
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		privateKey = make([]byte, PrivateKeySize)
		copy(privateKey[:], privateKeyBytes[:])
		message, err := encoding.HexStringToBytes(args[2])
		if err != nil {
			return err, true
		}
		cmd = &buildNoncePointCmd{
			privateKey: privateKey,
			message: message,
		}
	case "signrefund":
		var privateKey ed25519.PrivateKey
		var peerPublicKey ed25519.PublicKey
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		privateKey = make([]byte, PrivateKeySize)
		copy(privateKey[:], privateKeyBytes[:])
		participantNum64, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			return err, true
		}
		participantNum := int(participantNum64)
		peerPublicKeyBytes, err := encoding.HexStringToBytes(args[3])
		if err != nil {
			return err, true
		}
		peerPublicKey = make([]byte, PublicKeySize)
		copy(peerPublicKey[:], peerPublicKeyBytes[:])
		var noncePoint0, noncePoint1 CurvePoint
		err = noncePoint0.LoadString(args[4])
		if err != nil {
			return err, true
		}
		err = noncePoint1.LoadString(args[5])
		if err != nil {
			return err, true
		}
		var refundTx types.Transaction
		refundTxBytes, err := base64.StdEncoding.DecodeString(args[6])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(refundTxBytes, &refundTx)
		if err != nil {
			return err, true
		}
		cmd = &signRefundCmd{
			privateKey: privateKey,
			participantNum: participantNum,
			peerPublicKey: peerPublicKey,
			noncePoint0: noncePoint0,
			noncePoint1: noncePoint1,
			refundTransaction: refundTx,
		}
	case "verifyrefundsignature":
		var privateKey ed25519.PrivateKey
		var peerPublicKey ed25519.PublicKey
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		privateKey = make([]byte, PrivateKeySize)
		copy(privateKey[:], privateKeyBytes[:])
		participantNum64, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			return err, true
		}
		participantNum := int(participantNum64)
		peerPublicKeyBytes, err := encoding.HexStringToBytes(args[3])
		if err != nil {
			return err, true
		}
		peerPublicKey = make([]byte, PublicKeySize)
		copy(peerPublicKey[:], peerPublicKeyBytes[:])
		var noncePoint0, noncePoint1 CurvePoint
		err = noncePoint0.LoadString(args[4])
		if err != nil {
			return err, true
		}
		err = noncePoint1.LoadString(args[5])
		if err != nil {
			return err, true
		}
		var refundTx types.Transaction
		refundTxBytes, err := base64.StdEncoding.DecodeString(args[6])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(refundTxBytes, &refundTx)
		if err != nil {
			return err, true
		}
		sig, err := encoding.HexStringToBytes(args[7])
		if err != nil {
			return err, true
		}
		var signature Signature
		copy(signature[:], sig[:])
		cmd = &verifyRefundSignatureCmd{
			privateKey: privateKey,
			participantNum: participantNum,
			peerPublicKey: peerPublicKey,
			noncePoint0: noncePoint0,
			noncePoint1: noncePoint1,
			refundTransaction: refundTx,
			peerRefundSignature: signature,
		}
	case "broadcast":
		var tx types.Transaction
		txBytes, err := base64.StdEncoding.DecodeString(args[1])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(txBytes, &tx)
		if err != nil {
			return err, true
		}
		cmd = &broadcastCmd{
			transaction: tx,
		}
	case "buildadaptor":
		cmd = &buildAdaptorCmd{}
	case "verifyadaptor":
		var privateKey ed25519.PrivateKey
		var peerPublicKey ed25519.PublicKey
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		privateKey = make([]byte, PrivateKeySize)
		peerPublicKey = make([]byte, PublicKeySize)
		copy(privateKey[:], privateKeyBytes[:])
		peerPublicKeyBytes, err := encoding.HexStringToBytes(args[2])
		if err != nil {
			return err, true
		}
		copy(peerPublicKey[:], peerPublicKeyBytes[:])
		var noncePoint0, noncePoint1, adaptorPoint CurvePoint
		err = noncePoint0.LoadString(args[3])
		if err != nil {
			return err, true
		}
		err = noncePoint1.LoadString(args[4])
		if err != nil {
			return err, true
		}
		err = adaptorPoint.LoadString(args[5])
		if err != nil {
			return err, true
		}
		var claimTx types.Transaction
		claimTxBytes, err := base64.StdEncoding.DecodeString(args[6])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(claimTxBytes, &claimTx)
		if err != nil {
			return err, true
		}
		sig, err := encoding.HexStringToBytes(args[7])
		if err != nil {
			return err, true
		}
		var signature Signature
		copy(signature[:], sig[:])
		cmd = &verifyAdaptorCmd{
			privateKey: privateKey,
			peerPublicKey: peerPublicKey,
			noncePoint0: noncePoint0,
			noncePoint1: noncePoint1,
			adaptorPoint: adaptorPoint,
			claimTransaction: claimTx,
			adaptorSignature: signature,
		}
	case "signwithadaptor":
		var privateKey ed25519.PrivateKey
		var peerPublicKey ed25519.PublicKey
		privateKeyBytes, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		privateKey = make([]byte, PrivateKeySize)
		participantNum64, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			return err, true
		}
		participantNum := int(participantNum64)
		peerPublicKey = make([]byte, PublicKeySize)
		copy(privateKey[:], privateKeyBytes[:])
		peerPublicKeyBytes, err := encoding.HexStringToBytes(args[3])
		if err != nil {
			return err, true
		}
		copy(peerPublicKey[:], peerPublicKeyBytes[:])
		var noncePoint0, noncePoint1, adaptorPoint CurvePoint
		err = noncePoint0.LoadString(args[4])
		if err != nil {
			return err, true
		}
		err = noncePoint1.LoadString(args[5])
		if err != nil {
			return err, true
		}
		err = adaptorPoint.LoadString(args[6])
		if err != nil {
			return err, true
		}
		var claimTx types.Transaction
		claimTxBytes, err := base64.StdEncoding.DecodeString(args[7])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(claimTxBytes, &claimTx)
		if err != nil {
			return err, true
		}
		adaptorBytes, err := encoding.HexStringToBytes(args[8])
		if err != nil {
			return err, true
		}
		var adaptor Adaptor
		copy(adaptor[:], adaptorBytes[:])
		cmd = &signWithAdaptorCmd{
			privateKey: privateKey,
			participantNum: participantNum,
			peerPublicKey: peerPublicKey,
			noncePoint0: noncePoint0,
			noncePoint1: noncePoint1,
			adaptorPoint: adaptorPoint,
			claimTransaction: claimTx,
			adaptor: adaptor,
		}
	case "claimwithadaptor":
		localSig, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		var localSignature Signature
		copy(localSignature[:], localSig[:])
		peerSig, err := encoding.HexStringToBytes(args[2])
		if err != nil {
			return err, true
		}
		var peerSignature Signature
		copy(peerSignature[:], peerSig[:])
		var claimTx types.Transaction
		claimTxBytes, err := base64.StdEncoding.DecodeString(args[3])
		if err != nil {
			return err, true
		}
		err = encoding.Unmarshal(claimTxBytes, &claimTx)
		if err != nil {
			return err, true
		}
		var adaptorPoint CurvePoint
		err = adaptorPoint.LoadString(args[4])
		if err != nil {
			return err, true
		}
		var adaptor Adaptor
		adaptorBytes, err := encoding.HexStringToBytes(args[5])
		if err != nil {
			return err, true
		}
		copy(adaptor[:], adaptorBytes[:])
		cmd = &claimWithAdaptorCmd{
			localSignature: localSignature,
			peerSignature: peerSignature,
			claimTransaction: claimTx,
			adaptorPoint: adaptorPoint,
			adaptor: adaptor,
		}
	case "extractsecret":
		claimSig, err := encoding.HexStringToBytes(args[1])
		if err != nil {
			return err, true
		}
		var claimSignature Signature
		copy(claimSignature[:], claimSig[:])
		localSig, err := encoding.HexStringToBytes(args[2])
		if err != nil {
			return err, true
		}
		var localSignature Signature
		copy(localSignature[:], localSig[:])
		peerSig, err := encoding.HexStringToBytes(args[3])
		if err != nil {
			return err, true
		}
		var peerSignature Signature
		copy(peerSignature[:], peerSig[:])
		cmd = &extractSecretCmd{
			claimSignature: claimSignature,
			localSignature: localSignature,
			peerSignature: peerSignature,
		}
	}

	// Offline commands don't need to talk to the wallet.
	if cmd, ok := cmd.(offlineCommand); ok {
		return cmd.runOfflineCommand(), false
	}

	var client client.Client
	client.Address = *connectFlag
	client.UserAgent = "Hyperspace-Agent"
	err = cmd.runCommand(context.Background(), client)
	return err, false
}

// GenerateKeyPair creates a public-secret keypair that can be used to sign and verify
// messages.
func GenerateKeyPair() (sk ed25519.PrivateKey, pk ed25519.PublicKey) {
        // no error possible when using fastrand.Reader
        epk, esk, _ := ed25519.GenerateKey(fastrand.Reader)
	sk = make([]byte, ed25519.PrivateKeySize)
	pk = make([]byte, ed25519.PublicKeySize)
        copy(sk[:], esk)
        copy(pk[:], epk)
        return
}

func publicKeyToAddress(pk ed25519.PublicKey) types.UnlockHash {
	var cryptoPk crypto.PublicKey
	copy(cryptoPk[:], pk[:])
	siaPk := types.Ed25519PublicKey(cryptoPk)
	unlockConditions := types.UnlockConditions{
		PublicKeys:         []types.SiaPublicKey{siaPk},
		SignaturesRequired: 1,
	}
	unlockHash := unlockConditions.UnlockHash()
	return unlockHash
}

func buildCurvePoint(privateKey ed25519.PrivateKey, message []byte) ed25519.CurvePoint {
	noncePoint := ed25519.GenerateNoncePoint(privateKey, message)
	return noncePoint
}

func (cmd *buildKeysCmd) runCommand(ctx context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *buildKeysCmd) runOfflineCommand() error {
	sk, pk := GenerateKeyPair()
	unlockHash := publicKeyToAddress(pk).String()
	fmt.Printf("private key: %s\npublic key: %s\nrefund unlock hash: %s\n", encoding.BytesToHexString(sk[:]), encoding.BytesToHexString(pk[:]), unlockHash)
	return nil
}

func (cmd *buildTransactionsCmd) runCommand(ctx context.Context, c client.Client) error {
	var localPublicKey ed25519.PublicKey
	localPublicKey = make([]byte, PublicKeySize)
	copy(localPublicKey[:], cmd.privateKey[32:])
	var publicKey0, publicKey1 ed25519.PublicKey
	if cmd.participantNum == 0 {
		publicKey0 = localPublicKey
		publicKey1 = cmd.peerPublicKey
	} else {
		publicKey0 = cmd.peerPublicKey
		publicKey1 = localPublicKey
	}
	_, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, cmd.participantNum)
	jointPublicKey, _, _, _ := ed25519.GenerateJointKey(publicKey0, publicKey1)
	unlockHash := publicKeyToAddress(jointPublicKey)
	fmt.Printf("joint address: %s\n", unlockHash.String())
	wbtg, err := c.WalletBuildTransactionGet(unlockHash, cmd.amount)
	if err != nil {
		return err
	}
	txn := wbtg.Transaction
	fmt.Printf("funding transaction: %s\n", base64.StdEncoding.EncodeToString(encoding.Marshal(txn)))
	oid := txn.SiacoinOutputID(0)
	//fmt.Printf("scoid: %v\n", oid)
	var cryptoPk crypto.PublicKey
	copy(cryptoPk[:], jointPublicKey[:])
	siaPk := types.Ed25519PublicKey(cryptoPk)
	uc := types.UnlockConditions{PublicKeys: []types.SiaPublicKey{siaPk}, SignaturesRequired: 1}
	input := types.SiacoinInput{ParentID: oid, UnlockConditions: uc}
	wag, err := c.WalletAddressGet()
	if err != nil {
		return err
	}
	refundOutput := types.SiacoinOutput{UnlockHash: wag.Address, Value: cmd.amount}
	refundTxn := types.Transaction{SiacoinInputs: []types.SiacoinInput{input}, SiacoinOutputs: []types.SiacoinOutput{refundOutput}}
	refundSig := types.TransactionSignature{
		ParentID:       crypto.Hash(input.ParentID),
		CoveredFields:  types.FullCoveredFields,
		PublicKeyIndex: uint64(0),
		Timelock:       cmd.refundHeight,
	}
	refundTxn.TransactionSignatures = []types.TransactionSignature{refundSig}
	fmt.Printf("refund transaction: %s\n", base64.StdEncoding.EncodeToString(encoding.Marshal(refundTxn)))
	refundMsg := refundTxn.SigHash(0)
	refundMsgBytes := make([]byte, 32)
	copy(refundMsgBytes[:], refundMsg[:])
	fmt.Printf("refund message: %s\n", encoding.BytesToHexString(refundMsgBytes))
	refundNonce := buildCurvePoint(cmd.privateKey, refundMsgBytes)
	var cryptoRefundNonce, cryptoClaimNonce CurvePoint
	copy(cryptoRefundNonce[:], refundNonce[:])
	fmt.Printf("refund nonce point: %s\n", cryptoRefundNonce.String())

	claimOutput := types.SiacoinOutput{UnlockHash: cmd.claimAddress, Value: cmd.amount}
	claimTxn := types.Transaction{SiacoinInputs: []types.SiacoinInput{input}, SiacoinOutputs: []types.SiacoinOutput{claimOutput}}
	claimSig := types.TransactionSignature{
		ParentID:       crypto.Hash(input.ParentID),
		CoveredFields:  types.FullCoveredFields,
		PublicKeyIndex: uint64(0),
	}
	claimTxn.TransactionSignatures = []types.TransactionSignature{claimSig}
	fmt.Printf("claim transaction: %s\n", base64.StdEncoding.EncodeToString(encoding.Marshal(claimTxn)))
	claimMsg := claimTxn.SigHash(0)
	claimMsgBytes := make([]byte, 32)
	copy(claimMsgBytes[:], claimMsg[:])
	fmt.Printf("claim message: %s\n", encoding.BytesToHexString(claimMsgBytes))
	claimNonce := buildCurvePoint(cmd.privateKey, claimMsgBytes)
	copy(cryptoClaimNonce[:], claimNonce[:])
	fmt.Printf("claim nonce point: %s\n", cryptoClaimNonce.String())
	return nil
}

func (cmd *buildNoncePointCmd) runCommand(ctx context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *buildNoncePointCmd) runOfflineCommand() error {
	noncePoint := buildCurvePoint(cmd.privateKey, cmd.message)
	var cryptoNoncePoint CurvePoint
	copy(cryptoNoncePoint[:], noncePoint[:])
	fmt.Printf("nonce point: %s\n", cryptoNoncePoint.String())
	return nil
}

func (cmd *signRefundCmd) runCommand(ctx context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *signRefundCmd) runOfflineCommand() error {
	var localPublicKey ed25519.PublicKey
	localPublicKey = make([]byte, PublicKeySize)
	copy(localPublicKey[:], cmd.privateKey[32:])
	var publicKey0, publicKey1 ed25519.PublicKey
	if cmd.participantNum == 0 {
		publicKey0 = localPublicKey
		publicKey1 = cmd.peerPublicKey
	} else {
		publicKey0 = cmd.peerPublicKey
		publicKey1 = localPublicKey
	}
	jointPrivateKey, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, cmd.participantNum)
	if err != nil {
		return err
	}
	message := cmd.refundTransaction.SigHash(0)
	msgBytes := make([]byte, crypto.HashSize)
	noncePoint0Bytes := make([]byte, CurvePointSize)
	noncePoint1Bytes := make([]byte, CurvePointSize)
	copy(msgBytes[:], message[:])
	copy(noncePoint0Bytes[:], cmd.noncePoint0[:])
	copy(noncePoint1Bytes[:], cmd.noncePoint1[:])
	sig := ed25519.JointSign(cmd.privateKey, jointPrivateKey, noncePoint0Bytes, noncePoint1Bytes, msgBytes)
	fmt.Printf("signature: %s\n", encoding.BytesToHexString(sig))
	return nil
}

func (cmd *verifyRefundSignatureCmd) runCommand(ctx context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *verifyRefundSignatureCmd) runOfflineCommand() error {
	var localPublicKey ed25519.PublicKey
	localPublicKey = make([]byte, PublicKeySize)
	copy(localPublicKey[:], cmd.privateKey[32:])
	var publicKey0, publicKey1, jointPublicKey ed25519.PublicKey
	if cmd.participantNum == 0 {
		publicKey0 = localPublicKey
		publicKey1 = cmd.peerPublicKey
	} else {
		publicKey0 = cmd.peerPublicKey
		publicKey1 = localPublicKey
	}
	jointPrivateKey, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, cmd.participantNum)
	if err != nil {
		return err
	}
	jointPublicKey = make([]byte, PublicKeySize)
	copy(jointPublicKey[:], jointPrivateKey[32:])
	fmt.Printf("joint public string: %s\n", encoding.BytesToHexString(jointPublicKey))
	message := cmd.refundTransaction.SigHash(0)
	msgBytes := make([]byte, crypto.HashSize)
	noncePoint0Bytes := make([]byte, CurvePointSize)
	noncePoint1Bytes := make([]byte, CurvePointSize)
	peerSignatureBytes := make([]byte, SignatureSize)
	copy(msgBytes[:], message[:])
	fmt.Printf("msg string: %s\n", encoding.BytesToHexString(msgBytes))
	copy(noncePoint0Bytes[:], cmd.noncePoint0[:])
	copy(noncePoint1Bytes[:], cmd.noncePoint1[:])
	copy(peerSignatureBytes[:], cmd.peerRefundSignature[:])
	fmt.Printf("peer signature: %s\n", encoding.BytesToHexString(peerSignatureBytes))
	localSignatureBytes := ed25519.JointSign(cmd.privateKey, jointPrivateKey, noncePoint0Bytes, noncePoint1Bytes, msgBytes)
	fmt.Printf("local signature: %s\n", encoding.BytesToHexString(localSignatureBytes))
	signature := ed25519.AddSignature(localSignatureBytes, peerSignatureBytes)
	refundTx := cmd.refundTransaction
	refundTx.TransactionSignatures[0].Signature = signature
	if ed25519.Verify(jointPublicKey, msgBytes, signature) {
		fmt.Printf("signed refund transaction: %s\n", base64.StdEncoding.EncodeToString(encoding.Marshal(refundTx)))
	} else {
		fmt.Printf("failed to verify refund transaction signature")
	}
	return nil
}

func (cmd *broadcastCmd) runCommand(ct context.Context, c client.Client) error {
	err := c.TransactionPoolRawPost(cmd.transaction, nil)
	if err != nil {
		return err
	}
	tid := cmd.transaction.ID()
	fmt.Printf("broadcasted transaction: %s\n", encoding.BytesToHexString(tid[:]))
	return nil
}

func (cmd *buildAdaptorCmd) runCommand(ct context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *buildAdaptorCmd) runOfflineCommand() error {
	adaptor, adaptorPoint, err := ed25519.GenerateAdaptor(fastrand.Reader)
	if err != nil {
		return err
	}
	fmt.Printf("adaptor: %s\n", encoding.BytesToHexString(adaptor))
	fmt.Printf("adaptor point: %s\n", encoding.BytesToHexString(adaptorPoint))
	return nil
	/*
	var localPublicKey ed25519.PublicKey
	var publicKey0, publicKey1 ed25519.PublicKey
	localPublicKey = make([]byte, PublicKeySize)
	copy(localPublicKey[:], cmd.privateKey[32:])
	publicKey0 = cmd.peerPublicKey
	publicKey1 = localPublicKey
	jointPrivateKey, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, 1)
	if err != nil {
		return err
	}
	message := cmd.claimTransaction.SigHash(0)
	msgBytes := make([]byte, crypto.HashSize)
	copy(msgBytes[:], message[:])
	noncePoint0 := make([]byte, AdaptorSize)
	copy(noncePoint0[:], cmd.noncePoint0[:])
	noncePoint1 := buildCurvePoint(cmd.privateKey, msgBytes)
	fmt.Printf("nonce point: %s\n", encoding.BytesToHexString(noncePoint1))
	sig := ed25519.JointSignWithAdaptor(cmd.privateKey, jointPrivateKey, noncePoint0, noncePoint1, adaptorPoint, msgBytes)
	if err != nil {
		return err
	}
	fmt.Printf("signature: %s\n", encoding.BytesToHexString(sig))

	jointPublicKey, _, jointPublicKey1, _ := ed25519.GenerateJointKey(publicKey0, publicKey1)
	verified := ed25519.VerifyAdaptorSignature(jointPublicKey1, jointPublicKey, noncePoint0, noncePoint1, adaptorPoint, msgBytes, sig)
	if !verified {
		fmt.Printf("failed to verify local adaptor")
		return nil
	}
	return nil
	*/
}

func (cmd *verifyAdaptorCmd) runCommand(ct context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *verifyAdaptorCmd) runOfflineCommand() error {
	noncePoint0 := make([]byte, CurvePointSize)
	copy(noncePoint0[:], cmd.noncePoint0[:])
	fmt.Printf("noncePoint0: %s\n", encoding.BytesToHexString(noncePoint0))
	noncePoint1 := make([]byte, CurvePointSize)
	copy(noncePoint1[:], cmd.noncePoint1[:])
	fmt.Printf("noncePoint1: %s\n", encoding.BytesToHexString(noncePoint1))
	adaptorPoint := make([]byte, CurvePointSize)
	copy(adaptorPoint[:], cmd.adaptorPoint[:])
	fmt.Printf("adaptorPoint: %s\n", encoding.BytesToHexString(adaptorPoint))
	message := cmd.claimTransaction.SigHash(0)
	msgBytes := make([]byte, crypto.HashSize)
	copy(msgBytes[:], message[:])
	fmt.Printf("claim msg: %s\n", encoding.BytesToHexString(msgBytes))
	adaptorSignature := make([]byte, SignatureSize)
	copy(adaptorSignature[:], cmd.adaptorSignature[:])
	fmt.Printf("adaptor signature: %s\n", encoding.BytesToHexString(adaptorSignature))
	var publicKey0, publicKey1, jointPublicKey ed25519.PublicKey
	publicKey0 = make([]byte, PublicKeySize)
	copy(publicKey0[:], cmd.privateKey[32:])
	fmt.Printf("public key 0: %s\n", encoding.BytesToHexString(publicKey0))
	publicKey1 = cmd.peerPublicKey
	fmt.Printf("public key 1: %s\n", encoding.BytesToHexString(publicKey1))
	jointPrivateKey, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, 0)
	if err != nil {
		return err
	}
	jointPublicKey, _, jointPublicKey1, _ := ed25519.GenerateJointKey(publicKey0, publicKey1)
	fmt.Printf("joint public key: %s\n", encoding.BytesToHexString(jointPublicKey))
	fmt.Printf("joint public key 1: %s\n", encoding.BytesToHexString(jointPublicKey1))
	/*
	aggSigBytes := ed25519.AddSignature(noncePoint0, noncePoint1)
	aggSigBytes = ed25519.AddSignature(aggSigBytes, adaptorPoint)
	fmt.Printf("Agg R %v\n", aggSigBytes)
	*/
	verified := ed25519.VerifyAdaptorSignature(jointPublicKey1, jointPublicKey, noncePoint0, noncePoint1, adaptorPoint, msgBytes, adaptorSignature)
	fmt.Printf("verified: %t\n", verified)
	if verified {
		sig := ed25519.JointSignWithAdaptor(cmd.privateKey, jointPrivateKey, noncePoint0, noncePoint1, adaptorPoint, msgBytes)
		fmt.Printf("signature: %s\n", encoding.BytesToHexString(sig))
	}
	return nil
}
func (cmd *signWithAdaptorCmd) runCommand(ct context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *signWithAdaptorCmd) runOfflineCommand() error {
	var localPublicKey ed25519.PublicKey
	localPublicKey = make([]byte, PublicKeySize)
	copy(localPublicKey[:], cmd.privateKey[32:])
	var publicKey0, publicKey1 ed25519.PublicKey
	if cmd.participantNum == 0 {
		publicKey0 = localPublicKey
		publicKey1 = cmd.peerPublicKey
	} else {
		publicKey0 = cmd.peerPublicKey
		publicKey1 = localPublicKey
	}
	noncePoint0 := make([]byte, CurvePointSize)
	copy(noncePoint0[:], cmd.noncePoint0[:])
	noncePoint1 := make([]byte, CurvePointSize)
	copy(noncePoint1[:], cmd.noncePoint1[:])
	adaptorPoint := make([]byte, CurvePointSize)
	copy(adaptorPoint[:], cmd.adaptorPoint[:])
	message := cmd.claimTransaction.SigHash(0)
	msgBytes := make([]byte, crypto.HashSize)
	copy(msgBytes[:], message[:])
	jointPrivateKey, err := ed25519.GenerateJointPrivateKey(publicKey0, publicKey1, cmd.privateKey, cmd.participantNum)
	if err != nil {
		return err
	}
	localSigBytes := ed25519.JointSignWithAdaptor(cmd.privateKey, jointPrivateKey, noncePoint0, noncePoint1, adaptorPoint, msgBytes)
	fmt.Printf("signature: %s\n", encoding.BytesToHexString(localSigBytes))
	return nil
}

func (cmd *claimWithAdaptorCmd) runCommand(ct context.Context, c client.Client) error {
	localSigBytes := make([]byte, SignatureSize)
	copy(localSigBytes[:], cmd.localSignature[:])
	peerSigBytes := make([]byte, SignatureSize)
	copy(peerSigBytes[:], cmd.peerSignature[:])
	adaptorBytes := make([]byte, SignatureSize)
	copy(adaptorBytes[:], cmd.adaptorPoint[:])
	copy(adaptorBytes[32:], cmd.adaptor[:])
	/*
	jointPublicKey := make([]byte, PublicKeySize)
	copy(jointPublicKey[:], jointPrivateKey[32:])
	*/
	aggSigBytes := ed25519.AddSignature(peerSigBytes, localSigBytes)
	aggSigBytes = ed25519.AddSignature(aggSigBytes, adaptorBytes)
	/*
	if !ed25519.Verify(jointPublicKey, msgBytes, aggSigBytes) {
		fmt.Printf("verification failed\n")
		return nil
	}
	*/
	cmd.claimTransaction.TransactionSignatures[0].Signature = aggSigBytes
	fmt.Printf("signature: %s\n", encoding.BytesToHexString(aggSigBytes))
	err := c.TransactionPoolRawPost(cmd.claimTransaction, nil)
	if err != nil {
		return err
	} else {
		fmt.Printf("claimed coins with adaptor\n")
	}
	return nil
}

func (cmd *extractSecretCmd) runCommand(ct context.Context, c client.Client) error {
	return cmd.runOfflineCommand()
}

func (cmd *extractSecretCmd) runOfflineCommand() error {
	var claimSignature, localSignature, peerSignature ed25519.Scalar
	claimSignature = make([]byte, ed25519.ScalarSize)
	localSignature = make([]byte, ed25519.ScalarSize)
	peerSignature = make([]byte, ed25519.ScalarSize)
	copy(claimSignature[:], cmd.claimSignature[32:])
	copy(localSignature[:], cmd.localSignature[32:])
	copy(peerSignature[:], cmd.peerSignature[32:])
	buffer := localSignature.Add(peerSignature)
	adaptor := claimSignature.Subtract(buffer)
	fmt.Printf("deduced adaptor: %s\n", encoding.BytesToHexString(adaptor))
	return nil
}
