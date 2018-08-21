// Copyright (c) 2017 The Decred developers
// Copyright (c) 2018 The Hyperspace developers
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/HyperspaceApp/Hyperspace/node/api/client"
)

var (
	flagset     = flag.NewFlagSet("", flag.ExitOnError)
	connectFlag = flagset.String("s", "localhost", "host[:port] of Hyperspace RPC server")
)


func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: spaceatomicswap [flags] cmd [cmd args]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  buildkeys")
		fmt.Println("  buildtransactions <participant pubkey> <refund address> <refund height> <claim address> <amount>")
		fmt.Println("  signrefund <participant refund transaction>")
		fmt.Println("  broadcastfunding <funding transaction>")
		fmt.Println("  refund <refund transaction>")
		fmt.Println("  buildnonce <participant claim transaction>")
		fmt.Println("  buildnoncewithadapter <participant claim transaction>")
		fmt.Println("  claim <claim transaction> <signature>")
		fmt.Println("  extractsecret <participant claim transaction>")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

type command interface {
	runCommand(context.Context, client.Client) error
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

func run() (err error, showUsage bool) {
	flagset.Parse(os.Args[1:])
	args := flagset.Args()
	if len(args) == 0 {
		return nil, true
	}
	return nil, false
}
