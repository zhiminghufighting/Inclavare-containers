package main

import (
	"fmt"
	"github.com/shelter/remoteattestation"
	"github.com/urfave/cli"
	"unsafe"
)

var RemoteMrencalve [32]byte
var RemoteMrsigner [32]byte

var sgxraCommand = cli.Command{
	Name:  "sgxra",
	Usage: "setup TLS security channel with remote server and fetch specified enclave mrencalve from QE and compare with local caculated mrenclave value based on software algorithm",
	ArgsUsage: `[command options]

EXAMPLE:
       # shelter mrencalve`,
	/*	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
		cli.StringFlag{
			Name:  "none",
			Usage: "none",
		},
	},*/

	SkipArgReorder: true,

	Action: func(cliContext *cli.Context) error {

		var add string
		add = cliContext.String("addr")
		//connect to encalved by TCP socket
		//ret := remoteattestation.RemoteTlsSetupTCP(add, (unsafe.Pointer)(&RemoteMrencalve[0]), (unsafe.Pointer)(&RemoteMrsigner[0]))
		//connect to ra-tls-server by unix sockeet
		ret := remoteattestation.RemoteTlsSetupSock(add, (unsafe.Pointer)(&RemoteMrencalve[0]), (unsafe.Pointer)(&RemoteMrsigner[0]))
		if ret != nil {
			fmt.Errorf("RemotTlsSetup failed with err %s \n", ret)
		}

		fmt.Printf("remote attestation with enclaved is successful.\n")
		return nil

	},
}
