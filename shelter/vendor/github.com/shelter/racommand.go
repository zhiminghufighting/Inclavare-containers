package main

import (
	"fmt"
	"github.com/shelter/remoteattestation"
	"github.com/shelter/utils"
	"github.com/shelter/verification"
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
		var mrenclave [32]byte
		add = cliContext.String("addr")
		ret := remoteattestation.RemoteTlsSetupTCP(add, (unsafe.Pointer)(&RemoteMrencalve[0]), (unsafe.Pointer)(&RemoteMrsigner[0]))
		for i := 0; i < 32; i++ {
			fmt.Printf("mrencalve this is the %x number with value %x.\n", i, RemoteMrencalve[i])
		}
		//ret := remoteattestation.RemoteTlsSetupSock(add, &RemoteMrencalve[0], &RemoteMrsigner[0])
		if ret != nil {
			fmt.Errorf("RemotTlsSetup failed with err %s \n", ret)
		}

		if Globalurl == "" {
			Globalurl = defaultsrcurl
		}

		if Globalbranch == "" {
			Globalbranch = defaultsrcbranch
		}

		if ret := utils.GetSrcCode(Globalurl, Globalbranch, "", defaultlocalpath); ret != true {
			fmt.Errorf("get src code failed.")
			return nil
		}

		srcpath := string(defaultscrpathprefix + defaultscrpathsuffix)
		if true != utils.BuildTargetSrc(srcpath) {
			fmt.Errorf("build src code failed.\n")
			return nil
		}

		targetbinpath := targetencbinpath + targetencbin
		if true != verification.Measure_Encl(targetbinpath, unsafe.Pointer(&mrenclave[0])) {
			fmt.Errorf("measure mrenclave failed.\n")
			return nil
		}

		if true != verification.Mrencalve_Verify(unsafe.Pointer(&RemoteMrencalve[0]), unsafe.Pointer(&mrenclave[0])) {
			fmt.Errorf("mismatch with sigstruct mrencalve value.\n")
			return nil
		}

		fmt.Printf("both RA and mrencalve verify are successful.\n")
		return nil

	},
}
