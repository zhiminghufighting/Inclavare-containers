package main

import (
	"fmt"
	"github.com/shelter/utils"
	"github.com/shelter/verification"
	"github.com/urfave/cli"
	"unsafe"
)

const (
	defaultsrcurl      = "https://github.com/alibaba/inclavare-containers/"
	defaultsrcbranch   = "master"
	defaultsrccommitid = ""
	defaultlocalpath   = "/tmp/skeleton/"

	defaultscrpathprefix = "/tmp/skeleton/"
	defaultscrpathsuffix = "rune/libenclave/internal/runtime/pal/skeleton/"

	defaultencss     = "/tmp/skeleton/rune/libenclave/internal/runtime/pal/skeleton/encl.ss"
	targetencbinpath = defaultscrpathprefix + defaultscrpathsuffix
	targetencbin     = "encl.bin"
	targetencss      = "encl.ss"
)

var Globalurl string = ""
var Globalbranch string = ""

var mrverifyCommand = cli.Command{
	Name:  "mrverify",
	Usage: "download target source code to rebuild and caculate mrenclave based on software algorithm and then compare with mrenclave in sigsturct file",
	ArgsUsage: `[command options]

EXAMPLE:
       # shelter mrencalve`,
	/*	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Usage: "ra-tls server address",
		},
		cli.StringFlag{
			Name:  "port",
			Usage: "ra-tls server port",
		},
	},*/

	SkipArgReorder: true,

	Action: func(cliContext *cli.Context) error {

		var mrenclave [32]byte

		if Globalurl == "" {
			Globalurl = defaultsrcurl
		}

		if Globalbranch == "" {
			Globalbranch = defaultsrcbranch
		}

		fmt.Printf("prepare download code and build target bin file.\n")
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

		if true != verification.Mrencalve_VerifybySigstruct(defaultencss, unsafe.Pointer(&mrenclave[0])) {
			fmt.Errorf("mismatch with sigstruct mrencalve value.\n")
			return nil
		}
		fmt.Printf("new mrencalve match the vallue in sigstruct file successfully.\n")
		return nil
	},
}
