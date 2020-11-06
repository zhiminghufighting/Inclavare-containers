package main


import (
    "github.com/urfave/cli"
    "github.com/sirupsen/logrus"
    "github.com/shelter/utils"
)

/*
const (
    defaultbinpath = ""
    defaultencbin = ""
    defaultencss = ""
    targetencbinpath = ""
    targetencbin = ""
    targetencss = ""

    defaultsrcurl = ""
    defaultsrcbranch = ""
    defaultsrccommitid = ""
    defaultlocalpath = ""

    defaultscrpathprefix = ""
    defaultscrpathsuffix = ""
)
*/


var attCommand = cli.Command{
	Name:  "att",
	Usage: "connect to RA server and fetch specified enclave mrencalve and ias report",
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

        cmd := "cd " + defaultbinpath
        logrus.Debug("run attestiascommand\n")
        if _, ret := utils.ExecShell(cmd); ret != true{
            logrus.Debug("run cd failed\n")
            return nil
        }

        cmd = "./elv echo"

        if _, ret := utils.ExecShell(cmd); ret != true{
            logrus.Debug("run ./elv echo failed\n")
            return nil
        }

        //parse retstr to get ias report and mrenclave value from http response


		return nil

	},

}