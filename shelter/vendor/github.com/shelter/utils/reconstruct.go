package utils

import (
	"github.com/sirupsen/logrus"
)

var defaultbuildconfig = "/home/test/go/src"
var defaultsrccodedir = "/github.com/alibaba/inclavare-containers/rune/libenclave/internal/runtime/pal/skeleton"
var defaultbinary = "liberpal-skeleton-v*.so"

func CheckGcc()(bool){
	cmd_string := "gcc -v"
	if _, ret := ExecShell(cmd_string); ret != true {
		logrus.Debug("gcc is not ready!")
		return false
	}
	return true
}


//precheck for build environment
func prebuildcheck()(bool){
	//add other check step here
	//gcc check, git check already included in obtain source code;
	if ret := CheckGcc(); ret != true{
		return false
	}
	return true
}


//build source code
func Buildtarget(srcpath string, buildconfig string, targetfile string)(bool){
	if ret := prebuildcheck(); ret != true{
		return false
	}

	defaultsrcpath := defaultbuildconfig + defaultsrccodedir
	srcpath = defaultsrcpath
	if ret := CheckPath(srcpath); ret != true {
		return false
	}

	cmd_string := "make"
	if _, ret := ExecShell(cmd_string); ret != true {
		logrus.Debug("source code make faile failed!")
		return false
	}

	targetfile = defaultbinary
	cmd_string = "find -name " + targetfile
	if _, ret := ExecShell(cmd_string); ret != true {
		logrus.Debug("find file execute failed")
		return false
	}	
	return true
    
}