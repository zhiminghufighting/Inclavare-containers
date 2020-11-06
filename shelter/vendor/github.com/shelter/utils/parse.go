package utils

import (
	"path/filepath"
	"strings"
	"github.com/sirupsen/logrus"
)


// ResolveFilePath ensures that the current working directory is
// not a symlink and returns the absolute path to the log file or target file.
type SrcCodeInfo struct{
	repourl string 
	srcbranch  string 
	srccommitid string 
}

func resolveFilePath(logfile string) (string, error) {
	logpath, err := filepath.Abs(logfile)
	if err != nil {
		return "", err
	}

	return filepath.EvalSymlinks(logpath)
	
}


func GetBetweenStr(str string, start string, end string)(betweenstr string, count int){
	n := strings.Index(str, start)
	if n == -1 {
		logrus.Debug("string %s can't be found", start)
		return "", 0		
	}
	str = string([]byte(str)[n:])
	m := strings.Index(str,end)
	if m == -1 {
		logrus.Debug("string %s can't be found", end)	
		return "", 0	
	}
	str = string([]byte(str)[:m])
	m = m + n
	return str, m
}
