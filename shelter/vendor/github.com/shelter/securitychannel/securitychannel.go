package remoteattestation
/*
#cgo CFLAGS:  -I/opt/intel/sgxsdk/include 
#cgo LDFLAGS:  -l:libra-challenger.a -l:libwolfssl.a -lm
extern int ra_tls_echo(int sockfd);
*/
import "C"
import (
	"fmt"
	"net"
)

const(
	defaultcmd = ""
	defaultAddress = "/run/rune/ra-tls.sock"
)

func RaGetMrEncalve()(bool){
	return true
}


func RaGetIasReport()(bool){
	return true
}

func RemoteTlsSetup(address string)(error){
		addr := address
		if addr == "" {
			addr = defaultAddress
		}

		conn, err := net.Dial("unix", addr)
		if err != nil {
			fmt.Printf("unix connection failed with err %s \n", err)
			return err
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed")
		}

		sockfd, err := unixConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()))

		return nil
}

func RetriveIasReport()(error){
	fmt.Printf("Obtain ias report and: \n")
	return nil
}


func VerifyQuote(q []byte)(error){
	fmt.Printf("verify quote info is as below: \n")
	return nil
}