package remoteattestation
/*
#cgo CFLAGS:  -I/opt/intel/sgxsdk/include 
#cgo LDFLAGS:  -l:libra-challenger.a -l:libwolfssl.a -lm
extern int ra_tls_echo(int sockfd, unsigned char* mrenclave, unsigned char* mrsigner);
*/
import "C"
import (
	"fmt"
	"net"
	"unsafe"
)

const(
	defaultsockAddress = "/run/rune/ra-tls.sock"
	defaultutcpAddress = "0.0.0.0:3443"
)

//for local tcp connection
func RemoteTlsSetupTCP(address string, mrencalve unsafe.Pointer, mrsigner unsafe.Pointer)(error){
		addr := address
		if addr == "" {
			addr = defaultutcpAddress
		}

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			fmt.Errorf("tcp connection failed with err %s.\n", err)
			return err
		}
		defer conn.Close()

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed.\n")
		}

		sockfd, err := tcpConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()), (*C.uchar)(mrencalve), (*C.uchar)(mrsigner))
		return nil
}

//for local unix socket connection
func RemoteTlsSetupSock(address string, mrencalve unsafe.Pointer, mrsigner unsafe.Pointer)(error){
		addr := address
		if addr == "" {
			addr = defaultsockAddress
		}

		conn, err := net.Dial("unix", addr)
		if err != nil {
			fmt.Errorf("unix connection failed with err %s.\n", err)
			return err
		}
		defer conn.Close()

		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("casting to UnixConn failed.\n")
		}

		sockfd, err := unixConn.File()
		if err != nil {
			return err
		}

		C.ra_tls_echo(C.int(sockfd.Fd()), (*C.uchar)(mrencalve),(*C.uchar)(mrsigner))
		return nil
}

