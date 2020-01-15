package ofctrl

import (
	"github.com/Microsoft/go-winio"
	"net"
)

// Connect to named pipe
func DialUnixOrNamedPipe(address string) (net.Conn, error) {
	return winio.DialPipe(address, nil)
}
