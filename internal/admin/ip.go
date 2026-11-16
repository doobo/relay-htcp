package admin

import (
	"net"
	"strings"
)

func splitComma(s string) []string {
	return strings.Split(s, ",")
}

// hostPort strips the port from a "host:port" address, returning the bare
// host. It is a no-op when the address has no port.
func hostPort(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
