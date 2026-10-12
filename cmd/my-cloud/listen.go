package main

import (
	"net"
	"strconv"
)

// listen binds the port and returns the listener. Split out so main can
// report a bind failure synchronously, before announcing readiness — a
// container that logs "listening" but cannot accept connections is worse than
// one that exits.
func listen(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	return ln, nil
}
