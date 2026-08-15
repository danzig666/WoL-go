//go:build windows

package main

import (
	"net"

	"golang.org/x/sys/windows"
)

// enableBroadcast turns on SO_BROADCAST. Windows tolerates broadcast sends
// without it in some configurations, but the option is required by the socket
// API and setting it removes any doubt.
func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return opErr
}
