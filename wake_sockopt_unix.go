//go:build !windows

package main

import (
	"net"

	"golang.org/x/sys/unix"
)

// enableBroadcast turns on SO_BROADCAST, without which Linux and the BSDs
// refuse to send to a broadcast address at all.
func enableBroadcast(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	}); err != nil {
		return err
	}
	return opErr
}
