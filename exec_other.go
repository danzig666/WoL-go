//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// hiddenCommand is plain exec.Command away from Windows: no other platform
// pops up a window for a child process.
func hiddenCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}

// detachedCommand builds a command that outlives this process, by putting it in
// its own session so it is not sent the signals this one receives.
func detachedCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}
