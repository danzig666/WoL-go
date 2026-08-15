//go:build !windows

package main

import "os/exec"

// hiddenCommand is plain exec.Command away from Windows: no other platform
// pops up a window for a child process.
func hiddenCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
