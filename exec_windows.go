//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW: the child runs without allocating a console.
const createNoWindow = 0x08000000

// hiddenCommand builds a command that does not flash a console window.
//
// The tray build is linked for the GUI subsystem and so owns no console.
// Windows therefore creates a fresh one for every child process, which appears
// as a black window blinking on screen - several times a minute, once the
// history tracker started reading the ARP table on a timer.
func hiddenCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: createNoWindow,
	}
	return cmd
}
