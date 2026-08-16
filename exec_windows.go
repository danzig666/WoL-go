//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW: the child runs without allocating a console.
// DETACHED_PROCESS: the child gets no console at all and does not inherit ours.
// CREATE_NEW_PROCESS_GROUP: it is not signalled when this process is.
const (
	createNoWindow        = 0x08000000
	detachedProcess       = 0x00000008
	createNewProcessGroup = 0x00000200
)

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

// detachedCommand builds a command that outlives this process.
//
// It is used for the one job that cannot be done from inside the program being
// replaced: waiting for it to exit, and then starting its replacement.
func detachedCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcessGroup,
	}
	return cmd
}
