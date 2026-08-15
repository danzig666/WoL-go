//go:build !windows

package main

import "fmt"

// The agent is a Windows program: sleeping a machine, the service model and
// the power settings it reports are all Windows specific. These stubs exist so
// the package still builds elsewhere, which keeps it in the normal go vet and
// go build sweep rather than being quietly excluded.

func suspend(force bool) error {
	return fmt.Errorf("the sleep agent is only supported on Windows")
}

func installService() error {
	return fmt.Errorf("the sleep agent is only supported on Windows")
}

func uninstallService() error {
	return fmt.Errorf("the sleep agent is only supported on Windows")
}

func stopService() error {
	return fmt.Errorf("the sleep agent is only supported on Windows")
}

func startService() error {
	return fmt.Errorf("the sleep agent is only supported on Windows")
}

func serviceStopChannel() <-chan struct{} {
	return make(chan struct{})
}

func wakeArmed() (bool, bool)          { return false, false }
func fastStartupEnabled() (bool, bool) { return false, false }
func powerRequests() string            { return "" }
