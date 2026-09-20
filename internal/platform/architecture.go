// Package platform contains the small pieces of host detection shared by the
// server and the Windows agent.
package platform

import (
	"os"
	"runtime"
	"strings"
)

// NativeGOARCH reports the architecture of the operating system rather than
// merely that of the current process. They differ when a 32-bit WoL-go build
// is running under WOW64 on 64-bit Windows; using runtime.GOARCH there would
// keep downloading 386 updates forever.
func NativeGOARCH() string {
	return nativeGOARCH(runtime.GOOS, runtime.GOARCH, os.Getenv)
}

func nativeGOARCH(goos, processArch string, getenv func(string) string) string {
	if goos != "windows" {
		return processArch
	}

	// PROCESSOR_ARCHITEW6432 is set for a process running under WOW64 and names
	// the native host. Native 64-bit processes use PROCESSOR_ARCHITECTURE.
	value := strings.TrimSpace(getenv("PROCESSOR_ARCHITEW6432"))
	if value == "" {
		value = strings.TrimSpace(getenv("PROCESSOR_ARCHITECTURE"))
	}
	switch strings.ToLower(value) {
	case "amd64", "x86_64":
		return "amd64"
	case "arm64", "aarch64":
		return "arm64"
	case "x86", "i386", "i686":
		return "386"
	default:
		return processArch
	}
}
