package platform

import "testing"

func environment(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestNativeGOARCHDetectsAMD64BehindWOW64(t *testing.T) {
	got := nativeGOARCH("windows", "386", environment(map[string]string{
		"PROCESSOR_ARCHITEW6432": "AMD64",
		"PROCESSOR_ARCHITECTURE": "x86",
	}))
	if got != "amd64" {
		t.Errorf("native architecture = %q, want amd64", got)
	}
}

func TestNativeGOARCHDetectsARM64BehindEmulation(t *testing.T) {
	got := nativeGOARCH("windows", "amd64", environment(map[string]string{
		"PROCESSOR_ARCHITEW6432": "ARM64",
	}))
	if got != "arm64" {
		t.Errorf("native architecture = %q, want arm64", got)
	}
}

func TestNativeGOARCHUsesNativeProcessEnvironment(t *testing.T) {
	got := nativeGOARCH("windows", "386", environment(map[string]string{
		"PROCESSOR_ARCHITECTURE": "AMD64",
	}))
	if got != "amd64" {
		t.Errorf("native architecture = %q, want amd64", got)
	}
}

func TestNativeGOARCHFallsBackToProcessArchitecture(t *testing.T) {
	if got := nativeGOARCH("windows", "386", environment(nil)); got != "386" {
		t.Errorf("fallback architecture = %q, want 386", got)
	}
	if got := nativeGOARCH("linux", "arm64", environment(map[string]string{
		"PROCESSOR_ARCHITECTURE": "AMD64",
	})); got != "arm64" {
		t.Errorf("non-Windows architecture = %q, want arm64", got)
	}
}
