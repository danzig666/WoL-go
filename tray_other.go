//go:build !windows

package main

// The tray icon is a Windows feature. On every other platform the program
// behaves as it always has: it runs in the foreground until interrupted, which
// is what a router or a headless Linux box wants anyway.

func waitForShutdown(url string) {
	waitForSignal()
}

// announceFirstRun is a no-op away from Windows: these builds always have a
// terminal, so the password printed at startup is visible.
func announceFirstRun(password, url string) {}
