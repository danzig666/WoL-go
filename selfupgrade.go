package main

import (
	"debug/pe"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"WoL-go/internal/binswap"
	"WoL-go/internal/release"
)

// Replacing the server's own executable while it is running.
//
// The mechanics are the two renames in internal/binswap, and the part that
// cannot be done from inside: something has to be alive after this process
// exits to start its replacement. That something is a detached copy of the new
// binary running "finish-update", which waits, starts the new server, checks it
// answers, and puts the old one back if it does not.
//
// It also copes with the server being under a supervisor - systemd, a service
// wrapper, a NAS task manager - by watching to see whether the service comes
// back on its own before starting it. Guessing at the supervisor would be
// fragile; waiting to see what happens is not.

// shutdownForUpdate is set by main to stop the service cleanly. Killing the
// process would be simpler and would risk the database: SQLite in WAL mode with
// synchronous=NORMAL trades durability for speed on the assumption of an
// orderly exit.
var shutdownForUpdate func()

// serverExecutable is the file to replace, with any symlink resolved so the
// rename happens where the binary actually lives.
func serverExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

// serverAssetName works out which release asset is this build.
//
// On Windows the console and tray builds are the same program linked for
// different subsystems, so the file name is the only thing that distinguishes
// them - and it can be anything, because people rename downloads. The subsystem
// recorded in this binary's own PE header is the fact that cannot be renamed.
func serverAssetName() string {
	base := fmt.Sprintf("WoL-go-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS != "windows" {
		return base
	}
	if isGUIBuild() {
		return base + "-tray.exe"
	}
	return base + ".exe"
}

func isGUIBuild() bool {
	exe, err := serverExecutable()
	if err != nil {
		return false
	}
	file, err := pe.Open(exe)
	if err != nil {
		return false
	}
	defer file.Close()

	const subsystemGUI = 2
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return header.Subsystem == subsystemGUI
	case *pe.OptionalHeader32:
		return header.Subsystem == subsystemGUI
	}
	return false
}

// serverUpgradeAvailable reports whether the downloaded release contains a
// build this server could replace itself with.
func serverUpgradeAvailable(version string) bool {
	sums, err := cachedRelease(version)
	if err != nil {
		return false
	}
	if !sums.Has(serverAssetName()) {
		return false
	}
	_, err = os.Stat(filepath.Join(releaseDir(version), serverAssetName()))
	return err == nil
}

// applyServerUpgrade stages the new server, proves it runs, and then hands over.
func applyServerUpgrade(c *gin.Context) {
	version := downloadedVersion()
	if version == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Download the release first"})
		return
	}
	if !release.IsNewer(version, appVersion) && release.Valid(appVersion) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("This server is already running %s", appVersion),
		})
		return
	}

	if err := stageServerBinary(version); err != nil {
		log.Printf("Server update refused: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Answer before restarting, or the browser sees a dropped connection and
	// the administrator cannot tell a successful handover from a crash.
	c.JSON(http.StatusOK, gin.H{
		"applying": version,
		"message":  "Installing " + version + " and restarting. The page will come back on its own.",
	})

	go func() {
		time.Sleep(time.Second)
		if err := handOverToNewServer(version); err != nil {
			log.Printf("Server update failed: %v", err)
		}
	}()
}

// stageServerBinary puts the verified new build beside the current one and
// checks that it actually runs before anything is moved.
//
// Running it first is what makes this safe: a truncated download, the wrong
// architecture, or a missing library all fail here, while the working server is
// still in place and still serving.
func stageServerBinary(version string) error {
	sums, err := cachedRelease(version)
	if err != nil {
		return fmt.Errorf("the downloaded release is not usable: %w", err)
	}

	name := serverAssetName()
	source := filepath.Join(releaseDir(version), name)
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("release %s has no build for this system (%s)", version, name)
	}

	exe, err := serverExecutable()
	if err != nil {
		return err
	}
	staged := binswap.StagingPath(exe)

	if err := copyFile(source, staged, 0o755); err != nil {
		return fmt.Errorf("could not write %s: %w", staged, err)
	}

	// Check the copy, not the original: what matters is the bytes that will be
	// executed, after whatever the filesystem did in between.
	check, err := os.Open(staged)
	if err != nil {
		return err
	}
	err = sums.Check(name, check)
	check.Close()
	if err != nil {
		os.Remove(staged)
		return err
	}

	if err := smokeTest(staged, version); err != nil {
		os.Remove(staged)
		return err
	}
	return nil
}

// smokeTest runs the staged binary and asks it what it is.
func smokeTest(path, expected string) error {
	cmd := hiddenCommand(path, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("the downloaded build would not run: %v", err)
	}
	got := strings.TrimSpace(string(output))
	if got != expected {
		return fmt.Errorf("the downloaded build reports %q, expected %q", got, expected)
	}
	return nil
}

func copyFile(from, to string, mode os.FileMode) error {
	source, err := os.Open(from)
	if err != nil {
		return err
	}
	defer source.Close()

	// Remove first: the destination may be a previous staging attempt.
	os.Remove(to)
	dest, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dest, source); err != nil {
		dest.Close()
		return err
	}
	return dest.Close()
}

// handOverToNewServer performs the swap, starts the helper, and stops.
func handOverToNewServer(version string) error {
	exe, err := serverExecutable()
	if err != nil {
		return err
	}

	backup, err := binswap.Swap(exe)
	if err != nil {
		return err
	}
	log.Printf("Installed %s; restarting", version)

	args := []string{
		"finish-update",
		"--pid", strconv.Itoa(os.Getpid()),
		"--exe", exe,
		"--backup", backup,
		"--port", listenPort,
	}
	// Everything after the separator is what this server was started with, so
	// the replacement inherits the same flags.
	args = append(args, "--")
	args = append(args, os.Args[1:]...)

	helper := detachedCommand(exe, args...)
	helper.Dir = filepath.Dir(exe)
	if err := helper.Start(); err != nil {
		// Nothing has been lost: put the old binary back and carry on serving.
		if restoreErr := binswap.Restore(exe, backup); restoreErr != nil {
			log.Printf("Could not restore the previous server: %v", restoreErr)
		}
		return fmt.Errorf("could not start the update helper: %w", err)
	}
	_ = helper.Process.Release()

	if shutdownForUpdate != nil {
		shutdownForUpdate()
	} else {
		os.Exit(0)
	}
	return nil
}

// --- The helper ---

// runFinishUpdate is the detached process that completes a server update. It is
// the new binary, run with a subcommand, and it is the only part of this that
// is still alive while the server is not.
func runFinishUpdate(args []string) {
	var pid int
	var exe, backup, port string
	var original []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pid":
			if i+1 < len(args) {
				pid, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "--exe":
			if i+1 < len(args) {
				exe = args[i+1]
				i++
			}
		case "--backup":
			if i+1 < len(args) {
				backup = args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(args) {
				port = args[i+1]
				i++
			}
		case "--":
			original = args[i+1:]
			i = len(args)
		}
	}

	if exe == "" {
		return
	}
	logTo := filepath.Join(filepath.Dir(exe), "wol-update.log")
	if file, err := os.OpenFile(logTo, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		defer file.Close()
		log.SetOutput(file)
	}
	log.Printf("finish-update: waiting for the previous server (pid %d) to stop", pid)

	// Nothing can be started while the old one still holds the port.
	waitForExit(pid, port, 90*time.Second)

	// A supervisor may restart the service itself. Give it a moment to do so
	// before starting a second copy that would only fight over the port.
	if port != "" && waitUntilAnswering(port, 8*time.Second) {
		log.Printf("finish-update: the service came back on its own; nothing to do")
		binswap.Cleanup(exe)
		return
	}

	log.Printf("finish-update: starting %s", exe)
	started := exec.Command(exe, original...)
	started.Dir = filepath.Dir(exe)
	if err := started.Start(); err != nil {
		log.Printf("finish-update: could not start the new server: %v", err)
		rollBack(exe, backup, original)
		return
	}

	// If it is going to fail, it fails at once: a bad binary exits, a port
	// clash is immediate. Thirty seconds is generous for a service whose
	// startup is opening a database.
	if port != "" && !waitUntilAnswering(port, 30*time.Second) {
		log.Printf("finish-update: the new server did not answer; rolling back")
		_ = started.Process.Kill()
		rollBack(exe, backup, original)
		return
	}

	log.Printf("finish-update: the new server is running")
	binswap.Cleanup(exe)
}

func rollBack(exe, backup string, original []string) {
	if backup == "" {
		log.Printf("finish-update: no backup to roll back to")
		return
	}
	if err := binswap.Restore(exe, backup); err != nil {
		log.Printf("finish-update: could not restore the previous server: %v", err)
		return
	}
	log.Printf("finish-update: restored the previous server; starting it")
	previous := exec.Command(exe, original...)
	previous.Dir = filepath.Dir(exe)
	if err := previous.Start(); err != nil {
		log.Printf("finish-update: could not start the previous server either: %v", err)
	}
}

// waitForExit waits for the old server to be gone. The port is the reliable
// signal: a process id can be reused, but the listener is what would stop the
// replacement from starting.
func waitForExit(pid int, port string, timeout time.Duration) {
	if port == "" {
		// Nothing to watch; the old server was told to stop a moment ago.
		log.Printf("finish-update: no port to watch for pid %d, pausing instead", pid)
		time.Sleep(5 * time.Second)
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !portInUse(port) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	log.Printf("finish-update: gave up waiting for the previous server")
}

func portInUse(port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// waitUntilAnswering reports whether something is serving on the port.
func waitUntilAnswering(port string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if portInUse(port) {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}
