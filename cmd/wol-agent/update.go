package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"WoL-go/internal/binswap"
	"WoL-go/internal/release"
)

// Updating this agent, without restarting the computer it is on.
//
// The service holds its own executable open, and Windows will not let a running
// program be overwritten. That is where the reboot in most updaters comes from:
// they give up and schedule the replacement for the next start. It is not
// needed. A running executable can be *renamed*, so the new build is put in
// place with two renames and the only thing that restarts is this service -
// a few seconds, at the lock screen or in the middle of someone's work, with
// nothing on screen to see and nobody signed out.
//
// No elevation prompt appears either, and not because one is being suppressed:
// the service already runs as LOCAL SYSTEM, so it can replace its own file and
// drive the service manager without asking anyone for anything.
//
// The binary comes from the WoL-go server rather than GitHub, so this machine
// needs no route to the internet. What makes that safe is that the signature is
// checked here, against a public key compiled into this program. A server that
// has been tampered with cannot make this agent run anything.

// upgradeManifest is what the server offers.
type upgradeManifest struct {
	Version   string `json:"version"`
	Asset     string `json:"asset"`
	Size      int64  `json:"size"`
	Checksums string `json:"checksums"` // base64 of SHA256SUMS.txt
	Signature string `json:"signature"` // base64 Ed25519 signature over it
}

// upgrade fetches, verifies, installs and then arranges the restart.
func upgrade(cfg config) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find my own executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	manifest, err := fetchManifest(cfg)
	if err != nil {
		return err
	}
	if !release.IsNewer(manifest.Version, version) {
		log.Printf("already running %s; the server offers %s", version, manifest.Version)
		return nil
	}
	log.Printf("updating from %s to %s", version, manifest.Version)

	sums, err := verifyManifest(manifest)
	if err != nil {
		return err
	}

	staged := binswap.StagingPath(exe)
	if err := download(cfg, manifest, staged); err != nil {
		os.Remove(staged)
		return err
	}

	// Check what was written to disk, which is what would be executed.
	file, err := os.Open(staged)
	if err != nil {
		return err
	}
	err = sums.Check(manifest.Asset, file)
	file.Close()
	if err != nil {
		os.Remove(staged)
		return fmt.Errorf("the downloaded agent did not match the signed checksum: %w", err)
	}

	// Prove it runs before it is in the way. A truncated download or the wrong
	// architecture fails here, while the working agent is still installed.
	if err := smokeTest(staged, manifest.Version); err != nil {
		os.Remove(staged)
		return err
	}

	backup, err := binswap.Swap(exe)
	if err != nil {
		return err
	}
	log.Printf("installed %s; restarting the service", manifest.Version)

	// The restart cannot be done from in here: this process is the service
	// being restarted. A detached copy of the new binary does it instead.
	helper := detachedCommand(exe,
		"apply-update",
		"--exe", exe,
		"--backup", backup,
		"--delay", "2",
	)
	helper.Dir = filepath.Dir(exe)
	if err := helper.Start(); err != nil {
		if restoreErr := binswap.Restore(exe, backup); restoreErr != nil {
			return fmt.Errorf("could not start the restart helper (%w), and could not undo the update: %v", err, restoreErr)
		}
		return fmt.Errorf("could not start the restart helper, so nothing was changed: %w", err)
	}
	_ = helper.Process.Release()
	return nil
}

func fetchManifest(cfg config) (upgradeManifest, error) {
	var manifest upgradeManifest

	req, err := http.NewRequest(http.MethodGet,
		cfg.Server+"/api/agent/update?arch="+runtime.GOARCH, nil)
	if err != nil {
		return manifest, err
	}
	cfg.authorize(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return manifest, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return manifest, fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}
	if manifest.Version == "" || manifest.Asset == "" {
		return manifest, fmt.Errorf("the server offered no update for %s", runtime.GOARCH)
	}
	// The asset name is used as a file name and as a key into the checksums, so
	// it must be the name this build expects rather than anything the server
	// felt like sending.
	if manifest.Asset != release.AgentAsset(runtime.GOARCH) {
		return manifest, fmt.Errorf("the server offered %q, which is not the agent for %s",
			manifest.Asset, runtime.GOARCH)
	}
	return manifest, nil
}

// verifyManifest is the point the whole design turns on: the checksum list is
// accepted only if the release key signed it.
func verifyManifest(manifest upgradeManifest) (release.Checksums, error) {
	sums, err := base64.StdEncoding.DecodeString(manifest.Checksums)
	if err != nil {
		return nil, fmt.Errorf("the update manifest is unreadable: %w", err)
	}
	checksums, err := release.Verify(sums, []byte(manifest.Signature))
	if err != nil {
		return nil, fmt.Errorf("refusing the update: %w", err)
	}
	if !checksums.Has(manifest.Asset) {
		return nil, fmt.Errorf("refusing the update: %s is not covered by the signature", manifest.Asset)
	}
	return checksums, nil
}

func download(cfg config, manifest upgradeManifest, to string) error {
	req, err := http.NewRequest(http.MethodGet,
		cfg.Server+"/api/agent/update/download?arch="+runtime.GOARCH, nil)
	if err != nil {
		return err
	}
	cfg.authorize(req)

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}

	file, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	// Bounded so a confused or hostile server cannot fill the disk. The real
	// check is the checksum; this only limits the damage before it runs.
	written, err := io.Copy(file, io.LimitReader(resp.Body, 200<<20))
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("downloading the new agent: %w", err)
	}
	if manifest.Size > 0 && written != manifest.Size {
		return fmt.Errorf("the download stopped after %d of %d bytes", written, manifest.Size)
	}
	return nil
}

// smokeTest asks the staged binary what version it is. It has already been
// checked against the signature at this point, so running it is no more of a
// commitment than installing it.
func smokeTest(path, expected string) error {
	output, err := hiddenCommand(path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("the downloaded agent would not run: %v", err)
	}
	got := strings.TrimSpace(string(output))
	if got != expected {
		return fmt.Errorf("the downloaded agent reports %q, expected %q", got, expected)
	}
	return nil
}

// --- The helper ---

// runApplyUpdate restarts the service after its executable has been replaced.
// It is a detached copy of the new binary, and the only thing still running
// while the service is stopped, which is why the rollback lives here.
func runApplyUpdate(args []string) {
	var exe, backup string
	delay := 2

	for i := 0; i < len(args); i++ {
		switch args[i] {
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
		case "--delay":
			if i+1 < len(args) {
				delay, _ = strconv.Atoi(args[i+1])
				i++
			}
		}
	}
	if exe == "" {
		return
	}

	if file, err := os.OpenFile(filepath.Join(filepath.Dir(exe), "wol-agent-update.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644); err == nil {
		defer file.Close()
		log.SetOutput(file)
	}

	// Long enough for the agent that started this to finish telling the server
	// what happened, and to come to a stop of its own accord.
	time.Sleep(time.Duration(delay) * time.Second)

	// Nothing to restart: the agent was started by hand rather than installed
	// as a service. The new executable is in place and will be used the next
	// time it is started, which is all that can be done from here.
	if !serviceInstalled() {
		log.Printf("apply-update: no service installed; the new executable is in place")
		binswap.Cleanup(exe)
		return
	}

	log.Printf("apply-update: restarting the service to pick up the new executable")
	if err := stopService(); err != nil {
		log.Printf("apply-update: could not stop the service: %v", err)
	}
	if err := startService(); err != nil {
		log.Printf("apply-update: the new agent would not start: %v", err)
		rollBack(exe, backup)
		return
	}

	// It started; make sure it stays started rather than exiting immediately.
	time.Sleep(5 * time.Second)
	if !serviceRunning() {
		log.Printf("apply-update: the new agent did not stay running; rolling back")
		rollBack(exe, backup)
		return
	}

	log.Printf("apply-update: done, now running %s", version)
	binswap.Cleanup(exe)
}

func rollBack(exe, backup string) {
	if backup == "" {
		return
	}
	_ = stopService()
	if err := binswap.Restore(exe, backup); err != nil {
		log.Printf("apply-update: could not put the previous agent back: %v", err)
		return
	}
	if err := startService(); err != nil {
		log.Printf("apply-update: could not restart the previous agent: %v", err)
		return
	}
	log.Printf("apply-update: rolled back to the previous agent")
}

// detachedCommand builds a command that keeps running after this process ends,
// which is the whole point of the helper.
func detachedCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	applyDetached(cmd)
	return cmd
}
