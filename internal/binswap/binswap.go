// Package binswap replaces a running program's own executable.
//
// The received wisdom is that this needs a reboot, and installers reinforce it:
// when Windows refuses to overwrite a file that is in use, the usual fallback is
// MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT, which leaves the replacement
// sitting on disk until the machine next starts.
//
// None of that is necessary. Windows locks a running executable against being
// written to or deleted, but it does not stop the file being *renamed*: the
// directory entry moves while the mapped image carries on running from the same
// file object. So the new binary is put in place by two renames, and the only
// thing that has to restart afterwards is the program itself - never the
// computer, and never the person's session.
//
//	target.exe  ->  target.old.exe     (allowed, even while executing)
//	target.new.exe -> target.exe
//
// If anything goes wrong, Restore puts the previous executable back the same
// way. Recover handles the one dangerous instant - a crash or power cut between
// the two renames, which would otherwise leave no executable at all.
package binswap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Paths derived from the executable being replaced. Keeping them beside the
// original matters: a rename across volumes is a copy, and would fail on a file
// that is in use.
func stagingPath(target string) string { return withSuffix(target, ".new") }
func backupPath(target string) string  { return withSuffix(target, ".old") }

func withSuffix(target, suffix string) string {
	ext := filepath.Ext(target)
	return strings.TrimSuffix(target, ext) + suffix + ext
}

// StagingPath is where a download should be written before Swap is called: the
// same directory as the executable, so the swap is a rename rather than a copy.
func StagingPath(target string) string { return stagingPath(target) }

// BackupPath is where Swap leaves the previous executable.
func BackupPath(target string) string { return backupPath(target) }

// retry works around the other thing that holds new executables briefly:
// antivirus scanners open a freshly written file to inspect it, and a rename
// during that window fails with a sharing violation. It clears in well under a
// second, so a few attempts turn a spurious failure into a short pause.
func retry(what string, fn func() error) error {
	var err error
	for attempt := 0; attempt < 12; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("%s: %w", what, err)
}

// Swap moves the staged executable into place, keeping the current one as a
// backup. It returns the path of the backup so a caller that fails to start can
// hand it to Restore.
//
// After this returns, the *file* has been replaced but this process is still
// running the old image, which is a property of how executables are mapped.
// Restarting the program is what completes the update.
func Swap(target string) (backup string, err error) {
	staged := stagingPath(target)
	if _, err := os.Stat(staged); err != nil {
		return "", fmt.Errorf("nothing staged at %s: %w", staged, err)
	}

	backup = backupPath(target)
	// A backup from a previous update may still be there if the old process
	// had not exited when it was last cleaned up.
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("could not clear the previous backup %s: %w", backup, err)
	}

	if err := retry("moving the current executable aside", func() error {
		return os.Rename(target, backup)
	}); err != nil {
		return "", err
	}

	if err := retry("moving the new executable into place", func() error {
		return os.Rename(staged, target)
	}); err != nil {
		// The dangerous state: no executable at the expected path. Put the old
		// one straight back, so a failure here changes nothing at all.
		if restoreErr := os.Rename(backup, target); restoreErr != nil {
			return "", fmt.Errorf("%w - and the previous executable could not be put back: %v", err, restoreErr)
		}
		return "", err
	}

	return backup, nil
}

// Restore undoes a Swap, for when the new executable turns out not to run.
func Restore(target, backup string) error {
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("no backup at %s: %w", backup, err)
	}
	failed := stagingPath(target)
	_ = os.Remove(failed)
	// Keep the executable that did not work, rather than deleting evidence.
	if err := os.Rename(target, failed); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(target)
	}
	return retry("restoring the previous executable", func() error {
		return os.Rename(backup, target)
	})
}

// Recover repairs the one state that a crash mid-swap can leave behind: the
// executable missing, with the backup still present. Call it before doing
// anything else that assumes the program is installed properly.
//
// It is not able to help the process that was interrupted - that one is gone -
// but whatever runs next, a service restart or a person double-clicking, finds
// a working installation.
func Recover(target string) error {
	if _, err := os.Stat(target); err == nil {
		return nil
	}
	backup := backupPath(target)
	if _, err := os.Stat(backup); err != nil {
		return nil // nothing to recover from
	}
	return os.Rename(backup, target)
}

// Cleanup removes the backup left by a successful update, once the process
// holding it has gone. It is deliberately quiet: failing to delete it is
// harmless, and it will be cleared on the next update anyway.
func Cleanup(target string) {
	_ = os.Remove(backupPath(target))
}
