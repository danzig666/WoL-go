package binswap

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func setup(t *testing.T) (target string) {
	t.Helper()
	dir := t.TempDir()
	target = filepath.Join(dir, "app.exe")
	write(t, target, "old")
	write(t, StagingPath(target), "new")
	return target
}

func TestSwapAndRestore(t *testing.T) {
	target := setup(t)

	backup, err := Swap(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, target); got != "new" {
		t.Errorf("after swap the executable is %q, want \"new\"", got)
	}
	if got := read(t, backup); got != "old" {
		t.Errorf("the backup holds %q, want \"old\"", got)
	}
	if _, err := os.Stat(StagingPath(target)); !os.IsNotExist(err) {
		t.Error("the staged file should have been consumed")
	}

	if err := Restore(target, backup); err != nil {
		t.Fatal(err)
	}
	if got := read(t, target); got != "old" {
		t.Errorf("after restore the executable is %q, want \"old\"", got)
	}
	// The executable that did not work is kept rather than deleted.
	if got := read(t, StagingPath(target)); got != "new" {
		t.Errorf("the rejected executable is %q, want \"new\"", got)
	}
}

func TestSwapNeedsSomethingStaged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "app.exe")
	write(t, target, "old")

	if _, err := Swap(target); err == nil {
		t.Fatal("swapping with nothing staged should fail")
	}
	if got := read(t, target); got != "old" {
		t.Errorf("a failed swap changed the executable to %q", got)
	}
}

func TestSwapClearsAnEarlierBackup(t *testing.T) {
	target := setup(t)
	write(t, BackupPath(target), "ancient")

	if _, err := Swap(target); err != nil {
		t.Fatal(err)
	}
	if got := read(t, BackupPath(target)); got != "old" {
		t.Errorf("the backup holds %q, want the version just replaced", got)
	}
}

// The state a crash between the two renames would leave: no executable, but a
// backup sitting beside where it should be.
func TestRecoverAfterAnInterruptedSwap(t *testing.T) {
	target := setup(t)
	if _, err := Swap(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	if err := Recover(target); err != nil {
		t.Fatal(err)
	}
	if got := read(t, target); got != "old" {
		t.Errorf("recovery produced %q, want the previous executable", got)
	}
}

func TestRecoverLeavesAWorkingInstallationAlone(t *testing.T) {
	target := setup(t)
	if _, err := Swap(target); err != nil {
		t.Fatal(err)
	}
	if err := Recover(target); err != nil {
		t.Fatal(err)
	}
	if got := read(t, target); got != "new" {
		t.Errorf("recovery replaced a working executable with %q", got)
	}
}

func TestCleanup(t *testing.T) {
	target := setup(t)
	if _, err := Swap(target); err != nil {
		t.Fatal(err)
	}
	Cleanup(target)
	if _, err := os.Stat(BackupPath(target)); !os.IsNotExist(err) {
		t.Error("the backup should have been removed")
	}
	Cleanup(target) // must not panic or complain when there is nothing to do
}

func TestPathsStayBesideTheExecutable(t *testing.T) {
	for _, target := range []string{"/opt/wol/WoL-go", `C:\Util\wol-agent.exe`} {
		for _, path := range []string{StagingPath(target), BackupPath(target)} {
			if filepath.Dir(path) != filepath.Dir(target) {
				t.Errorf("%s is not beside %s", path, target)
			}
		}
	}
	if got := StagingPath(`C:\Util\wol-agent.exe`); got != `C:\Util\wol-agent.new.exe` {
		t.Errorf("staging path is %q", got)
	}
	// Keeping the .exe extension matters: Windows will not execute the smoke
	// test without it.
	if got := BackupPath(`C:\Util\wol-agent.exe`); got != `C:\Util\wol-agent.old.exe` {
		t.Errorf("backup path is %q", got)
	}
}
