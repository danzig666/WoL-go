package main

import (
	"database/sql"
	"testing"
)

// withTestDB gives the package a small database of its own. The reconciler
// writes what it decides, and the writing is half of what is worth testing:
// clearing a stale claim from another record is exactly the step that stops
// two computers fighting over one address.
func withTestDB(t *testing.T) {
	t.Helper()

	previous := db
	handle, err := sql.Open("sqlite", "file:reconcile?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	handle.SetMaxOpenConns(1)
	if _, err := handle.Exec(`CREATE TABLE devices (
		id INTEGER PRIMARY KEY,
		name TEXT,
		mac TEXT UNIQUE,
		ip TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Exec(`CREATE TABLE device_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_id INTEGER NOT NULL,
		state TEXT NOT NULL,
		started_at INTEGER NOT NULL,
		ended_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}

	db = handle
	t.Cleanup(func() {
		handle.Exec("DROP TABLE devices")
		handle.Close()
		db = previous
	})
}

func TestCurrentOnlineSinceUsesTheOpenHistoryInterval(t *testing.T) {
	withTestDB(t)
	if _, err := db.Exec(
		"INSERT INTO device_history (device_id, state, started_at, ended_at) VALUES (1, 'online', 100, 190)",
	); err != nil {
		t.Fatal(err)
	}
	if got := currentOnlineSince(1, 200); got != 100 {
		t.Errorf("online since = %d, want interval start 100", got)
	}
}

func TestCurrentOnlineSinceStartsNowAfterAnOfflineState(t *testing.T) {
	withTestDB(t)
	if _, err := db.Exec(
		"INSERT INTO device_history (device_id, state, started_at, ended_at) VALUES (1, 'offline', 100, 190)",
	); err != nil {
		t.Fatal(err)
	}
	if got := currentOnlineSince(1, 200); got != 200 {
		t.Errorf("online since = %d, want current observation 200", got)
	}
}

func addTestDevice(t *testing.T, id int64, name, mac, ip string) Device {
	t.Helper()
	if _, err := db.Exec("INSERT INTO devices (id, name, mac, ip) VALUES (?, ?, ?, ?)",
		id, name, mac, ip); err != nil {
		t.Fatal(err)
	}
	return Device{ID: id, Name: name, MAC: mac, IP: ip}
}

func savedIP(t *testing.T, id int64) string {
	t.Helper()
	var ip string
	if err := db.QueryRow("SELECT COALESCE(ip, '') FROM devices WHERE id = ?", id).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	return ip
}

func TestReconcileFindsAMachineThatMoved(t *testing.T) {
	withTestDB(t)
	device := addTestDevice(t, 1, "Gamer", "B4:2E:99:4F:74:77", "192.168.0.131")

	// DHCP has given it a different address since.
	arp := map[string]string{
		"192.168.0.140": "B4:2E:99:4F:74:77",
		"192.168.0.131": "00:11:22:33:44:55", // somebody else lives there now
	}

	got := reconcileAddresses([]Device{device}, arp)
	if got[0].IP != "192.168.0.140" {
		t.Errorf("in memory the address is %q, want the one the cache reports", got[0].IP)
	}
	if saved := savedIP(t, 1); saved != "192.168.0.140" {
		t.Errorf("saved address is %q, want it corrected too", saved)
	}
}

func TestReconcileLeavesAGoodAddressAlone(t *testing.T) {
	withTestDB(t)
	device := addTestDevice(t, 1, "Gamer", "B4:2E:99:4F:74:77", "192.168.0.131")

	arp := map[string]string{"192.168.0.131": "B4:2E:99:4F:74:77"}
	got := reconcileAddresses([]Device{device}, arp)

	if got[0].IP != "192.168.0.131" {
		t.Errorf("address changed to %q for no reason", got[0].IP)
	}
}

// A stale cache entry can outlive a move, leaving one hardware address at two
// addresses. Without care the record would flip between them on alternate
// polls, which is worse than being wrong in one direction.
func TestReconcileDoesNotFlapBetweenTwoCacheEntries(t *testing.T) {
	withTestDB(t)
	device := addTestDevice(t, 1, "Gamer", "B4:2E:99:4F:74:77", "192.168.0.140")

	arp := map[string]string{
		"192.168.0.131": "B4:2E:99:4F:74:77", // the address it used to have
		"192.168.0.140": "B4:2E:99:4F:74:77", // and the one it has now
	}

	for i := 0; i < 20; i++ {
		got := reconcileAddresses([]Device{device}, arp)
		if got[0].IP != "192.168.0.140" {
			t.Fatalf("pass %d moved the address to %q", i, got[0].IP)
		}
	}
}

// When two records claim one address, the cache decides which is right, and
// the loser is cleared rather than left to be probed - probing it is what
// reported the wrong machine as online in the first place.
func TestReconcileClearsAStaleClaimFromAnotherRecord(t *testing.T) {
	withTestDB(t)
	moved := addTestDevice(t, 1, "Gamer", "B4:2E:99:4F:74:77", "192.168.0.99")
	stale := addTestDevice(t, 2, "Office", "AA:BB:CC:DD:EE:FF", "192.168.0.140")

	arp := map[string]string{"192.168.0.140": "B4:2E:99:4F:74:77"}
	reconcileAddresses([]Device{moved, stale}, arp)

	if got := savedIP(t, 1); got != "192.168.0.140" {
		t.Errorf("the machine that is really there has %q", got)
	}
	if got := savedIP(t, 2); got != "" {
		t.Errorf("the stale claim on 192.168.0.140 was left as %q", got)
	}
}

func TestReconcileIgnoresRecordsItCannotPlace(t *testing.T) {
	withTestDB(t)
	noMAC := addTestDevice(t, 1, "Mystery", "", "192.168.0.50")
	absent := addTestDevice(t, 2, "Switched off", "11:22:33:44:55:66", "192.168.0.51")

	got := reconcileAddresses([]Device{noMAC, absent}, map[string]string{
		"192.168.0.77": "99:88:77:66:55:44",
	})

	if got[0].IP != "192.168.0.50" || got[1].IP != "192.168.0.51" {
		t.Errorf("addresses changed to %q and %q", got[0].IP, got[1].IP)
	}
	if savedIP(t, 2) != "192.168.0.51" {
		t.Error("a machine that is simply switched off had its address taken away")
	}
}

// An empty cache is the normal state on a host that has just started, and must
// not be read as "none of these machines are where they were".
func TestReconcileWithNothingInTheCache(t *testing.T) {
	withTestDB(t)
	device := addTestDevice(t, 1, "Gamer", "B4:2E:99:4F:74:77", "192.168.0.131")

	got := reconcileAddresses([]Device{device}, nil)
	if got[0].IP != "192.168.0.131" || savedIP(t, 1) != "192.168.0.131" {
		t.Error("an empty cache changed a saved address")
	}
}
