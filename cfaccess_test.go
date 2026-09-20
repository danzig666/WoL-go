package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func withCFTestDB(t *testing.T) {
	t.Helper()

	previousDB := db
	previousTrust := cfTrustSpec()
	handle, err := sql.Open("sqlite", "file:cf_admin_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	handle.SetMaxOpenConns(1)

	statements := []string{
		`CREATE TABLE cf_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL UNIQUE COLLATE NOCASE,
			is_admin INTEGER NOT NULL DEFAULT 0,
			first_seen INTEGER NOT NULL DEFAULT 0,
			last_seen INTEGER NOT NULL DEFAULT 0,
			note TEXT
		)`,
		`CREATE TABLE devices (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE cf_user_devices (
			user_id INTEGER NOT NULL,
			device_id INTEGER NOT NULL,
			PRIMARY KEY (user_id, device_id)
		)`,
	}
	for _, statement := range statements {
		if _, err := handle.Exec(statement); err != nil {
			handle.Close()
			t.Fatal(err)
		}
	}

	db = handle
	if err := applyCFTrust("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		handle.Close()
		db = previousDB
		if err := applyCFTrust(previousTrust); err != nil {
			t.Errorf("restore Cloudflare trust: %v", err)
		}
	})
}

func TestCloudflareAdminCanUseAdminRouteWithoutJWT(t *testing.T) {
	withCFTestDB(t)
	if _, err := db.Exec(
		"INSERT INTO cf_users (email, is_admin) VALUES (?, 1)",
		"owner@example.com",
	); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	if err := router.SetTrustedProxies(nil); err != nil {
		t.Fatal(err)
	}
	router.GET("/admin", resolveIdentity(), authorizeAdmin(), adminIdentity(), whoAmI)

	request := httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.RemoteAddr = "127.0.0.1:43210"
	request.Header.Set(cfEmailHeader, "Owner@Example.com")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("Cloudflare administrator got status %d: %s", response.Code, response.Body.String())
	}
	var identity struct {
		Kind           string `json:"kind"`
		Email          string `json:"email"`
		IsAdmin        bool   `json:"is_admin"`
		SeesEverything bool   `json:"sees_everything"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Kind != "cloudflare" || identity.Email != "owner@example.com" ||
		!identity.IsAdmin || !identity.SeesEverything {
		t.Errorf("unexpected identity: %+v", identity)
	}

	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.RemoteAddr = "127.0.0.1:43211"
	request.Header.Set(cfEmailHeader, "visitor@example.com")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary Cloudflare visitor got status %d, want 401", response.Code)
	}

	// The same header sent directly rather than by the configured tunnel must
	// not confer the saved administrator role.
	request = httptest.NewRequest(http.MethodGet, "/admin", nil)
	request.RemoteAddr = "192.0.2.10:43212"
	request.Header.Set(cfEmailHeader, "owner@example.com")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("untrusted identity header got status %d, want 401", response.Code)
	}
}

func TestSetCFUserDevicesAlsoUpdatesAdminRole(t *testing.T) {
	withCFTestDB(t)
	result, err := db.Exec("INSERT INTO cf_users (email) VALUES (?)", "owner@example.com")
	if err != nil {
		t.Fatal(err)
	}
	userID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO devices (id) VALUES (7)"); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/users/:id/devices", setCFUserDevices)
	body := []byte(`{"device_ids":[7],"is_admin":true}`)
	request := httptest.NewRequest(http.MethodPut, "/users/1/devices", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("update got status %d: %s", response.Code, response.Body.String())
	}

	var isAdmin bool
	if err := db.QueryRow("SELECT is_admin FROM cf_users WHERE id = ?", userID).Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	if !isAdmin {
		t.Error("administrator role was not saved")
	}
	var grants int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM cf_user_devices WHERE user_id = ? AND device_id = 7",
		userID,
	).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Errorf("saved %d device grants, want 1", grants)
	}

	// Clients from before this feature omit is_admin; doing so must preserve
	// the role rather than silently demoting the user.
	request = httptest.NewRequest(http.MethodPut, "/users/1/devices", bytes.NewReader([]byte(`{"device_ids":[]}`)))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("legacy update got status %d: %s", response.Code, response.Body.String())
	}
	if err := db.QueryRow("SELECT is_admin FROM cf_users WHERE id = ?", userID).Scan(&isAdmin); err != nil {
		t.Fatal(err)
	}
	if !isAdmin {
		t.Error("an update without is_admin removed the existing role")
	}
}

func TestCreateTablesAddsAdminRoleToExistingCFUsers(t *testing.T) {
	handle, err := sql.Open("sqlite", "file:cf_admin_migration_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	handle.SetMaxOpenConns(1)

	// This is the schema used before Cloudflare administrators were added.
	if _, err := handle.Exec(`CREATE TABLE cf_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE COLLATE NOCASE,
		first_seen INTEGER NOT NULL DEFAULT 0,
		last_seen INTEGER NOT NULL DEFAULT 0,
		note TEXT
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Exec("INSERT INTO cf_users (email) VALUES (?)", "existing@example.com"); err != nil {
		t.Fatal(err)
	}

	createTables(handle)

	var isAdmin bool
	if err := handle.QueryRow(
		"SELECT is_admin FROM cf_users WHERE email = ?",
		"existing@example.com",
	).Scan(&isAdmin); err != nil {
		t.Fatalf("migrated administrator column is unavailable: %v", err)
	}
	if isAdmin {
		t.Error("existing Cloudflare user was unexpectedly promoted during migration")
	}
}
