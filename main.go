package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/natefinch/lumberjack.v2"
	_ "modernc.org/sqlite"
)

var db *sql.DB

//go:embed web/*
var webFiles embed.FS

var defaultMode string

// noTray suppresses the Windows notification-area icon, for running as a
// service or from a terminal.
var noTray bool

// firstRunPassword holds the generated administrator password when this start
// created the account, so it can be shown in a dialog if there is no console.
var firstRunPassword string

// cfTrustFromFlag records that the Cloudflare setting came from the command
// line, in which case the web interface leaves it alone.
var cfTrustFromFlag bool

// listenHost and listenPort are kept so the service can tell an agent where to
// find it. The browser's own address is no use for that: an administrator
// working through the Cloudflare hostname would be shown the one address an
// agent cannot use.
var listenHost, listenPort string

func main() {
	host := flag.String("h", "0.0.0.0", "Host to bind to")
	port := flag.String("p", "9543", "Port to bind to")
	debug := flag.Bool("debug", false, "Enable gin debug mode and verbose request logging")
	publicWake := flag.Bool("public-wake", true, "Allow waking computers without signing in (use -public-wake=false to require a password)")
	flag.BoolVar(&noTray, "no-tray", false, "Do not show the notification-area (system tray) icon on Windows")
	cfTrust := flag.String("cf-trust", "", "Source addresses whose Cloudflare Access headers are trusted, e.g. \"localhost\" or \"127.0.0.1,192.168.0.50\". Empty disables Cloudflare identities.")
	flag.Parse()

	listenHost, listenPort = *host, *port

	if strings.TrimSpace(*cfTrust) != "" {
		if err := applyCFTrust(*cfTrust); err != nil {
			log.Fatalf("Invalid -cf-trust value: %v", err)
		}
		// A value on the command line pins the setting: the web interface
		// shows it but will not fight the flag.
		cfTrustFromFlag = true
	}

	// Log to both the rotating file and stdout, so a plain double-click of the
	// executable still shows startup output (including the generated password).
	logFile := &lumberjack.Logger{
		Filename:   dataPath("wol.log"),
		MaxSize:    10, // megabytes
		MaxBackups: 3,
		MaxAge:     28, // days
	}
	// Stdout is wrapped so its errors are discarded. Built for the system tray
	// there is no console, every write to stdout fails, and io.MultiWriter
	// stops at the first error - which would silently lose the log file too.
	log.SetOutput(io.MultiWriter(quietWriter{os.Stdout}, logFile))

	log.Printf("Starting Wake-on-LAN service")

	db = initDB()
	defer db.Close()

	jwtKey = loadOrCreateJWTSecret(db)

	// Without a flag, the setting comes from the database - the only way a
	// tray user, who has no command line, can configure it at all.
	if !cfTrustFromFlag {
		loadCFTrust()
	}

	if !*debug && defaultMode != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// Rate-limiting keys off the client IP, so proxy headers must not be
	// trusted unless an operator explicitly configures a proxy.
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("Error configuring trusted proxies: %v", err)
	}
	router.Use(securityHeaders())

	// Public routes.
	router.POST("/api/login", loginRateLimit(), login)
	router.POST("/api/password", authorizeJWT(true), updatePassword)

	// Waking a machine needs no password: anyone who can reach the page may
	// turn a computer on, which is harmless, but they see only names and
	// online status and cannot change the list. Pass -public-wake=false to
	// require a sign-in for this too.
	//
	// The group is also registered when Cloudflare identities are in use, so
	// that remote visitors keep working even with anonymous waking turned off;
	// requireVisitor then rejects the anonymous ones.
	// Always registered: whether a given caller is allowed through is decided
	// per request by requireVisitor, since Cloudflare identities can be
	// switched on from the web interface long after startup.
	anon := router.Group("/api/public", resolveIdentity(), requireVisitor(*publicWake))
	{
		anon.GET("/devices", listPublicDevices)
		anon.GET("/status", publicStatus)
		anon.POST("/devices/:id/wake", wakeRateLimit(), wakeDevice)
		anon.POST("/devices/wake-all", wakeRateLimit(), wakeAllDevices)
	}
	switch {
	case *publicWake:
		log.Printf("Anonymous wake-up is enabled; adding and removing computers still requires signing in")
	case cfEnabled():
		log.Printf("Anonymous wake-up is disabled; only Cloudflare visitors and the administrator may wake")
	default:
		log.Printf("Anonymous wake-up is disabled; signing in is required for everything")
	}

	if cfEnabled() {
		log.Printf("Trusting Cloudflare Access headers from %s", strings.Join(cfTrustDescription(), ", "))
	}

	// Everything else needs a valid session.
	api := router.Group("/api", authorizeJWT(false), adminIdentity())
	{
		api.GET("/devices", listDevices)
		api.POST("/devices", createDevice)
		api.POST("/devices/bulk", createDevicesBulk)
		api.PUT("/devices/order", reorderDevices)
		api.PUT("/devices/:id", updateDevice)
		api.DELETE("/devices/:id", deleteDevice)
		api.POST("/devices/:id/wake", wakeDevice)
		api.POST("/devices/wake-all", wakeAllDevices)
		api.GET("/status", devicesStatus)
		api.GET("/networks", listNetworks)
		api.POST("/scan", beginScan)
		api.GET("/scan", scanStatus)

		// Sleep agents.
		api.GET("/agents", listAgents)
		api.POST("/devices/:id/enrol", createEnrolment)
		api.POST("/devices/:id/sleep", sleepDevice)
		api.DELETE("/agents/:id", deleteAgent)

		// History and statistics: strictly the administrator's view.
		api.GET("/history", historyOverview)
		api.GET("/history/:id/heatmap", deviceHeatmap)
		api.GET("/wakes", listWakeEvents)

		// Cloudflare Access configuration and its diagnostics.
		api.GET("/cf-settings", cfSettings)
		api.PUT("/cf-settings", updateCFSettings)

		// Managing who may reach which computer from the internet.
		api.GET("/users", listCFUsers)
		api.POST("/users", createCFUser)
		api.PUT("/users/:id/devices", setCFUserDevices)
		api.DELETE("/users/:id", deleteCFUser)
	}

	// The agent's own endpoints. Enrolment is open because the pairing code is
	// the credential; everything else needs the token that code buys.
	router.POST("/api/agent/enrol", enrolAgent)
	agent := router.Group("/api/agent", authorizeAgent())
	{
		agent.POST("/heartbeat", agentHeartbeat)
		agent.GET("/commands", agentCommands)
		agent.POST("/result", agentResult)
	}

	// Sleeping is offered to the same visitors who may wake, since it is the
	// counterpart of the same button.
	anon.POST("/devices/:id/sleep", wakeRateLimit(), sleepDevice)

	// Who am I: used by the page to show the signed-in address and to decide
	// which controls to offer.
	router.GET("/api/me", resolveIdentity(), whoAmI)

	// The page needs to know whether to offer the buttons at all.
	router.GET("/api/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"public_wake":       *publicWake,
			"cloudflare_active": cfEnabled(),
			// Lets the page report which build it is actually running, which
			// settles "have I really deployed the new version?".
			"build": buildStamp,
		})
	})

	registerLegacyRoutes(router)

	// Serving embedded files
	subFS, err := fs.Sub(webFiles, "web") // This creates a sub filesystem from the embedded files
	if err != nil {
		log.Fatalf("Error preparing embedded web assets: %v", err)
	}
	loadWebAssets(subFS)
	router.GET("/web/*filepath", serveWebAsset)
	router.HEAD("/web/*filepath", serveWebAsset)

	// Redirect root to the static HTML file
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/web/index.html")
	})

	address := net.JoinHostPort(*host, *port)
	srv := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	startHistoryTracker()

	browseURL := "http://" + displayAddress(*host, *port)

	go func() {
		log.Printf("Wake-on-LAN service ready - open %s in your browser", browseURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// With no console attached the startup banner is invisible, so a first-run
	// password has to be shown some other way.
	announceFirstRun(firstRunPassword, browseURL)

	// On Windows this puts an icon in the notification area and blocks until
	// Quit is chosen; elsewhere it waits for Ctrl-C.
	waitForShutdown(browseURL)

	log.Printf("Shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Forced shutdown: %v", err)
	}
}

// quietWriter swallows write errors from the wrapped writer.
type quietWriter struct{ w io.Writer }

func (q quietWriter) Write(p []byte) (int, error) {
	if q.w != nil {
		_, _ = q.w.Write(p)
	}
	return len(p), nil
}

var (
	dataDirOnce  sync.Once
	resolvedData string
)

// dataDir decides where wol.db and wol.log live. Anchoring them to the
// executable rather than the working directory matters once the program is
// started from a shortcut or the "Start with Windows" entry, where the working
// directory is somewhere like C:\Windows\System32 - a plain relative path
// would quietly create a second, empty database there.
func dataDir() string {
	dataDirOnce.Do(func() {
		exe, err := os.Executable()
		if err == nil {
			dir := filepath.Dir(exe)
			if writable(dir) {
				resolvedData = dir
				return
			}
			// Installed somewhere read-only, such as Program Files.
			if config, err := os.UserConfigDir(); err == nil {
				dir := filepath.Join(config, "WoL-go")
				if err := os.MkdirAll(dir, 0o755); err == nil {
					resolvedData = dir
					return
				}
			}
		}
		resolvedData = "." // fall back to the working directory
	})
	return resolvedData
}

func dataPath(name string) string {
	return filepath.Join(dataDir(), name)
}

func writable(dir string) bool {
	file, err := os.CreateTemp(dir, ".wolcheck")
	if err != nil {
		return false
	}
	name := file.Name()
	file.Close()
	os.Remove(name)
	return true
}

// waitForSignal blocks until the program is interrupted. It is the shutdown
// path for console and non-Windows builds.
func waitForSignal() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
}

// displayAddress turns a wildcard bind into something a person can click.
func displayAddress(host, port string) string {
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = "localhost"
	}
	return net.JoinHostPort(host, port)
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		c.Next()
	}
}

func initDB() *sql.DB {
	log.Printf("Using data directory %s", dataDir())
	// Foreign keys are off by default in SQLite; the access grants rely on
	// ON DELETE CASCADE to disappear with the device or person they belong to.
	//
	// WAL lets reads carry on while something is being written, and
	// busy_timeout makes a writer wait its turn instead of failing outright.
	// Without these, reloading the page quickly produced "database is locked"
	// errors, which surfaced as "could not load the list".
	dsn := dataPath("wol.db") +
		"?_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}

	// SQLite takes one writer at a time. Letting database/sql open several
	// connections just turns that into lock errors, so the pool is kept at
	// one: every query here is small, and none holds a cursor open while
	// issuing another.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err = db.Ping(); err != nil {
		log.Fatalf("Error connecting to the database: %v", err)
	}

	createTables(db) // Ensure tables are created after confirming the DB connection
	migrateMacAddresses(db)
	// After the migration, so rows it has just inserted are covered too.
	backfillVendors(db)
	backfillSortOrder(db)
	migratePlaintextPasswords(db)
	insertDefaultAdmin(db)
	return db
}

func createTables(db *sql.DB) {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS devices (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mac TEXT NOT NULL UNIQUE,
            ip TEXT,
            notes TEXT,
            broadcast TEXT,
            port INTEGER NOT NULL DEFAULT 9,
            last_woken INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );`,
		`CREATE TABLE IF NOT EXISTS users (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            token_version INTEGER NOT NULL DEFAULT 0
        );`,
		`CREATE TABLE IF NOT EXISTS settings (
            key TEXT NOT NULL PRIMARY KEY,
            value TEXT NOT NULL
        );`,
		// People who reach the service through Cloudflare Access. Recorded on
		// first sight so the administrator has someone to grant access to.
		`CREATE TABLE IF NOT EXISTS cf_users (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            first_seen INTEGER NOT NULL DEFAULT 0,
            last_seen INTEGER NOT NULL DEFAULT 0,
            note TEXT
        );`,
		// One row per computer shared with one person.
		`CREATE TABLE IF NOT EXISTS cf_user_devices (
            user_id INTEGER NOT NULL REFERENCES cf_users(id) ON DELETE CASCADE,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, device_id)
        );`,
		// One row per stretch of time a computer stayed in one state. The
		// tracker extends the open row while nothing changes, so long-term
		// history stays small.
		`CREATE TABLE IF NOT EXISTS device_history (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            state TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            ended_at INTEGER NOT NULL
        );`,
		`CREATE INDEX IF NOT EXISTS idx_history_device ON device_history (device_id, ended_at);`,
		// The companion program installed on a computer, which can put it to
		// sleep. One per device; only the hash of its token is kept.
		`CREATE TABLE IF NOT EXISTS agents (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            hostname TEXT,
            version TEXT,
            wake_armed INTEGER,
            fast_startup INTEGER,
            power_requests TEXT,
            last_seen INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL DEFAULT 0
        );`,
		// Short-lived pairing codes, stored hashed like any other credential.
		`CREATE TABLE IF NOT EXISTS agent_enrolments (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT NOT NULL,
            device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            used_at INTEGER NOT NULL DEFAULT 0
        );`,
		// Commands waiting to be collected. Rows are discarded once stale, so
		// a machine that slept through one does not act on it when it wakes.
		`CREATE TABLE IF NOT EXISTS agent_commands (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
            command TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );`,
		// Who woke which machine, and when.
		`CREATE TABLE IF NOT EXISTS wake_events (
            id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            at INTEGER NOT NULL,
            actor TEXT
        );`,
	}
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			log.Fatalf("Error creating table: %v", err)
		}
	}

	// Upgrade databases created before token revocation existed. SQLite has no
	// "ADD COLUMN IF NOT EXISTS", so a duplicate-column error here is expected.
	addColumnIfMissing(db, "users", "token_version INTEGER NOT NULL DEFAULT 0")

	// Everything learned about a machine is kept with it, rather than being
	// recomputed on every read or discarded after a scan.
	addColumnIfMissing(db, "devices", "hostname TEXT")
	addColumnIfMissing(db, "devices", "vendor TEXT")
	addColumnIfMissing(db, "devices", "last_seen INTEGER NOT NULL DEFAULT 0")
	addColumnIfMissing(db, "devices", "sort_order INTEGER NOT NULL DEFAULT 0")
}

// backfillVendors fills in the manufacturer for rows saved before it was
// stored, and for any row whose lookup previously failed. It runs once per
// start and touches only the rows that need it.
func backfillVendors(db *sql.DB) {
	rows, err := db.Query("SELECT id, mac FROM devices WHERE vendor IS NULL OR vendor = ''")
	if err != nil {
		log.Printf("Could not check manufacturers: %v", err)
		return
	}
	type pending struct {
		id  int64
		mac string
	}
	var todo []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.mac); err == nil {
			todo = append(todo, p)
		}
	}
	rows.Close()

	var filled int
	for _, p := range todo {
		vendor := vendorForMAC(p.mac)
		if vendor == "" {
			continue
		}
		if _, err := db.Exec("UPDATE devices SET vendor = ? WHERE id = ?", vendor, p.id); err != nil {
			log.Printf("Could not record manufacturer for %s: %v", p.mac, err)
			continue
		}
		filled++
	}
	if filled > 0 {
		log.Printf("Recorded the manufacturer for %d saved computer(s)", filled)
	}
}

// backfillSortOrder gives a position to rows that have never been arranged,
// so the list has a definite order from the outset. Existing arrangements are
// left alone: only rows still sitting at zero are numbered, alphabetically,
// after whatever has already been placed.
func backfillSortOrder(db *sql.DB) {
	rows, err := db.Query("SELECT id FROM devices WHERE sort_order = 0 ORDER BY name COLLATE NOCASE")
	if err != nil {
		log.Printf("Could not check the saved order: %v", err)
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}

	var highest int64
	if err := db.QueryRow("SELECT COALESCE(MAX(sort_order), 0) FROM devices").Scan(&highest); err != nil {
		log.Printf("Could not check the saved order: %v", err)
		return
	}

	for i, id := range ids {
		if _, err := db.Exec("UPDATE devices SET sort_order = ? WHERE id = ?", highest+int64(i)+1, id); err != nil {
			log.Printf("Could not set the order for device %d: %v", id, err)
		}
	}
}

func addColumnIfMissing(db *sql.DB, table, definition string) {
	if _, err := db.Exec("ALTER TABLE " + table + " ADD COLUMN " + definition); err != nil &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
		log.Fatalf("Error migrating %s table: %v", table, err)
	}
}

// migrateMacAddresses carries entries over from the original schema, which
// stored a bare list of MAC addresses with no names or metadata.
func migrateMacAddresses(db *sql.DB) {
	var exists int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'mac_addresses'").Scan(&exists)
	if err != nil || exists == 0 {
		return
	}

	rows, err := db.Query("SELECT mac FROM mac_addresses")
	if err != nil {
		log.Printf("Could not read legacy MAC list: %v", err)
		return
	}
	var macs []string
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err == nil {
			macs = append(macs, mac)
		}
	}
	rows.Close()

	// Entries are carried over as they stand: the old table held nothing but
	// MAC addresses, so the address is also the name, and the user can rename
	// them afterwards. The IP is filled in where the machine is already known
	// to the ARP cache, since that is what drives the online indicator.
	ips := legacyIPs(macs)

	var migrated int
	for _, mac := range macs {
		normalized, err := normalizeMAC(mac)
		if err != nil {
			log.Printf("Skipping unusable legacy MAC %q", mac)
			continue
		}
		ip := ips[normalized]
		res, err := db.Exec(
			"INSERT OR IGNORE INTO devices (name, mac, ip, port, created_at, vendor) VALUES (?, ?, ?, 9, ?, ?)",
			normalized, normalized, ip, time.Now().Unix(), vendorForMAC(normalized),
		)
		if err != nil {
			log.Printf("Could not migrate %s: %v", normalized, err)
			continue
		}
		if affected, _ := res.RowsAffected(); affected > 0 {
			migrated++
			log.Printf("  %s%s", normalized, describeAddress(ip))
		}
	}

	if migrated > 0 {
		log.Printf("Migrated %d saved MAC address(es) into the new device list", migrated)
	}
	if _, err := db.Exec("DROP TABLE mac_addresses"); err != nil {
		log.Printf("Could not drop legacy table: %v", err)
	}
}

// legacyIPs finds the current address of each saved MAC, where the machine is
// already in the ARP cache. This is a local lookup with no network traffic, so
// it costs nothing at startup; machines that are off simply have no IP
// recorded, and the user can fill one in later.
func legacyIPs(macs []string) map[string]string {
	// Reverse the ARP cache: it is keyed by address, and here the MAC is the
	// thing that is known. Both sides are already upper-case colon form.
	ipByMAC := map[string]string{}
	for ip, mac := range arpTable() {
		if _, exists := ipByMAC[mac]; !exists {
			ipByMAC[mac] = ip
		}
	}

	out := make(map[string]string, len(macs))
	for _, raw := range macs {
		if normalized, err := normalizeMAC(raw); err == nil {
			out[normalized] = ipByMAC[normalized]
		}
	}
	return out
}

func describeAddress(ip string) string {
	if ip == "" {
		return ""
	}
	return " at " + ip
}

// registerLegacyRoutes keeps the original endpoints working for anyone who
// scripted against them before the device list gained names and metadata.
func registerLegacyRoutes(router *gin.Engine) {
	router.POST("/login", loginRateLimit(), login)
	router.POST("/update-password", authorizeJWT(true), updatePassword)

	legacy := router.Group("", authorizeJWT(false))

	legacy.GET("/macs", func(c *gin.Context) {
		devices, err := loadDevices()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load your devices"})
			return
		}
		macs := []string{}
		for _, d := range devices {
			macs = append(macs, d.MAC)
		}
		c.JSON(http.StatusOK, macs)
	})

	legacy.POST("/macs", func(c *gin.Context) {
		var body struct {
			MAC string `json:"mac"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		mac, err := normalizeMAC(body.MAC)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err = db.Exec(
			"INSERT INTO devices (name, mac, port, created_at) VALUES (?, ?, 9, ?)",
			mac, mac, time.Now().Unix(),
		)
		if err != nil {
			if isUniqueViolation(err) {
				c.JSON(http.StatusConflict, gin.H{"error": "That MAC address is already on your list"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the device"})
			return
		}
		c.Status(http.StatusOK)
	})

	legacy.DELETE("/macs/:mac", func(c *gin.Context) {
		mac, err := normalizeMAC(c.Param("mac"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if _, err := db.Exec("DELETE FROM devices WHERE mac = ?", mac); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove the device"})
			return
		}
		c.Status(http.StatusOK)
	})

	legacy.POST("/macs/:mac/wake", func(c *gin.Context) {
		mac, err := normalizeMAC(c.Param("mac"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		device, err := scanDevice(db.QueryRow("SELECT "+deviceColumns+" FROM devices WHERE mac = ?", mac))
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Unknown MAC address"})
			return
		}
		if err := sendMagicPacket(device.MAC, device.Broadcast, device.Port, device.IP); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send the wake-up signal"})
			return
		}
		if _, err := db.Exec("UPDATE devices SET last_woken = ? WHERE id = ?", time.Now().Unix(), device.ID); err != nil {
			log.Printf("Could not record wake time: %v", err)
		}
		recordWake(device.ID, "legacy API")
		c.Status(http.StatusOK)
	})
}
