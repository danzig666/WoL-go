package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// An agent is a small companion program running on a computer, which polls for
// commands and can put that computer to sleep.
//
// The vocabulary is deliberately tiny. Anything that could run a program on the
// remote machine would turn this into a backdoor on every PC in the house,
// protected by one bearer token.
// The fourth word, upgrade, is the only one that changes what the agent is,
// and it is safe for a reason that has nothing to do with trusting this server:
// the agent installs the binary only if it carries the release signature.
// "Upgrade" therefore means "fetch a build signed by the release key", not
// "run whatever the server sends".
const (
	commandSleep      = "sleep"
	commandSleepForce = "sleep-force"
	commandUpgrade    = "upgrade"
)

// enrolmentValidFor bounds how long a pairing code can be used.
const enrolmentValidFor = 15 * time.Minute

// commandValidFor discards commands the agent did not collect in time.
//
// A sleeping computer is not polling. Without an expiry, a sleep command would
// sit in the queue and be collected the moment the machine was woken - sending
// it straight back to sleep.
const commandValidFor = 90 * time.Second

// longPollTimeout is how long an agent's request is held open waiting for
// something to do.
const longPollTimeout = 45 * time.Second

// agentOfflineAfter is how long without a heartbeat before an agent is
// considered gone.
const agentOfflineAfter = 2 * time.Minute

// Agent is the stored record.
type Agent struct {
	ID        int64  `json:"id"`
	DeviceID  int64  `json:"device_id"`
	Hostname  string `json:"hostname"`
	Version   string `json:"version"`
	LastSeen  int64  `json:"last_seen"`
	CreatedAt int64  `json:"created_at"`
	// Reported by the agent about its own machine, so the interface can warn
	// that waking will not work before the user finds out the hard way.
	WakeArmed     *bool  `json:"wake_armed"`
	FastStartup   *bool  `json:"fast_startup"`
	PowerRequests string `json:"power_requests"`
	Online        bool   `json:"online"`
}

// --- Waiting agents ---
//
// A parked long-poll waits on a channel and holds no database connection. The
// pool is a single connection, so a waiting request that held it would freeze
// the whole service.

type waitingAgent struct {
	commands chan string
}

var (
	waitersMu sync.Mutex
	waiters   = map[int64]*waitingAgent{}
)

func waitForCommand(agentID int64, timeout time.Duration) (string, bool) {
	waiter := &waitingAgent{commands: make(chan string, 1)}

	waitersMu.Lock()
	// Only one poll per agent; a reconnecting agent replaces the old one.
	if previous, ok := waiters[agentID]; ok {
		close(previous.commands)
	}
	waiters[agentID] = waiter
	waitersMu.Unlock()

	defer func() {
		waitersMu.Lock()
		if waiters[agentID] == waiter {
			delete(waiters, agentID)
		}
		waitersMu.Unlock()
	}()

	select {
	case command, ok := <-waiter.commands:
		return command, ok && command != ""
	case <-time.After(timeout):
		return "", false
	}
}

// deliverCommand hands a command to a waiting agent, reporting whether one was
// listening.
func deliverCommand(agentID int64, command string) bool {
	waitersMu.Lock()
	waiter, ok := waiters[agentID]
	waitersMu.Unlock()
	if !ok {
		return false
	}
	select {
	case waiter.commands <- command:
		return true
	default:
		return false
	}
}

// --- Tokens ---

// newAgentToken returns a token and the hash to store. Only the hash is kept,
// so the database cannot be read to impersonate an agent.
func newAgentToken() (token string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newEnrolmentCode returns a short code a person can retype, in the shape
// XXXX-XXXX. Ambiguous letters are absent from the alphabet.
func newEnrolmentCode() (string, error) {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	alphabet := base32.NewEncoding("ABCDEFGHJKLMNPQRSTUVWXYZ23456789").WithPadding(base32.NoPadding)
	text := alphabet.EncodeToString(buf)
	return text[:4] + "-" + text[4:8], nil
}

func normalizeCode(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

// --- Administration ---

// suggestedServerURLs lists the addresses an agent should be pointed at:
// this machine on the local network, never the public hostname.
//
// A hostname behind Cloudflare Access answers an agent with a sign-in page,
// and an agent cannot sign in. Taking the address from the browser would hand
// out exactly that hostname whenever the administrator happens to be working
// remotely, which is the one address guaranteed not to work.
func suggestedServerURLs() []string {
	port := listenPort
	if port == "" {
		port = "9543"
	}

	var urls []string
	seen := map[string]bool{}
	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		urls = append(urls, "http://"+net.JoinHostPort(ip, port))
	}

	// Bound to one address: that is the only one that will answer.
	if listenHost != "" && listenHost != "0.0.0.0" && listenHost != "::" {
		add(listenHost)
		return urls
	}

	// The address this machine uses to reach the outside world is the one on
	// the real network, rather than a hypervisor's.
	add(outboundIP())
	for _, network := range localNetworks() {
		if address, ok := network["address"].(string); ok {
			add(address)
		}
	}
	return urls
}

// createEnrolment issues a pairing code for one device.
func createEnrolment(c *gin.Context) {
	deviceID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}
	device, err := deviceByID(deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
		return
	}

	code, err := newEnrolmentCode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a code"})
		return
	}

	now := time.Now().Unix()
	if _, err := db.Exec(
		`INSERT INTO agent_enrolments (code_hash, device_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		hashToken(normalizeCode(code)), deviceID, now, now+int64(enrolmentValidFor.Seconds()),
	); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create a code"})
		return
	}

	log.Printf("Issued an agent code for %q", device.Name)
	c.JSON(http.StatusCreated, gin.H{
		"code":        code,
		"expires_in":  int(enrolmentValidFor.Seconds()),
		"device":      device.Name,
		"server_urls": suggestedServerURLs(),
	})
}

func listAgents(c *gin.Context) {
	rows, err := db.Query(
		`SELECT id, device_id, COALESCE(hostname, ''), COALESCE(version, ''),
		        COALESCE(last_seen, 0), COALESCE(created_at, 0),
		        wake_armed, fast_startup, COALESCE(power_requests, '')
		 FROM agents ORDER BY device_id`)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the agents"})
		return
	}
	defer rows.Close()

	agents := []Agent{}
	cutoff := time.Now().Add(-agentOfflineAfter).Unix()
	for rows.Next() {
		var a Agent
		var wake, fast sql.NullBool
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.Hostname, &a.Version,
			&a.LastSeen, &a.CreatedAt, &wake, &fast, &a.PowerRequests); err != nil {
			continue
		}
		if wake.Valid {
			a.WakeArmed = &wake.Bool
		}
		if fast.Valid {
			a.FastStartup = &fast.Bool
		}
		a.Online = a.LastSeen > cutoff
		agents = append(agents, a)
	}
	c.JSON(http.StatusOK, agents)
}

// parseID reads a numeric path parameter.
func parseID(value string) (int64, error) {
	return strconv.ParseInt(value, 10, 64)
}

func deleteAgent(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown agent"})
		return
	}
	if _, err := db.Exec("DELETE FROM agents WHERE id = ?", id); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove the agent"})
		return
	}
	log.Printf("Removed agent %d", id)
	c.Status(http.StatusNoContent)
}

// sleepDevice queues a sleep command for the agent on a device.
func sleepDevice(c *gin.Context) {
	deviceID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}

	identity := identityOf(c)
	allowed, err := mayUseDevice(identity, deviceID)
	if err != nil || !allowed {
		c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
		return
	}

	// Sleeping interrupts whoever is using the machine, so anyone other than
	// the administrator needs it to have been allowed for that computer.
	if !identity.isAdmin() {
		device, err := deviceByID(deviceID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
			return
		}
		if !device.SleepPublic {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Only the administrator can put this computer to sleep",
			})
			log.Printf("Refused sleep of %q for %s: not allowed for others", device.Name, wakeActor(identity))
			return
		}
	}

	var body struct {
		Force bool `json:"force"`
	}
	_ = c.ShouldBindJSON(&body)

	var agentID int64
	var lastSeen int64
	err = db.QueryRow("SELECT id, COALESCE(last_seen, 0) FROM agents WHERE device_id = ?", deviceID).
		Scan(&agentID, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No sleep agent is installed on that computer",
		})
		return
	}
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	command := commandSleep
	if body.Force {
		command = commandSleepForce
	}

	now := time.Now().Unix()
	if _, err := db.Exec(
		"INSERT INTO agent_commands (agent_id, command, created_at) VALUES (?, ?, ?)",
		agentID, command, now,
	); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send the command"})
		return
	}

	// Nudge a waiting poll so the machine sleeps now rather than at the next
	// cycle. If nothing is listening the command waits in the queue instead.
	delivered := deliverCommand(agentID, command)

	device, _ := deviceByID(deviceID)
	log.Printf("%s asked %q to sleep (force=%v, agent listening=%v)",
		wakeActor(identity), device.Name, body.Force, delivered)

	c.JSON(http.StatusOK, gin.H{
		"sent":          true,
		"agent_waiting": delivered,
		"agent_online":  lastSeen > time.Now().Add(-agentOfflineAfter).Unix(),
	})
}

// --- The agent's own endpoints ---

// enrolAgent exchanges a pairing code for a permanent token.
func enrolAgent(c *gin.Context) {
	var body struct {
		Code     string   `json:"code"`
		Hostname string   `json:"hostname"`
		Version  string   `json:"version"`
		MACs     []string `json:"macs"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	code := normalizeCode(body.Code)
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "A pairing code is required"})
		return
	}

	var enrolmentID, deviceID, expiresAt int64
	err := db.QueryRow(
		`SELECT id, device_id, expires_at FROM agent_enrolments
		 WHERE code_hash = ? AND used_at = 0`, hashToken(code),
	).Scan(&enrolmentID, &deviceID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Deliberately vague: an unknown code and a used one look the same.
		c.JSON(http.StatusUnauthorized, gin.H{"error": "That pairing code is not valid"})
		log.Printf("Rejected an agent pairing attempt from %s", c.RemoteIP())
		return
	}
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	if time.Now().Unix() > expiresAt {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "That pairing code has expired"})
		return
	}

	token, hash, err := newAgentToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	now := time.Now().Unix()
	// One agent per device: re-pairing replaces the previous one.
	if _, err := db.Exec("DELETE FROM agents WHERE device_id = ?", deviceID); err != nil {
		log.Printf("Database error: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO agents (device_id, token_hash, hostname, version, last_seen, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		deviceID, hash, body.Hostname, body.Version, now, now,
	); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not register the agent"})
		return
	}
	if _, err := db.Exec("UPDATE agent_enrolments SET used_at = ? WHERE id = ?", now, enrolmentID); err != nil {
		log.Printf("Database error: %v", err)
	}

	// The machine knows its own MAC addresses better than a network scan does.
	adoptReportedMACs(deviceID, body.MACs)

	device, _ := deviceByID(deviceID)
	log.Printf("Agent paired with %q (%s)", device.Name, body.Hostname)
	c.JSON(http.StatusCreated, gin.H{"token": token, "device": device.Name})
}

// adoptReportedMACs corrects the saved MAC if the machine reports a different
// one, which is the usual reason a computer never wakes.
func adoptReportedMACs(deviceID int64, macs []string) {
	device, err := deviceByID(deviceID)
	if err != nil {
		return
	}

	normalized := make([]string, 0, len(macs))
	for _, mac := range macs {
		if clean, err := normalizeMAC(mac); err == nil {
			normalized = append(normalized, clean)
		}
	}
	if len(normalized) == 0 {
		return
	}

	for _, mac := range normalized {
		if mac == device.MAC {
			return // already correct
		}
	}

	// Prefer the first reported address, which the agent orders with wired
	// adapters first.
	chosen := normalized[0]
	if _, err := db.Exec("UPDATE devices SET mac = ?, vendor = ? WHERE id = ?",
		chosen, vendorForMAC(chosen), deviceID); err != nil {
		log.Printf("Could not adopt the reported MAC for device %d: %v", deviceID, err)
		return
	}
	log.Printf("Agent corrected the MAC for %q: %s -> %s", device.Name, device.MAC, chosen)
}

// authorizeAgent validates the agent's bearer token and notes it as seen.
func authorizeAgent() gin.HandlerFunc {
	return func(c *gin.Context) {
		const bearer = "Bearer "
		header := c.GetHeader("Authorization")
		if !strings.HasPrefix(header, bearer) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "An agent token is required"})
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(header, bearer))

		var agentID, deviceID int64
		err := db.QueryRow("SELECT id, device_id FROM agents WHERE token_hash = ?", hashToken(token)).
			Scan(&agentID, &deviceID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "That agent token is not valid"})
			return
		}

		c.Set("agentID", agentID)
		c.Set("agentDeviceID", deviceID)
		c.Next()
	}
}

// agentHeartbeat records that the machine is awake and what it knows about its
// own power settings.
func agentHeartbeat(c *gin.Context) {
	agentID := c.GetInt64("agentID")

	var body struct {
		Hostname      string   `json:"hostname"`
		Version       string   `json:"version"`
		WakeArmed     *bool    `json:"wake_armed"`
		FastStartup   *bool    `json:"fast_startup"`
		PowerRequests string   `json:"power_requests"`
		MACs          []string `json:"macs"`
	}
	_ = c.ShouldBindJSON(&body)

	if _, err := db.Exec(
		`UPDATE agents SET last_seen = ?, hostname = ?, version = ?,
		        wake_armed = ?, fast_startup = ?, power_requests = ?
		 WHERE id = ?`,
		time.Now().Unix(), body.Hostname, body.Version,
		body.WakeArmed, body.FastStartup, body.PowerRequests, agentID,
	); err != nil {
		log.Printf("Database error: %v", err)
	}

	// An agent reporting in is proof the machine is running, which is better
	// evidence than any probe.
	deviceID := c.GetInt64("agentDeviceID")
	if _, err := db.Exec("UPDATE devices SET last_seen = ? WHERE id = ?",
		time.Now().Unix(), deviceID); err != nil {
		log.Printf("Database error: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// agentCommands is the long poll. The request is held open until there is
// something to do, and holds no database connection while it waits.
func agentCommands(c *gin.Context) {
	agentID := c.GetInt64("agentID")

	// Anything already queued and still fresh goes out immediately.
	if command, ok := takeQueuedCommand(agentID); ok {
		c.JSON(http.StatusOK, gin.H{"command": command})
		return
	}

	// The write deadline has to be pushed out, or the server's own 60 second
	// WriteTimeout would kill the held response.
	if controller := http.NewResponseController(c.Writer); controller != nil {
		_ = controller.SetWriteDeadline(time.Now().Add(longPollTimeout + 30*time.Second))
	}

	command, ok := waitForCommand(agentID, longPollTimeout)
	if !ok {
		// Nothing to do; the agent asks again straight away.
		c.JSON(http.StatusOK, gin.H{"command": ""})
		return
	}

	// Clear the queued row that the nudge corresponds to.
	takeQueuedCommand(agentID)
	c.JSON(http.StatusOK, gin.H{"command": command})
}

// takeQueuedCommand returns the newest unexpired command and clears the queue.
func takeQueuedCommand(agentID int64) (string, bool) {
	cutoff := time.Now().Add(-commandValidFor).Unix()

	var id int64
	var command string
	err := db.QueryRow(
		`SELECT id, command FROM agent_commands
		 WHERE agent_id = ? AND created_at >= ?
		 ORDER BY id DESC LIMIT 1`, agentID, cutoff,
	).Scan(&id, &command)

	// Whether or not something fresh was found, stale rows are cleared: a
	// command the machine slept through must not fire when it wakes.
	if _, err := db.Exec("DELETE FROM agent_commands WHERE agent_id = ?", agentID); err != nil {
		log.Printf("Database error: %v", err)
	}

	if errors.Is(err, sql.ErrNoRows) {
		return "", false
	}
	if err != nil {
		log.Printf("Database error: %v", err)
		return "", false
	}
	return command, true
}

// agentResult records what came of a command, for the log.
func agentResult(c *gin.Context) {
	var body struct {
		Command string `json:"command"`
		OK      bool   `json:"ok"`
		Detail  string `json:"detail"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	deviceID := c.GetInt64("agentDeviceID")
	device, _ := deviceByID(deviceID)
	if body.OK {
		log.Printf("Agent on %q carried out %s", device.Name, body.Command)
	} else {
		log.Printf("Agent on %q could not %s: %s", device.Name, body.Command, body.Detail)
	}
	c.Status(http.StatusNoContent)
}

// agentSummary is attached to the device list so the interface knows which
// computers can be put to sleep.
func agentsByDevice() map[int64]Agent {
	out := map[int64]Agent{}
	rows, err := db.Query(
		`SELECT id, device_id, COALESCE(last_seen, 0), wake_armed, fast_startup,
		        COALESCE(power_requests, '')
		 FROM agents`)
	if err != nil {
		return out
	}
	defer rows.Close()

	cutoff := time.Now().Add(-agentOfflineAfter).Unix()
	for rows.Next() {
		var a Agent
		var wake, fast sql.NullBool
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.LastSeen, &wake, &fast, &a.PowerRequests); err != nil {
			continue
		}
		if wake.Valid {
			a.WakeArmed = &wake.Bool
		}
		if fast.Valid {
			a.FastStartup = &fast.Bool
		}
		a.Online = a.LastSeen > cutoff
		out[a.DeviceID] = a
	}
	return out
}

func pruneEnrolments() {
	if _, err := db.Exec("DELETE FROM agent_enrolments WHERE expires_at < ?",
		time.Now().Add(-24*time.Hour).Unix()); err != nil {
		log.Printf("Could not prune enrolments: %v", err)
	}
}

var _ = fmt.Sprintf
