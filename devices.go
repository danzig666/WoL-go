package main

import (
	"database/sql"
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

// Device is a machine the user can wake. Everything known about it is stored,
// including the details discovered by a network scan, so a record stays
// complete even when the machine itself is switched off.
type Device struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Notes     string `json:"notes"`
	Broadcast string `json:"broadcast"`
	Port      int    `json:"port"`
	LastWoken int64  `json:"last_woken"`
	CreatedAt int64  `json:"created_at"`
	// Vendor is the manufacturer that owns the MAC prefix, recorded when the
	// device is saved so the list does not depend on the lookup table at
	// read time.
	Vendor string `json:"vendor"`
	// Hostname is what the machine called itself when it was last discovered,
	// kept separately from Name so a rename does not lose it.
	Hostname string `json:"hostname"`
	// LastSeen is when the machine last answered a probe.
	LastSeen int64 `json:"last_seen"`
	// CanSleep reports whether a sleep agent is installed and reporting in,
	// which is what decides if the interface offers a Sleep button.
	CanSleep    bool `json:"can_sleep"`
	AgentOnline bool `json:"agent_online"`
}

const deviceColumns = "id, name, mac, COALESCE(ip, ''), COALESCE(notes, ''), COALESCE(broadcast, ''), " +
	"COALESCE(port, 9), COALESCE(last_woken, 0), COALESCE(created_at, 0), " +
	"COALESCE(vendor, ''), COALESCE(hostname, ''), COALESCE(last_seen, 0)"

func scanDevice(row interface{ Scan(...interface{}) error }) (Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.Name, &d.MAC, &d.IP, &d.Notes, &d.Broadcast, &d.Port,
		&d.LastWoken, &d.CreatedAt, &d.Vendor, &d.Hostname, &d.LastSeen)
	if err == nil && d.Vendor == "" {
		// Older rows, or a manufacturer the table did not know at the time.
		d.Vendor = vendorForMAC(d.MAC)
	}
	return d, err
}

func loadDevices() ([]Device, error) {
	rows, err := db.Query("SELECT " + deviceColumns + " FROM devices ORDER BY sort_order, name COLLATE NOCASE")
	if err != nil {
		return nil, err
	}

	devices := []Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		devices = append(devices, d)
	}
	err = rows.Err()
	// Closed before the next query: the pool holds a single connection, so a
	// cursor left open here would deadlock against it.
	rows.Close()
	if err != nil {
		return nil, err
	}

	return withAgentState(devices), nil
}

// withAgentState marks the computers that have a sleep agent.
func withAgentState(devices []Device) []Device {
	if len(devices) == 0 {
		return devices
	}
	agents := agentsByDevice()
	for i := range devices {
		if agent, ok := agents[devices[i].ID]; ok {
			devices[i].CanSleep = true
			devices[i].AgentOnline = agent.Online
		}
	}
	return devices
}

func deviceByID(id int64) (Device, error) {
	return scanDevice(db.QueryRow("SELECT "+deviceColumns+" FROM devices WHERE id = ?", id))
}

// knownDevicesByMAC is used by the scanner to flag hosts already saved.
func knownDevicesByMAC() map[string]Device {
	out := map[string]Device{}
	devices, err := loadDevices()
	if err != nil {
		log.Printf("Could not load devices: %v", err)
		return out
	}
	for _, d := range devices {
		out[d.MAC] = d
	}
	return out
}

// normalizeMAC validates and canonicalizes a MAC address so only well-formed
// values reach the database or the packet builder.
func normalizeMAC(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("a MAC address is required")
	}
	// Accept the bare 12-digit form people copy out of router pages.
	compact := strings.Map(func(r rune) rune {
		if strings.ContainsRune(":-. ", r) {
			return -1
		}
		return r
	}, value)
	if len(compact) == 12 {
		var parts []string
		for i := 0; i < 12; i += 2 {
			parts = append(parts, compact[i:i+2])
		}
		value = strings.Join(parts, ":")
	}

	hw, err := net.ParseMAC(value)
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("%q is not a valid MAC address (expected something like 00:1A:2B:3C:4D:5E)", strings.TrimSpace(value))
	}
	return strings.ToUpper(hw.String()), nil
}

type deviceInput struct {
	Name      string `json:"name"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Notes     string `json:"notes"`
	Broadcast string `json:"broadcast"`
	Port      int    `json:"port"`
	// Hostname is supplied by the scan results when computers are added from
	// a discovery, so what the machine calls itself is kept alongside
	// whatever the user chooses to name it.
	Hostname string `json:"hostname"`
	Vendor   string `json:"vendor"`
}

// validate cleans up user input and returns a friendly message on failure.
func (in *deviceInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	in.IP = strings.TrimSpace(in.IP)
	in.Broadcast = strings.TrimSpace(in.Broadcast)
	in.Notes = strings.TrimSpace(in.Notes)
	in.Hostname = strings.TrimSpace(in.Hostname)

	mac, err := normalizeMAC(in.MAC)
	if err != nil {
		return err
	}
	in.MAC = mac

	// The manufacturer is derived, never taken from the caller.
	in.Vendor = vendorForMAC(mac)
	if len([]rune(in.Hostname)) > 128 {
		in.Hostname = string([]rune(in.Hostname)[:128])
	}

	if in.Name == "" {
		in.Name = in.MAC
	}
	if len([]rune(in.Name)) > 64 {
		return fmt.Errorf("name is too long (64 characters maximum)")
	}
	if len([]rune(in.Notes)) > 500 {
		return fmt.Errorf("notes are too long (500 characters maximum)")
	}
	if in.IP != "" {
		if ip := net.ParseIP(in.IP); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not a valid IPv4 address", in.IP)
		}
	}
	if in.Broadcast != "" {
		if ip := net.ParseIP(in.Broadcast); ip == nil || ip.To4() == nil {
			return fmt.Errorf("%q is not a valid broadcast address", in.Broadcast)
		}
	}
	if in.Port == 0 {
		in.Port = 9
	}
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func listDevices(c *gin.Context) {
	devices, err := loadDevices()
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load your devices"})
		return
	}
	c.JSON(http.StatusOK, devices)
}

func createDevice(c *gin.Context) {
	var in deviceInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please fill in the form"})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := db.Exec(
		// New entries go to the end of the list rather than jumping into the
		// middle of an arrangement the user has already made.
		`INSERT INTO devices (name, mac, ip, notes, broadcast, port, created_at, vendor, hostname, sort_order)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM devices))`,
		in.Name, in.MAC, in.IP, in.Notes, in.Broadcast, in.Port, time.Now().Unix(), in.Vendor, in.Hostname,
	)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "That MAC address is already on your list"})
			return
		}
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the device"})
		return
	}

	id, _ := res.LastInsertId()
	device, err := deviceByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the device"})
		return
	}
	log.Printf("Added device %q (%s)", device.Name, device.MAC)
	c.JSON(http.StatusCreated, device)
}

// createDevicesBulk backs the "add selected" button on the scan results.
func createDevicesBulk(c *gin.Context) {
	var body struct {
		Devices []deviceInput `json:"devices"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nothing to add"})
		return
	}
	if len(body.Devices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Select at least one device first"})
		return
	}
	if len(body.Devices) > 256 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Too many devices at once (256 maximum)"})
		return
	}

	var added, skipped int
	var problems []string
	for _, in := range body.Devices {
		if err := in.validate(); err != nil {
			problems = append(problems, err.Error())
			continue
		}
		_, err := db.Exec(
			// New entries go to the end of the list rather than jumping into the
			// middle of an arrangement the user has already made.
			`INSERT INTO devices (name, mac, ip, notes, broadcast, port, created_at, vendor, hostname, sort_order)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM devices))`,
			in.Name, in.MAC, in.IP, in.Notes, in.Broadcast, in.Port, time.Now().Unix(), in.Vendor, in.Hostname,
		)
		switch {
		case err == nil:
			added++
		case isUniqueViolation(err):
			skipped++
		default:
			log.Printf("Database error: %v", err)
			problems = append(problems, "could not save "+in.Name)
		}
	}

	log.Printf("Bulk add: %d added, %d already present", added, skipped)
	c.JSON(http.StatusOK, gin.H{"added": added, "skipped": skipped, "problems": problems})
}

func updateDevice(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}

	var in deviceInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please fill in the form"})
		return
	}
	if err := in.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	res, err := db.Exec(
		"UPDATE devices SET name = ?, mac = ?, ip = ?, notes = ?, broadcast = ?, port = ?, vendor = ?, hostname = COALESCE(NULLIF(?, ''), hostname) WHERE id = ?",
		in.Name, in.MAC, in.IP, in.Notes, in.Broadcast, in.Port, in.Vendor, in.Hostname, id,
	)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "Another device already uses that MAC address"})
			return
		}
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save your changes"})
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
		return
	}

	device, err := deviceByID(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save your changes"})
		return
	}
	log.Printf("Updated device %q (%s)", device.Name, device.MAC)
	c.JSON(http.StatusOK, device)
}

// reorderDevices stores the arrangement the administrator dragged the cards
// into. The whole list is sent, and positions are renumbered from one.
func reorderDevices(c *gin.Context) {
	var body struct {
		IDs []int64 `json:"ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if len(body.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Nothing to reorder"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the new order"})
		return
	}
	defer tx.Rollback()

	seen := make(map[int64]bool, len(body.IDs))
	position := 0
	for _, id := range body.IDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		position++
		if _, err := tx.Exec("UPDATE devices SET sort_order = ? WHERE id = ?", position, id); err != nil {
			log.Printf("Database error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the new order"})
			return
		}
	}

	// Anything the page did not mention - added by someone else while the
	// dragging was going on - is pushed to the end rather than losing its
	// place entirely.
	if _, err := tx.Exec(
		"UPDATE devices SET sort_order = sort_order + ? WHERE sort_order > ?",
		position, position,
	); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the new order"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the new order"})
		return
	}

	log.Printf("Saved a new order for %d computer(s)", position)
	c.Status(http.StatusNoContent)
}

func deleteDevice(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}

	res, err := db.Exec("DELETE FROM devices WHERE id = ?", id)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove the device"})
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
		return
	}
	log.Printf("Deleted device %d", id)
	c.Status(http.StatusNoContent)
}

func wakeDevice(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown device"})
		return
	}

	identity := identityOf(c)
	allowed, err := mayUseDevice(identity, id)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	if !allowed {
		// Deliberately the same answer as a device that does not exist, so
		// the endpoint cannot be used to discover which machines are saved.
		c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
		log.Printf("Refused wake of device %d for %s", id, identity.Email)
		return
	}

	device, err := deviceByID(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "That device no longer exists"})
			return
		}
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	if identity.Email != "" {
		log.Printf("%s (%s) is waking %q", identity.Email, identity.Kind, device.Name)
	}

	if err := sendMagicPacket(device.MAC, device.Broadcast, device.Port, device.IP); err != nil {
		log.Printf("Error sending magic packet: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send the wake-up signal"})
		return
	}

	now := time.Now().Unix()
	if _, err := db.Exec("UPDATE devices SET last_woken = ? WHERE id = ?", now, id); err != nil {
		log.Printf("Could not record wake time: %v", err)
	}
	recordWake(id, wakeActor(identity))
	c.JSON(http.StatusOK, gin.H{"success": true, "last_woken": now, "name": device.Name})
}

func wakeAllDevices(c *gin.Context) {
	// A Cloudflare visitor wakes only what has been shared with them.
	devices, err := visibleDevices(identityOf(c))
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load your devices"})
		return
	}
	if len(devices) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You have no devices yet"})
		return
	}

	actor := wakeActor(identityOf(c))
	var woken int
	for _, d := range devices {
		if err := sendMagicPacket(d.MAC, d.Broadcast, d.Port, d.IP); err != nil {
			log.Printf("Error waking %s: %v", d.Name, err)
			continue
		}
		recordWake(d.ID, actor)
		woken++
	}
	if _, err := db.Exec("UPDATE devices SET last_woken = ?", time.Now().Unix()); err != nil {
		log.Printf("Could not record wake time: %v", err)
	}
	c.JSON(http.StatusOK, gin.H{"woken": woken, "total": len(devices)})
}

// deviceStatus is what the interface draws a status dot from.
type deviceStatus struct {
	// Online means something answered a probe, which only happens while the
	// operating system is actually running.
	Online bool `json:"online"`
	// Asleep means nothing answered, but the machine still holds its address
	// on the network - the signature of a sleeping computer whose network
	// card is still listening, and therefore one that can be woken.
	Asleep bool   `json:"asleep"`
	IP     string `json:"ip,omitempty"`
}

// computeStatuses works out the state of every device.
//
// The ARP cache alone cannot tell sleeping from awake: a Wake-on-LAN network
// card answers ARP while the computer sleeps, which is precisely how it stays
// reachable enough to be woken. Treating an ARP entry as "online" therefore
// reported sleeping machines as switched on. Only a reply from a service -
// which needs the operating system to be running - proves a machine is awake,
// so the ARP entry is reported separately as "asleep" instead.
func computeStatuses(devices []Device, includeIP bool) map[string]deviceStatus {
	results := make(map[string]deviceStatus, len(devices))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, d := range devices {
		key := strconv.FormatInt(d.ID, 10)
		if d.IP == "" {
			results[key] = deviceStatus{}
			continue
		}
		wg.Add(1)
		go func(d Device, key string) {
			defer wg.Done()
			online := quickProbe(d.IP)
			status := deviceStatus{Online: online}
			if includeIP {
				status.IP = d.IP
			}
			mu.Lock()
			results[key] = status
			mu.Unlock()
		}(d, key)
	}
	wg.Wait()

	arp := arpTable()
	for _, d := range devices {
		key := strconv.FormatInt(d.ID, 10)
		status := results[key]
		if !status.Online && d.IP != "" && arp[d.IP] == d.MAC {
			status.Asleep = true
			results[key] = status
		}
		// Remember when the machine was last actually running, so the list
		// can still say something useful once it is off again. Written at most
		// once a minute per machine: every open page polls this endpoint, and
		// writing on each poll is needless contention.
		now := time.Now().Unix()
		if status.Online && now-d.LastSeen >= 60 {
			if _, err := db.Exec("UPDATE devices SET last_seen = ? WHERE id = ?", now, d.ID); err != nil {
				log.Printf("Could not record last seen for device %d: %v", d.ID, err)
			}
		}
	}
	return results
}

// devicesStatus reports which machines are currently reachable. It is a
// best-effort check: a machine behind a strict firewall may be awake but
// appear offline, which is why the UI labels it "no reply" rather than "off".
func devicesStatus(c *gin.Context) {
	devices, err := loadDevices()
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load your devices"})
		return
	}
	c.JSON(http.StatusOK, computeStatuses(devices, true))
}

// quickProbe asks whether anything is actually running on the machine. The
// ports are tried at once rather than one after another, so a page full of
// devices refreshes quickly.
func quickProbe(ip string) bool {
	if _, _, ok := nbstat(ip, 250*time.Millisecond); ok {
		return true
	}

	// 445 and 139 are Windows file sharing, 135 the RPC mapper (open on most
	// Windows machines on a private network), then remote desktop, SSH and a
	// couple of common web ports.
	ports := []int{445, 135, 139, 3389, 22, 80, 8080}
	found := make(chan bool, len(ports))
	for _, port := range ports {
		go func(port int) {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				found <- true
				return
			}
			found <- false
		}(port)
	}

	for range ports {
		if <-found {
			return true
		}
	}
	return false
}

// --- Anonymous access ---
//
// Waking a machine is deliberately available without signing in: it is a
// harmless action (the worst outcome is a computer turning on) and it is the
// one thing people want to do from a phone without hunting for a password.
// Everything that changes the list, and every detail that is not needed to
// press the button, stays behind the password.

// PublicDevice is the reduced view anonymous callers receive. It deliberately
// omits the MAC address, IP address and notes: publishing those would let
// anyone on the network inventory the machines and spoof their addresses.
type PublicDevice struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Vendor    string `json:"vendor"`
	LastWoken int64  `json:"last_woken"`
}

func listPublicDevices(c *gin.Context) {
	devices, err := visibleDevices(identityOf(c))
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list"})
		return
	}

	out := make([]PublicDevice, 0, len(devices))
	for _, d := range devices {
		out = append(out, PublicDevice{
			ID:        d.ID,
			Name:      d.Name,
			Vendor:    d.Vendor,
			LastWoken: d.LastWoken,
		})
	}
	c.JSON(http.StatusOK, out)
}

// publicStatus mirrors devicesStatus without echoing the IP addresses back.
func publicStatus(c *gin.Context) {
	devices, err := visibleDevices(identityOf(c))
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list"})
		return
	}
	c.JSON(http.StatusOK, computeStatuses(devices, false))
}

// wakeRateLimit caps how often an anonymous caller can emit magic packets, so
// an open endpoint cannot be turned into a broadcast flood.
type wakeRecord struct {
	count int
	since time.Time
}

var (
	wakeMu      sync.Mutex
	wakeCounts  = map[string]*wakeRecord{}
	maxWakes    = 30
	wakeWindow  = time.Minute
	lastCleanup time.Time
)

func wakeRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()

		wakeMu.Lock()
		if now.Sub(lastCleanup) > wakeWindow {
			for k, v := range wakeCounts {
				if now.Sub(v.since) > wakeWindow {
					delete(wakeCounts, k)
				}
			}
			lastCleanup = now
		}

		rec, ok := wakeCounts[ip]
		if !ok || now.Sub(rec.since) > wakeWindow {
			rec = &wakeRecord{since: now}
			wakeCounts[ip] = rec
		}
		rec.count++
		blocked := rec.count > maxWakes
		wakeMu.Unlock()

		if blocked {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many wake-up requests. Please wait a minute.",
			})
			log.Printf("Rate limited wake requests from %s", ip)
			return
		}
		c.Next()
	}
}

// wakeActor labels a wake event for the activity list.
func wakeActor(id Identity) string {
	switch {
	case id.isAdmin():
		return "administrator"
	case id.isCloudflare():
		return id.Email
	default:
		return "local network"
	}
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToUpper(err.Error()), "UNIQUE CONSTRAINT FAILED")
}

// --- Network discovery endpoints ---

func listNetworks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"networks": localNetworks(),
		"default":  defaultNetwork(),
	})
}

func beginScan(c *gin.Context) {
	var body struct {
		Network string `json:"network"`
	}
	_ = c.ShouldBindJSON(&body)

	if err := startScan(strings.TrimSpace(body.Network)); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, currentScan.snapshot())
}

func scanStatus(c *gin.Context) {
	c.JSON(http.StatusOK, currentScan.snapshot())
}
