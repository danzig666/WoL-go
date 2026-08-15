package main

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// CFUser is someone who has reached the service through Cloudflare Access.
type CFUser struct {
	ID        int64   `json:"id"`
	Email     string  `json:"email"`
	FirstSeen int64   `json:"first_seen"`
	LastSeen  int64   `json:"last_seen"`
	Note      string  `json:"note"`
	DeviceIDs []int64 `json:"device_ids"`
}

var (
	touchMu   sync.Mutex
	lastTouch = map[string]time.Time{}
)

// howOftenToRecordAVisit limits the "last seen" write. Updating it on every
// request turned each page load into a database write, which under a fast
// reload is enough contention to make writes fail.
const howOftenToRecordAVisit = time.Minute

// touchCFUser finds the person behind an address, creating the row on their
// first visit. A brand new person starts with no computers shared with them,
// so they see an empty list until the administrator grants something.
//
// The lookup comes first and the write is both rare and optional: identity
// must not depend on a write succeeding, or a momentarily busy database would
// quietly demote a Cloudflare visitor to an anonymous local one - which would
// show them somebody else's computers.
func touchCFUser(email string) (CFUser, error) {
	user, err := cfUserByEmail(email)
	if err == nil {
		recordVisit(user.ID, email)
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CFUser{}, err
	}

	now := time.Now().Unix()
	if _, err := db.Exec(
		`INSERT INTO cf_users (email, first_seen, last_seen) VALUES (?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET last_seen = excluded.last_seen`,
		email, now, now,
	); err != nil {
		return CFUser{}, err
	}
	return cfUserByEmail(email)
}

// recordVisit updates "last seen" at most once a minute per person, and
// treats failure as unimportant.
func recordVisit(id int64, email string) {
	touchMu.Lock()
	if time.Since(lastTouch[email]) < howOftenToRecordAVisit {
		touchMu.Unlock()
		return
	}
	lastTouch[email] = time.Now()
	touchMu.Unlock()

	if _, err := db.Exec("UPDATE cf_users SET last_seen = ? WHERE id = ?", time.Now().Unix(), id); err != nil {
		log.Printf("Could not record the visit by %s: %v", email, err)
	}
}

func cfUserByEmail(email string) (CFUser, error) {
	var u CFUser
	err := db.QueryRow(
		"SELECT id, email, first_seen, last_seen, COALESCE(note, '') FROM cf_users WHERE email = ?",
		email,
	).Scan(&u.ID, &u.Email, &u.FirstSeen, &u.LastSeen, &u.Note)
	if err != nil {
		return CFUser{}, err
	}
	u.DeviceIDs, err = grantedDeviceIDs(u.ID)
	return u, err
}

func grantedDeviceIDs(userID int64) ([]int64, error) {
	rows, err := db.Query("SELECT device_id FROM cf_user_devices WHERE user_id = ? ORDER BY device_id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// devicesForUser returns only the computers shared with this person.
func devicesForUser(userID int64) ([]Device, error) {
	rows, err := db.Query(
		"SELECT "+deviceColumns+` FROM devices
		 WHERE id IN (SELECT device_id FROM cf_user_devices WHERE user_id = ?)
		 ORDER BY sort_order, name COLLATE NOCASE`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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
	rows.Close()
	if err != nil {
		return nil, err
	}

	return withAgentState(devices), nil
}

// visibleDevices is the list the caller is allowed to know about.
func visibleDevices(id Identity) ([]Device, error) {
	if id.isCloudflare() {
		return devicesForUser(id.UserID)
	}
	return loadDevices()
}

// mayUseDevice reports whether the caller is allowed to see and wake a
// particular computer.
func mayUseDevice(id Identity, deviceID int64) (bool, error) {
	if id.seesEverything() {
		return true, nil
	}
	var count int
	err := db.QueryRow(
		"SELECT COUNT(*) FROM cf_user_devices WHERE user_id = ? AND device_id = ?",
		id.UserID, deviceID,
	).Scan(&count)
	return count > 0, err
}

// --- Administration ---

func listCFUsers(c *gin.Context) {
	rows, err := db.Query("SELECT id, email, first_seen, last_seen, COALESCE(note, '') FROM cf_users ORDER BY email")
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list of people"})
		return
	}
	defer rows.Close()

	users := []CFUser{}
	for rows.Next() {
		var u CFUser
		if err := rows.Scan(&u.ID, &u.Email, &u.FirstSeen, &u.LastSeen, &u.Note); err != nil {
			log.Printf("Database error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list of people"})
			return
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list of people"})
		return
	}

	// Attach the grants after the rows are read, so the connection is free.
	for i := range users {
		ids, err := grantedDeviceIDs(users[i].ID)
		if err != nil {
			log.Printf("Database error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not load the list of people"})
			return
		}
		users[i].DeviceIDs = ids
	}

	c.JSON(http.StatusOK, users)
}

// createCFUser lets the administrator authorise an address before its owner
// has ever visited, so access works on their first attempt.
func createCFUser(c *gin.Context) {
	var body struct {
		Email string `json:"email"`
		Note  string `json:"note"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter an email address"})
		return
	}

	email, err := normalizeEmail(body.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().Unix()
	_, err = db.Exec(
		"INSERT INTO cf_users (email, first_seen, last_seen, note) VALUES (?, 0, 0, ?)",
		email, body.Note,
	)
	if err != nil {
		if isUniqueViolation(err) {
			c.JSON(http.StatusConflict, gin.H{"error": "That person is already on the list"})
			return
		}
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not add that person"})
		return
	}
	_ = now

	user, err := cfUserByEmail(email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not add that person"})
		return
	}
	log.Printf("Administrator pre-authorised %s", email)
	c.JSON(http.StatusCreated, user)
}

// setCFUserDevices replaces the whole set of computers shared with a person.
func setCFUserDevices(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown person"})
		return
	}

	var body struct {
		DeviceIDs []int64 `json:"device_ids"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var email string
	if err := db.QueryRow("SELECT email FROM cf_users WHERE id = ?", id).Scan(&email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "That person is no longer on the list"})
			return
		}
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM cf_user_devices WHERE user_id = ?", id); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
		return
	}
	for _, deviceID := range body.DeviceIDs {
		// INSERT OR IGNORE also drops duplicates in the submitted list.
		if _, err := tx.Exec(
			"INSERT OR IGNORE INTO cf_user_devices (user_id, device_id) SELECT ?, id FROM devices WHERE id = ?",
			id, deviceID,
		); err != nil {
			log.Printf("Database error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
		return
	}

	granted, err := grantedDeviceIDs(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the changes"})
		return
	}
	log.Printf("Access for %s now covers %d computer(s)", email, len(granted))
	c.JSON(http.StatusOK, gin.H{"device_ids": granted})
}

func deleteCFUser(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown person"})
		return
	}

	res, err := db.Exec("DELETE FROM cf_users WHERE id = ?", id)
	if err != nil {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not remove that person"})
		return
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "That person is no longer on the list"})
		return
	}
	// Grants go with them; the foreign key is declared ON DELETE CASCADE, and
	// this covers databases where the pragma is not active.
	if _, err := db.Exec("DELETE FROM cf_user_devices WHERE user_id = ?", id); err != nil {
		log.Printf("Could not clear grants for user %d: %v", id, err)
	}
	log.Printf("Removed Cloudflare user %d", id)
	c.Status(http.StatusNoContent)
}

// whoAmI tells the page who it is talking to, so it can show the signed-in
// address and word its empty state correctly.
//
// This reports the *visitor* identity only. Whether an administrator session
// is also in play is something the page already knows from its own token, and
// the two are independent: an administrator signing in through the tunnel is
// still a Cloudflare visitor, and their address stays on screen.
func whoAmI(c *gin.Context) {
	id := identityOf(c)
	c.JSON(http.StatusOK, gin.H{
		"kind":              id.Kind,
		"email":             id.Email,
		"sees_everything":   id.seesEverything(),
		"cloudflare_active": cfEnabled(),
	})
}
