package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// jwtKey is loaded from the WOL_JWT_SECRET environment variable, or generated
// randomly on first run and persisted in the database. It is never hardcoded.
var jwtKey []byte

const tokenIssuer = "wol-go"

// migratePlaintextPasswords rehashes any credentials left over from the
// version of this service that stored passwords in the clear.
func migratePlaintextPasswords(db *sql.DB) {
	rows, err := db.Query("SELECT id, password FROM users")
	if err != nil {
		log.Fatalf("Error reading users: %v", err)
	}
	type migration struct {
		id       int
		password string
	}
	var pending []migration
	for rows.Next() {
		var m migration
		if err := rows.Scan(&m.id, &m.password); err != nil {
			rows.Close()
			log.Fatalf("Error reading users: %v", err)
		}
		if !strings.HasPrefix(m.password, "$2") { // not a bcrypt hash
			pending = append(pending, m)
		}
	}
	rows.Close()

	for _, m := range pending {
		hash, err := hashPassword(m.password)
		if err != nil {
			log.Fatalf("Error hashing stored password: %v", err)
		}
		// Force a password change: the old value was readable on disk.
		if _, err := db.Exec("UPDATE users SET password = ?, must_change_password = 1 WHERE id = ?", hash, m.id); err != nil {
			log.Fatalf("Error upgrading stored password: %v", err)
		}
		log.Printf("Upgraded plaintext password for user id %d to a bcrypt hash; a password change is now required", m.id)
	}
}

func insertDefaultAdmin(db *sql.DB) {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", "admin").Scan(&count); err != nil {
		log.Fatalf("Error checking for default admin: %v", err)
	}
	if count > 0 {
		return
	}

	password, err := randomPassword()
	if err != nil {
		log.Fatalf("Error generating admin password: %v", err)
	}
	hash, err := hashPassword(password)
	if err != nil {
		log.Fatalf("Error hashing admin password: %v", err)
	}
	if _, err := db.Exec(
		"INSERT INTO users (username, password, must_change_password) VALUES (?, ?, 1)",
		"admin", hash,
	); err != nil {
		log.Fatalf("Error inserting default admin: %v", err)
	}

	// Kept for the startup dialog shown when there is no console to print to.
	firstRunPassword = password

	// Printed once, on first run only. It is not recoverable afterwards -
	// delete wol.db to start over.
	banner := strings.Repeat("=", 62)
	log.Printf("\n%s\n  FIRST RUN: an 'admin' account was created.\n\n      username: admin\n      password: %s\n\n  Write this down. It is shown only once, and you will be asked\n  to change it when you first sign in.\n%s\n", banner, password, banner)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func randomPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	// URL-safe alphabet keeps the password easy to retype from a console.
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// loadOrCreateJWTSecret prefers WOL_JWT_SECRET, falling back to a random
// secret persisted in the database so tokens survive restarts.
func loadOrCreateJWTSecret(db *sql.DB) []byte {
	if env := strings.TrimSpace(os.Getenv("WOL_JWT_SECRET")); env != "" {
		if len(env) < 32 {
			log.Fatalf("WOL_JWT_SECRET must be at least 32 characters")
		}
		log.Printf("Using JWT signing key from WOL_JWT_SECRET")
		return []byte(env)
	}

	var stored string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", "jwt_secret").Scan(&stored)
	switch {
	case err == nil && stored != "":
		secret, decErr := hex.DecodeString(stored)
		if decErr != nil {
			log.Fatalf("Error decoding stored JWT secret: %v", decErr)
		}
		return secret
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		log.Fatalf("Error reading JWT secret: %v", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("Error generating JWT secret: %v", err)
	}
	if _, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", "jwt_secret", hex.EncodeToString(secret)); err != nil {
		log.Fatalf("Error storing JWT secret: %v", err)
	}
	log.Printf("Generated a new random JWT signing key and stored it in the database")
	return secret
}

// loginRateLimit throttles password guessing per client IP.
type attemptRecord struct {
	failures int
	blocked  time.Time
	seen     time.Time
}

var (
	attemptsMu sync.Mutex
	attempts   = map[string]*attemptRecord{}
)

const (
	maxLoginFailures = 5
	loginLockout     = 15 * time.Minute
)

func loginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		attemptsMu.Lock()
		rec, ok := attempts[ip]
		if ok && time.Now().Before(rec.blocked) {
			retry := int(time.Until(rec.blocked).Seconds()) + 1
			attemptsMu.Unlock()
			c.Header("Retry-After", strconv.Itoa(retry))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many failed sign-in attempts. Please wait " + strconv.Itoa(retry/60+1) + " minute(s) and try again.",
			})
			log.Printf("Blocked login attempt from %s (rate limited)", ip)
			return
		}
		attemptsMu.Unlock()
		c.Next()
	}
}

func recordLoginFailure(ip string) {
	attemptsMu.Lock()
	defer attemptsMu.Unlock()

	// Opportunistically drop stale records so the map cannot grow without bound.
	cutoff := time.Now().Add(-loginLockout)
	for k, v := range attempts {
		if v.seen.Before(cutoff) && time.Now().After(v.blocked) {
			delete(attempts, k)
		}
	}

	rec, ok := attempts[ip]
	if !ok {
		rec = &attemptRecord{}
		attempts[ip] = rec
	}
	rec.failures++
	rec.seen = time.Now()
	if rec.failures >= maxLoginFailures {
		rec.blocked = time.Now().Add(loginLockout)
		rec.failures = 0
		log.Printf("Rate limiting %s after %d failed logins", ip, maxLoginFailures)
	}
}

func recordLoginSuccess(ip string) {
	attemptsMu.Lock()
	delete(attempts, ip)
	attemptsMu.Unlock()
}

// authorizeJWT validates the bearer token. Accounts flagged for a mandatory
// password change may only reach the password-change endpoint, so pass
// allowPendingPasswordChange for that route alone.
func authorizeJWT(allowPendingPasswordChange bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		const bearerSchema = "Bearer "
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, bearerSchema) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Please sign in"})
			return
		}
		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerSchema))
		if tokenString == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Please sign in"})
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		},
			jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
			jwt.WithIssuer(tokenIssuer),
			jwt.WithExpirationRequired(),
		)
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Your session has expired. Please sign in again."})
			log.Printf("Invalid API token: %v", err)
			return
		}

		subject, err := claims.GetSubject()
		if err != nil || subject == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			log.Printf("Invalid API token: missing subject")
			return
		}
		userID, err := strconv.Atoi(subject)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			log.Printf("Invalid API token: malformed subject")
			return
		}
		tokenVersion, ok := claims["ver"].(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			log.Printf("Invalid API token: missing version claim")
			return
		}

		// The account must still exist, and the token version must match the
		// current one, so a password change logs out every existing session.
		// A version counter is used rather than an issued-at timestamp because
		// the "iat" claim is only accurate to the second, which would let a
		// token minted in the same second as the change survive it.
		var mustChange int
		var currentVersion int64
		var username string
		err = db.QueryRow("SELECT username, must_change_password, token_version FROM users WHERE id = ?", userID).
			Scan(&username, &mustChange, &currentVersion)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid session"})
			log.Printf("Invalid API token: unknown user %d", userID)
			return
		}
		if int64(tokenVersion) != currentVersion {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Your session has expired. Please sign in again."})
			log.Printf("Rejected revoked token for user %d", userID)
			return
		}
		if mustChange == 1 && !allowPendingPasswordChange {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Please choose a new password first"})
			return
		}

		c.Set("userID", userID)
		c.Set("username", username)
		c.Next()
	}
}

func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter a username and password"})
		return
	}

	var user struct {
		ID                 int
		Password           string
		MustChangePassword int
		TokenVersion       int64
	}
	err := db.QueryRow("SELECT id, password, must_change_password, token_version FROM users WHERE username = ?", credentials.Username).
		Scan(&user.ID, &user.Password, &user.MustChangePassword, &user.TokenVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.Printf("Database error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong. Please try again."})
		return
	}

	if errors.Is(err, sql.ErrNoRows) {
		// Hash a dummy value anyway so response timing does not reveal
		// whether the username exists.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"),
			[]byte(credentials.Password))
		recordLoginFailure(c.ClientIP())
		log.Printf("Failed login for unknown user from %s", c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		recordLoginFailure(c.ClientIP())
		log.Printf("Failed login for user %q from %s", credentials.Username, c.ClientIP())
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Incorrect username or password"})
		return
	}
	recordLoginSuccess(c.ClientIP())

	tokenString, err := issueToken(user.ID, user.TokenVersion)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not start your session"})
		log.Printf("Could not create token: %v", err)
		return
	}
	log.Printf("User %s logged in", credentials.Username)

	c.JSON(http.StatusOK, gin.H{
		"token":                tokenString,
		"username":             credentials.Username,
		"must_change_password": user.MustChangePassword == 1,
	})
}

func issueToken(userID int, tokenVersion int64) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"exp": jwt.NewNumericDate(now.Add(24 * time.Hour)),
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now.Add(-time.Minute)),
		"iss": tokenIssuer,
		"sub": strconv.Itoa(userID),
		"ver": tokenVersion,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtKey)
}

var (
	hasLetter = regexp.MustCompile(`(?i)[a-z]`)
	hasDigit  = regexp.MustCompile(`[0-9]`)
)

func updatePassword(c *gin.Context) {
	var data struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Please enter a new password"})
		return
	}

	// The account is taken from the verified token, never from the request
	// body, so a caller cannot change another user's password.
	userID := c.GetInt("userID")

	if len(data.NewPassword) < 8 || !hasLetter.MatchString(data.NewPassword) || !hasDigit.MatchString(data.NewPassword) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters and include a letter and a number"})
		return
	}

	hash, err := hashPassword(data.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not update password"})
		log.Printf("Error hashing password: %v", err)
		return
	}

	// Bump the token version, which invalidates every token already issued for
	// this account, including the one used to make this request.
	var newVersion int64
	if err := db.QueryRow(
		"UPDATE users SET password = ?, must_change_password = 0, token_version = token_version + 1 WHERE id = ? RETURNING token_version",
		hash, userID,
	).Scan(&newVersion); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong. Please try again."})
		log.Printf("Database error: %v", err)
		return
	}

	// Hand back a fresh token so the user is not logged out by their own change.
	tokenString, err := issueToken(userID, newVersion)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not start your session"})
		log.Printf("Could not create token: %v", err)
		return
	}
	log.Printf("User %d changed their password", userID)

	c.JSON(http.StatusOK, gin.H{"success": "Password updated", "token": tokenString})
}
