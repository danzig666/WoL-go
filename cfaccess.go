package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Cloudflare Access puts the signed-in user's address in this header before
// forwarding the request.
const cfEmailHeader = "Cf-Access-Authenticated-User-Email"

// cfTrustedNets are the source addresses whose Cloudflare headers are
// believed. It is empty until configured, which keeps the header inert by
// default: without this list anyone able to reach the service could simply
// send the header and become whoever they liked.
//
// It is guarded by a lock because the administrator can change it from the
// web interface while requests are being served - the tray build has no
// command line to pass a flag on.
var (
	cfMu          sync.RWMutex
	cfTrustedNets []*net.IPNet
	cfTrustValue  string
)

const cfTrustSetting = "cf_trust"

// cfEnabled reports whether Cloudflare identities are accepted at all.
func cfEnabled() bool {
	cfMu.RLock()
	defer cfMu.RUnlock()
	return len(cfTrustedNets) > 0
}

// cfTrustSpec returns the configured value as the user typed it.
func cfTrustSpec() string {
	cfMu.RLock()
	defer cfMu.RUnlock()
	return cfTrustValue
}

// applyCFTrust parses and installs a new trust list.
func applyCFTrust(value string) error {
	nets, err := parseCFTrust(value)
	if err != nil {
		return err
	}
	cfMu.Lock()
	cfTrustedNets = nets
	cfTrustValue = strings.TrimSpace(value)
	cfMu.Unlock()
	return nil
}

// loadCFTrust restores the saved setting at startup.
func loadCFTrust() {
	value, err := getSetting(cfTrustSetting)
	if err != nil || value == "" {
		return
	}
	if err := applyCFTrust(value); err != nil {
		log.Printf("Stored Cloudflare trust setting %q is unusable: %v", value, err)
	}
}

// parseCFTrust turns the -cf-trust value into networks. It accepts addresses
// and CIDR blocks, plus the word "localhost" for the common case of
// cloudflared running on this same machine.
func parseCFTrust(value string) ([]*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	var nets []*net.IPNet
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.EqualFold(part, "localhost") {
			_, v4, _ := net.ParseCIDR("127.0.0.0/8")
			_, v6, _ := net.ParseCIDR("::1/128")
			nets = append(nets, v4, v6)
			continue
		}

		if strings.Contains(part, "/") {
			_, block, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a valid address or network", part)
			}
			nets = append(nets, block)
			continue
		}

		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("%q is not a valid address or network", part)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

func cfTrustsAddress(ip net.IP) bool {
	if ip == nil {
		return false
	}
	cfMu.RLock()
	defer cfMu.RUnlock()
	for _, block := range cfTrustedNets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// --- Diagnostics ---
//
// Getting this working depends on one fact the administrator cannot easily
// discover: which address the tunnel actually connects from. The last few
// requests are therefore remembered, so the settings page can simply show it.

type cfSighting struct {
	At          int64  `json:"at"`
	Peer        string `json:"peer"`
	HeaderFound bool   `json:"header_found"`
	Email       string `json:"email"`
	Trusted     bool   `json:"trusted"`
	// CFHeaders lists the names of any Cloudflare headers on the request.
	// Names only, never values. This separates the two failures that look
	// identical from outside: a request that never went through Cloudflare at
	// all, and one that did but had no Access policy in front of it.
	CFHeaders []string `json:"cf_headers"`
	Host      string   `json:"host"`
}

// cloudflareHeaderNames returns the Cf-* headers present on a request.
func cloudflareHeaderNames(h http.Header) []string {
	var names []string
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "cf-") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

var (
	sightingMu sync.Mutex
	sightings  []cfSighting
)

func noteSighting(s cfSighting) {
	sightingMu.Lock()
	defer sightingMu.Unlock()

	// Collapse repeats from the same peer with the same outcome, so a busy
	// page does not push the interesting entries out of the list. The set of
	// Cloudflare headers is part of what makes an outcome distinct: a direct
	// visitor and a tunnel without Access both lack an identity, and telling
	// them apart is the whole point of this list.
	signature := strings.Join(s.CFHeaders, ",")
	for i, existing := range sightings {
		if existing.Peer == s.Peer && existing.HeaderFound == s.HeaderFound &&
			existing.Email == s.Email && existing.Trusted == s.Trusted &&
			strings.Join(existing.CFHeaders, ",") == signature {
			sightings[i].At = s.At
			return
		}
	}
	sightings = append([]cfSighting{s}, sightings...)
	if len(sightings) > 8 {
		sightings = sightings[:8]
	}
}

// warnOccasionally emits a message at most once a minute per subject, so a
// misconfiguration is visible in the log without every page load repeating it.
var (
	warnMu   sync.Mutex
	lastWarn = map[string]time.Time{}
)

func warnOccasionally(subject string, emit func()) {
	warnMu.Lock()
	if time.Since(lastWarn[subject]) < time.Minute {
		warnMu.Unlock()
		return
	}
	lastWarn[subject] = time.Now()
	warnMu.Unlock()
	emit()
}

func recentSightings() []cfSighting {
	sightingMu.Lock()
	defer sightingMu.Unlock()
	out := make([]cfSighting, len(sightings))
	copy(out, sightings)
	return out
}

// Identity is who is making a request.
type Identity struct {
	// Kind is "admin", "cloudflare" or "local".
	Kind   string
	Email  string
	UserID int64 // cf_users.id, for Cloudflare identities
}

func (i Identity) isAdmin() bool      { return i.Kind == "admin" }
func (i Identity) isCloudflare() bool { return i.Kind == "cloudflare" }

// seesEverything reports whether this identity may list every saved computer.
// Administrators and people on the local network may; a Cloudflare visitor is
// limited to what has been shared with their address.
func (i Identity) seesEverything() bool {
	return !i.isCloudflare()
}

const identityKey = "identity"

func identityOf(c *gin.Context) Identity {
	if value, ok := c.Get(identityKey); ok {
		if id, ok := value.(Identity); ok {
			return id
		}
	}
	return Identity{Kind: "local"}
}

var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// normalizeEmail lower-cases and sanity-checks an address.
func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", fmt.Errorf("an email address is required")
	}
	if len(value) > 254 {
		return "", fmt.Errorf("that email address is too long")
	}
	if !emailPattern.MatchString(value) {
		return "", fmt.Errorf("%q does not look like an email address", value)
	}
	return value, nil
}

// resolveIdentity works out who is calling, before any handler runs.
//
// The Cloudflare header is only consulted when the request actually arrives
// from a trusted source address. RemoteIP is the real TCP peer - proxy headers
// such as X-Forwarded-For are deliberately not consulted, since trusting those
// would let a remote caller claim to be the tunnel.
func resolveIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		identity := Identity{Kind: "local"}

		peerText := c.RemoteIP()
		peer := net.ParseIP(peerText)
		raw := c.GetHeader(cfEmailHeader)
		trusted := cfTrustsAddress(peer)

		// Every request is recorded, not only the ones bearing a header:
		// seeing "the tunnel connects from 127.0.0.1, no header" is exactly
		// what tells an administrator what is wrong.
		cfHeaders := cloudflareHeaderNames(c.Request.Header)
		sighting := cfSighting{
			At:          time.Now().Unix(),
			Peer:        peerText,
			HeaderFound: raw != "",
			Trusted:     trusted,
			CFHeaders:   cfHeaders,
			Host:        c.Request.Host,
		}

		switch {
		case raw == "" && len(cfHeaders) > 0:
			// The request came through Cloudflare, but Access did not add an
			// identity - almost always a hostname served by the tunnel with
			// no Access application in front of it.
			warnOccasionally("cf-no-identity", func() {
				log.Printf("Request for %q from %s carried Cloudflare headers (%s) but no identity header - "+
					"is Cloudflare Access enforcing on that hostname?",
					c.Request.Host, peerText, strings.Join(cfHeaders, ", "))
			})
		case raw == "":
			// Nothing to do; an ordinary local visitor.
		case !cfEnabled():
			warnOccasionally("cf-disabled", func() {
				log.Printf("An identity header arrived from %s, but Cloudflare identities are switched off. "+
					"Set the trusted source under People > Cloudflare Access setup (probably \"localhost\").", peerText)
			})
		case !trusted:
			// Sent from an address that is not the tunnel. That is exactly
			// the spoofing attempt this guard exists for.
			log.Printf("Ignoring Cloudflare identity header from untrusted address %s", peerText)
		default:
			email, err := normalizeEmail(raw)
			if err != nil {
				log.Printf("Ignoring malformed Cloudflare identity from %s", peerText)
			} else {
				sighting.Email = email
				user, err := touchCFUser(email)
				if err != nil {
					// The visitor is still a Cloudflare visitor: falling back
					// to a local identity here would show them every computer
					// on the list. With no user record their grant list is
					// empty, so they see nothing until the database recovers.
					log.Printf("Could not look up Cloudflare user %s: %v", email, err)
					identity = Identity{Kind: "cloudflare", Email: email, UserID: 0}
				} else {
					identity = Identity{Kind: "cloudflare", Email: email, UserID: user.ID}
				}
			}
		}

		noteSighting(sighting)
		c.Set(identityKey, identity)
		c.Next()
	}
}

// cfSettings reports the current configuration and what has been seen, so the
// administrator can tell at a glance why identities are or are not arriving.
func cfSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"cf_trust":  cfTrustSpec(),
		"enabled":   cfEnabled(),
		"locked":    cfTrustFromFlag,
		"sightings": recentSightings(),
	})
}

func updateCFSettings(c *gin.Context) {
	if cfTrustFromFlag {
		c.JSON(http.StatusConflict, gin.H{
			"error": "This is set by the -cf-trust command line option; remove it to manage the setting here.",
		})
		return
	}

	var body struct {
		CFTrust string `json:"cf_trust"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if err := applyCFTrust(body.CFTrust); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := setSetting(cfTrustSetting, cfTrustSpec()); err != nil {
		log.Printf("Could not save the Cloudflare setting: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the setting"})
		return
	}

	if cfEnabled() {
		log.Printf("Now trusting Cloudflare Access headers from %s", strings.Join(cfTrustDescription(), ", "))
	} else {
		log.Printf("Cloudflare Access identities turned off")
	}
	c.JSON(http.StatusOK, gin.H{"cf_trust": cfTrustSpec(), "enabled": cfEnabled()})
}

// requireVisitor rejects anonymous callers when anonymous waking is turned
// off, while still letting recognised Cloudflare visitors through.
func requireVisitor(publicWake bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if publicWake || identityOf(c).isCloudflare() {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Please sign in"})
	}
}

// cfTrustDescription renders the trusted networks for the startup log.
func cfTrustDescription() []string {
	cfMu.RLock()
	defer cfMu.RUnlock()
	var out []string
	for _, block := range cfTrustedNets {
		out = append(out, block.String())
	}
	return out
}

// getSetting and setSetting back the small key/value settings table.
func getSetting(key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

func setSetting(key, value string) error {
	_, err := db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", key, value)
	return err
}

// adminIdentity marks the request as coming from the signed-in administrator.
// It runs after authorizeJWT, which has already validated the session.
func adminIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, _ := c.Get("username")
		name, _ := username.(string)
		c.Set(identityKey, Identity{Kind: "admin", Email: name})
		c.Next()
	}
}
