package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"WoL-go/internal/release"
)

// Updating, and why the server sits in the middle of it.
//
// Agents never speak to GitHub. The server checks for a release, downloads it
// once, verifies the signature, and then hands the binary to any agent that is
// told to update. That keeps machines on a network with no way out to the
// internet working, and means one daily request rather than one per computer.
//
// It does not mean the server is trusted. Every agent verifies the signature
// itself against the public key compiled into it, so the worst a compromised
// server can do is offer an old release. Nothing here can make an agent run
// code that Ed25519 signature does not cover - which is what keeps the promise
// that a stolen agent token cannot become a shell.
//
// Nothing installs itself. Checking is automatic; downloading and applying are
// both things the administrator presses a button for.

// updateRepo is the repository releases are taken from. A fork that publishes
// its own releases changes this and its own signing key together.
const updateRepo = "danzig666/WoL-go"

// appVersion is stamped in by the release build with
// -ldflags "-X main.appVersion=v1.2.0". An ordinary "go build" leaves it as
// the development value, which compares as older than every release.
var appVersion = release.DevVersion

const (
	settingUpdateCheck     = "update_check"
	settingUpdateLatest    = "update_latest"
	settingUpdateNotes     = "update_notes"
	settingUpdateURL       = "update_url"
	settingUpdatePublished = "update_published"
	settingUpdateChecked   = "update_checked_at"
)

// checkUpdatesEvery is deliberately unhurried. There is nothing to be gained
// from noticing a release within the hour, and an unauthenticated GitHub client
// gets sixty requests an hour to share with everything else on the address.
const checkUpdatesEvery = 24 * time.Hour

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type releaseInfo struct {
	Tag         string         `json:"tag_name"`
	URL         string         `json:"html_url"`
	PublishedAt string         `json:"published_at"`
	Notes       string         `json:"body"`
	Draft       bool           `json:"draft"`
	Prerelease  bool           `json:"prerelease"`
	Assets      []releaseAsset `json:"assets"`
}

var updates = struct {
	sync.Mutex
	latest        releaseInfo
	checkedAt     int64
	checkError    string
	downloading   bool
	downloadStep  string
	downloadError string
}{}

// --- Checking ---

// updateCheckEnabled reports whether the daily check runs. It is on unless
// somebody turned it off: knowing an update exists is useful, and it is the
// applying of one that is worth being deliberate about.
func updateCheckEnabled() bool {
	value, err := getSetting(settingUpdateCheck)
	if err != nil || value == "" {
		return true
	}
	return value == "1"
}

// startUpdateChecker does the first check shortly after startup - late enough
// not to slow the service appearing - and then daily.
func startUpdateChecker() {
	loadRememberedRelease()

	go func() {
		time.Sleep(45 * time.Second)
		for {
			if updateCheckEnabled() {
				if _, err := checkForUpdate(); err != nil {
					log.Printf("Update check failed: %v", err)
				}
			}
			time.Sleep(checkUpdatesEvery)
		}
	}()
}

// loadRememberedRelease restores what the last check found, so a restart does
// not blank the panel until the next check comes round.
func loadRememberedRelease() {
	tag, _ := getSetting(settingUpdateLatest)
	if tag == "" {
		return
	}
	notes, _ := getSetting(settingUpdateNotes)
	url, _ := getSetting(settingUpdateURL)
	published, _ := getSetting(settingUpdatePublished)
	checked, _ := getSetting(settingUpdateChecked)

	updates.Lock()
	defer updates.Unlock()
	updates.latest = releaseInfo{Tag: tag, Notes: notes, URL: url, PublishedAt: published}
	fmt.Sscanf(checked, "%d", &updates.checkedAt)
}

func rememberRelease(info releaseInfo, checkedAt int64) {
	_ = setSetting(settingUpdateLatest, info.Tag)
	_ = setSetting(settingUpdateNotes, info.Notes)
	_ = setSetting(settingUpdateURL, info.URL)
	_ = setSetting(settingUpdatePublished, info.PublishedAt)
	_ = setSetting(settingUpdateChecked, fmt.Sprintf("%d", checkedAt))
}

func githubClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func githubRequest(url string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// GitHub rejects requests with no user agent.
	req.Header.Set("User-Agent", "WoL-go/"+appVersion)
	return req, nil
}

// checkForUpdate asks GitHub about the newest release.
func checkForUpdate() (releaseInfo, error) {
	url := "https://api.github.com/repos/" + updateRepo + "/releases/latest"
	req, err := githubRequest(url)
	if err != nil {
		return releaseInfo{}, err
	}

	resp, err := githubClient().Do(req)
	if err != nil {
		recordCheckError(err.Error())
		return releaseInfo{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusForbidden && strings.Contains(string(body), "rate limit") {
		err := fmt.Errorf("GitHub is rate limiting this address; the next check is in a day")
		recordCheckError(err.Error())
		return releaseInfo{}, err
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("GitHub answered HTTP %d", resp.StatusCode)
		recordCheckError(err.Error())
		return releaseInfo{}, err
	}

	var info releaseInfo
	if err := json.Unmarshal(body, &info); err != nil {
		recordCheckError("GitHub's answer could not be read")
		return releaseInfo{}, err
	}
	if info.Tag == "" {
		err := fmt.Errorf("no releases published yet")
		recordCheckError(err.Error())
		return releaseInfo{}, err
	}

	now := time.Now().Unix()
	updates.Lock()
	updates.latest = info
	updates.checkedAt = now
	updates.checkError = ""
	updates.Unlock()
	rememberRelease(info, now)

	if release.IsNewer(info.Tag, appVersion) {
		log.Printf("Update available: %s (running %s)", info.Tag, appVersion)
	}
	return info, nil
}

func recordCheckError(message string) {
	updates.Lock()
	updates.checkError = message
	updates.checkedAt = time.Now().Unix()
	updates.Unlock()
}

// --- The downloaded copy ---

// updateDir holds one directory per downloaded release, beside the database.
func updateDir() string { return dataPath("updates") }

func releaseDir(version string) string {
	// Version strings come from GitHub tags and end up in a path, so anything
	// that is not obviously part of a version is dropped.
	return filepath.Join(updateDir(), safeVersion(version))
}

func safeVersion(version string) string {
	var b strings.Builder
	for _, r := range version {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cachedRelease returns the checksums of a downloaded release, having verified
// the signature again. Verifying on every use rather than trusting a marker
// file means a tampered cache is caught at the moment it would be served.
func cachedRelease(version string) (release.Checksums, error) {
	dir := releaseDir(version)
	sums, err := os.ReadFile(filepath.Join(dir, release.ChecksumFile))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, release.SignatureFile))
	if err != nil {
		return nil, err
	}
	return release.Verify(sums, sig)
}

// downloadedVersion reports which release, if any, is sitting on disk ready to
// be handed out.
func downloadedVersion() string {
	updates.Lock()
	tag := updates.latest.Tag
	updates.Unlock()
	if tag != "" {
		if _, err := cachedRelease(tag); err == nil {
			return tag
		}
	}

	// After a restart the remembered tag may not be what was downloaded.
	entries, err := os.ReadDir(updateDir())
	if err != nil {
		return ""
	}
	var found []string
	for _, entry := range entries {
		if entry.IsDir() {
			if _, err := cachedRelease(entry.Name()); err == nil {
				found = append(found, entry.Name())
			}
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Slice(found, func(i, j int) bool { return release.Compare(found[i], found[j]) > 0 })
	return found[0]
}

// assetsToCache is what gets downloaded: every agent build, because any of the
// paired computers might need one, and the server's own build for this
// platform.
func assetsToCache(sums release.Checksums) []string {
	var wanted []string
	for _, arch := range []string{"amd64", "386", "arm64"} {
		if name := release.AgentAsset(arch); sums.Has(name) {
			wanted = append(wanted, name)
		}
	}
	if name := serverAssetName(); sums.Has(name) {
		wanted = append(wanted, name)
	}
	return wanted
}

// downloadRelease fetches and verifies a release into the cache. It reports
// progress through the shared state so the panel can show what it is doing.
func downloadRelease(info releaseInfo) error {
	dir := releaseDir(info.Tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	assets := map[string]releaseAsset{}
	for _, a := range info.Assets {
		assets[a.Name] = a
	}

	sumsAsset, ok := assets[release.ChecksumFile]
	if !ok {
		return fmt.Errorf("release %s has no %s", info.Tag, release.ChecksumFile)
	}
	sigAsset, ok := assets[release.SignatureFile]
	if !ok {
		return fmt.Errorf("release %s is not signed (no %s), so it cannot be installed from here", info.Tag, release.SignatureFile)
	}

	setDownloadStep("checking the signature")
	sums, err := fetchBytes(sumsAsset.URL, 1<<20)
	if err != nil {
		return fmt.Errorf("could not download the checksums: %w", err)
	}
	sig, err := fetchBytes(sigAsset.URL, 4096)
	if err != nil {
		return fmt.Errorf("could not download the signature: %w", err)
	}
	checksums, err := release.Verify(sums, sig)
	if err != nil {
		return fmt.Errorf("release %s: %w", info.Tag, err)
	}

	wanted := assetsToCache(checksums)
	if len(wanted) == 0 {
		return fmt.Errorf("release %s contains nothing this server can use", info.Tag)
	}

	for i, name := range wanted {
		asset, ok := assets[name]
		if !ok {
			return fmt.Errorf("%s is listed in the checksums but missing from the release", name)
		}
		setDownloadStep(fmt.Sprintf("downloading %s (%d of %d)", name, i+1, len(wanted)))
		if err := fetchAsset(asset, filepath.Join(dir, name), checksums); err != nil {
			return err
		}
	}

	// The checksum list is written last, so a half-finished download never
	// looks like a complete one.
	if err := os.WriteFile(filepath.Join(dir, release.ChecksumFile), sums, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, release.SignatureFile), sig, 0o644); err != nil {
		return err
	}

	pruneOldDownloads(info.Tag)
	log.Printf("Downloaded and verified release %s", info.Tag)
	return nil
}

func fetchBytes(url string, limit int64) ([]byte, error) {
	req, err := githubRequest(url)
	if err != nil {
		return nil, err
	}
	resp, err := githubClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// fetchAsset downloads one file and keeps it only if it matches the signed
// checksum. A partial or altered download is discarded rather than cached.
func fetchAsset(asset releaseAsset, path string, sums release.Checksums) error {
	req, err := githubRequest(asset.URL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", asset.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %d", asset.Name, resp.StatusCode)
	}

	temp := path + ".part"
	file, err := os.Create(temp)
	if err != nil {
		return err
	}
	// 200 MB is far above any real binary here and well below anything that
	// could fill a disk unnoticed.
	if _, err := io.Copy(file, io.LimitReader(resp.Body, 200<<20)); err != nil {
		file.Close()
		os.Remove(temp)
		return fmt.Errorf("downloading %s: %w", asset.Name, err)
	}
	file.Close()

	check, err := os.Open(temp)
	if err != nil {
		return err
	}
	err = sums.Check(asset.Name, check)
	check.Close()
	if err != nil {
		os.Remove(temp)
		return err
	}

	os.Remove(path)
	return os.Rename(temp, path)
}

// pruneOldDownloads keeps only the release just fetched, so the cache does not
// grow by forty megabytes per release forever.
func pruneOldDownloads(keep string) {
	entries, err := os.ReadDir(updateDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != safeVersion(keep) {
			_ = os.RemoveAll(filepath.Join(updateDir(), entry.Name()))
		}
	}
}

func setDownloadStep(step string) {
	updates.Lock()
	updates.downloadStep = step
	updates.Unlock()
}

// --- The administrator's endpoints ---

type agentUpdateStatus struct {
	AgentID  int64  `json:"agent_id"`
	DeviceID int64  `json:"device_id"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
	Online   bool   `json:"online"`
	Behind   bool   `json:"behind"`
}

// agentUpdateStatuses lists every paired agent against the release that is
// downloaded, since that is the only version they could actually be given.
func agentUpdateStatuses(target string) []agentUpdateStatus {
	out := []agentUpdateStatus{}
	rows, err := db.Query(
		`SELECT a.id, a.device_id, COALESCE(a.hostname, ''), COALESCE(a.version, ''),
		        COALESCE(a.last_seen, 0), COALESCE(d.name, '')
		 FROM agents a LEFT JOIN devices d ON d.id = a.device_id
		 ORDER BY d.sort_order, a.device_id`)
	if err != nil {
		log.Printf("Database error: %v", err)
		return out
	}
	defer rows.Close()

	cutoff := time.Now().Add(-agentOfflineAfter).Unix()
	for rows.Next() {
		var s agentUpdateStatus
		var lastSeen int64
		if err := rows.Scan(&s.AgentID, &s.DeviceID, &s.Hostname, &s.Version, &lastSeen, &s.Name); err != nil {
			continue
		}
		s.Online = lastSeen > cutoff
		s.Behind = target != "" && release.IsNewer(target, s.Version)
		out = append(out, s)
	}
	return out
}

func updateStatus(c *gin.Context) {
	updates.Lock()
	latest := updates.latest
	checkedAt := updates.checkedAt
	checkError := updates.checkError
	downloading := updates.downloading
	step := updates.downloadStep
	downloadError := updates.downloadError
	updates.Unlock()

	downloaded := downloadedVersion()

	// Agents can only be moved to a release that is on disk here.
	target := downloaded
	c.JSON(http.StatusOK, gin.H{
		"current":          appVersion,
		"latest":           latest.Tag,
		"latest_url":       latest.URL,
		"latest_notes":     latest.Notes,
		"latest_published": latest.PublishedAt,
		"checked_at":       checkedAt,
		"check_error":      checkError,
		"check_enabled":    updateCheckEnabled(),
		"downloaded":       downloaded,
		"downloading":      downloading,
		"download_step":    step,
		"download_error":   downloadError,
		"server_behind":    latest.Tag != "" && release.IsNewer(latest.Tag, appVersion),
		"server_asset":     serverAssetName(),
		"server_can_apply": downloaded != "" && serverUpgradeAvailable(downloaded),
		"repo":             updateRepo,
		"agents":           agentUpdateStatuses(target),
	})
}

func updateSettings(c *gin.Context) {
	var body struct {
		Check *bool `json:"check"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Check == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	value := "0"
	if *body.Check {
		value = "1"
	}
	if err := setSetting(settingUpdateCheck, value); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the setting"})
		return
	}
	log.Printf("Automatic update checking is now %s", map[bool]string{true: "on", false: "off"}[*body.Check])
	c.JSON(http.StatusOK, gin.H{"check_enabled": *body.Check})
}

func checkUpdatesNow(c *gin.Context) {
	info, err := checkForUpdate()
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"latest":        info.Tag,
		"current":       appVersion,
		"server_behind": release.IsNewer(info.Tag, appVersion),
	})
}

// beginDownload fetches the release in the background: forty megabytes over a
// slow line is longer than any browser should be asked to wait.
func beginDownload(c *gin.Context) {
	updates.Lock()
	if updates.downloading {
		updates.Unlock()
		c.JSON(http.StatusConflict, gin.H{"error": "A download is already running"})
		return
	}
	info := updates.latest
	updates.Unlock()

	if info.Tag == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Check for an update first"})
		return
	}

	// The remembered release has no asset list after a restart, so ask again.
	if len(info.Assets) == 0 {
		fresh, err := checkForUpdate()
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
		info = fresh
	}

	updates.Lock()
	updates.downloading = true
	updates.downloadError = ""
	updates.downloadStep = "starting"
	updates.Unlock()

	go func() {
		err := downloadRelease(info)
		updates.Lock()
		updates.downloading = false
		updates.downloadStep = ""
		if err != nil {
			updates.downloadError = err.Error()
			log.Printf("Could not download release %s: %v", info.Tag, err)
		}
		updates.Unlock()
	}()

	c.JSON(http.StatusAccepted, gin.H{"downloading": info.Tag})
}

// upgradeAgent queues the upgrade for one agent. Like sleeping, it is a queued
// command a waiting poll is nudged about, so it happens within a second on a
// machine that is running.
func upgradeAgent(c *gin.Context) {
	agentID, err := parseID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown agent"})
		return
	}

	version := downloadedVersion()
	if version == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Download the release first"})
		return
	}

	if err := queueUpgrade(agentID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not send the command"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"sent": true, "version": version})
}

// upgradeAllAgents updates every agent that is behind, a moment apart.
//
// Staggering them is not politeness: each one restarts its own service and
// re-polls, and starting forty at the same instant would be a self-inflicted
// thundering herd on a machine that is often a NAS.
func upgradeAllAgents(c *gin.Context) {
	version := downloadedVersion()
	if version == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Download the release first"})
		return
	}

	var queued []string
	for i, agent := range agentUpdateStatuses(version) {
		if !agent.Behind || !agent.Online {
			continue
		}
		id := agent.AgentID
		delay := time.Duration(i) * 3 * time.Second
		time.AfterFunc(delay, func() {
			if err := queueUpgrade(id); err != nil {
				log.Printf("Could not queue an upgrade for agent %d: %v", id, err)
			}
		})
		queued = append(queued, agent.Name)
	}

	log.Printf("Queued %s for %d agent(s)", version, len(queued))
	c.JSON(http.StatusOK, gin.H{"sent": len(queued), "version": version, "computers": queued})
}

func queueUpgrade(agentID int64) error {
	if _, err := db.Exec(
		"INSERT INTO agent_commands (agent_id, command, created_at) VALUES (?, ?, ?)",
		agentID, commandUpgrade, time.Now().Unix(),
	); err != nil {
		log.Printf("Database error: %v", err)
		return err
	}
	deliverCommand(agentID, commandUpgrade)
	return nil
}

// --- The mirror the agents fetch from ---

// agentUpdateManifest tells an agent what is available and gives it everything
// it needs to check the download itself.
func agentUpdateManifest(c *gin.Context) {
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	version := downloadedVersion()
	if version == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No update has been downloaded"})
		return
	}

	sums, err := cachedRelease(version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No update has been downloaded"})
		return
	}

	name := release.AgentAsset(arch)
	path := filepath.Join(releaseDir(version), name)
	info, err := os.Stat(path)
	if err != nil || !sums.Has(name) {
		c.JSON(http.StatusNotFound, gin.H{"error": "No update for " + arch})
		return
	}

	sumsBody, err := os.ReadFile(filepath.Join(releaseDir(version), release.ChecksumFile))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}
	sigBody, err := os.ReadFile(filepath.Join(releaseDir(version), release.SignatureFile))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Something went wrong"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"version":   version,
		"asset":     name,
		"size":      info.Size(),
		"checksums": base64.StdEncoding.EncodeToString(sumsBody),
		"signature": strings.TrimSpace(string(sigBody)),
	})
}

// agentUpdateDownload serves the binary itself. It is plain bytes over the
// agent's authenticated connection; the agent decides whether to trust them by
// checking the signature, not by having asked us.
func agentUpdateDownload(c *gin.Context) {
	arch := c.DefaultQuery("arch", runtime.GOARCH)
	version := downloadedVersion()
	if version == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "No update has been downloaded"})
		return
	}

	name := release.AgentAsset(arch)
	path := filepath.Join(releaseDir(version), name)
	if _, err := os.Stat(path); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "No update for " + arch})
		return
	}

	deviceID := c.GetInt64("agentDeviceID")
	device, _ := deviceByID(deviceID)
	log.Printf("Sending %s %s to the agent on %q", name, version, device.Name)

	c.Header("Content-Type", "application/octet-stream")
	c.File(path)
}
