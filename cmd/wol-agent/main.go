// Command wol-agent is the companion program that runs on a computer so
// WoL-go can put it to sleep.
//
// It makes only outbound requests, so no firewall rule or open port is needed
// on the machine it runs on. It holds a long poll open waiting for something
// to do, which is why pressing Sleep takes effect straight away rather than at
// the next poll.
//
// The set of things it will do is deliberately three words long: sleep, sleep
// by force, and report on itself. It cannot run programs, and there is no path
// through it to a shell.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"WoL-go/internal/binswap"
	"WoL-go/internal/release"
)

// version is stamped in by the release build with
// -ldflags "-X main.version=v1.2.0". A plain "go build" leaves the development
// value, which compares as older than any release.
var version = release.DevVersion

// heartbeatEvery is how often the agent reports in. It also decides how
// quickly the panel notices a machine has gone.
const heartbeatEvery = 30 * time.Second

type config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	// Cloudflare Access service token, for the case where the agent has to
	// reach the server through a protected hostname. Access cannot ask a
	// service for a password, so it authenticates with these two headers
	// instead.
	CFClientID     string `json:"cf_client_id,omitempty"`
	CFClientSecret string `json:"cf_client_secret,omitempty"`
}

// authorize adds the agent's credentials, and the Access service token when
// one is configured.
func (c config) authorize(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	c.addAccessHeaders(req)
}

func (c config) addAccessHeaders(req *http.Request) {
	if c.CFClientID != "" && c.CFClientSecret != "" {
		req.Header.Set("CF-Access-Client-Id", c.CFClientID)
		req.Header.Set("CF-Access-Client-Secret", c.CFClientSecret)
	}
}

// describeResponse turns a failed reply into something worth reading.
//
// A hostname behind Cloudflare Access answers an unauthenticated request with
// a sign-in page, so without this the agent printed several hundred lines of
// HTML and left the reader to work out what happened.
func describeResponse(status int, body []byte) string {
	text := strings.TrimSpace(string(body))

	var problem struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &problem) == nil && problem.Error != "" {
		return problem.Error
	}

	lower := strings.ToLower(text)
	if strings.Contains(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		if strings.Contains(lower, "cloudflare access") || strings.Contains(lower, "cloudflareaccess.com") {
			return "the address is protected by Cloudflare Access, which asked for a sign-in.\n" +
				"      Point the agent at the server's local address instead, for example\n" +
				"      --server http://192.168.1.10:9543, or supply an Access service token with\n" +
				"      --cf-client-id and --cf-client-secret."
		}
		return fmt.Sprintf("the server returned a web page rather than an answer (HTTP %d). "+
			"Check the address is the WoL-go server", status)
	}

	if len(text) > 200 {
		text = text[:200] + "..."
	}
	if text == "" {
		return fmt.Sprintf("HTTP %d", status)
	}
	return fmt.Sprintf("HTTP %d: %s", status, text)
}

func main() {
	log.SetFlags(log.LstdFlags)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// The helper runs before anything else, because it is a detached copy of a
	// newly installed binary whose only job is to restart the service.
	if os.Args[1] == "apply-update" {
		runApplyUpdate(os.Args[2:])
		return
	}

	// Repair an update that was interrupted between its two renames, so
	// whatever runs next finds a working installation.
	if exe, err := os.Executable(); err == nil {
		if err := binswap.Recover(exe); err != nil {
			log.Printf("could not recover the previous executable: %v", err)
		}
		binswap.Cleanup(exe)
	}

	switch os.Args[1] {
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "run":
		runAgent(os.Args[2:])
	case "stop":
		// Stop before replacing the executable: Windows locks a running one.
		if err := stopService(); err != nil {
			log.Fatalf("could not stop the service: %v", err)
		}
		log.Printf("Stopped. The executable can now be replaced.")
	case "start":
		if err := startService(); err != nil {
			log.Fatalf("could not start the service: %v", err)
		}
		log.Printf("Started.")
	case "restart":
		if err := stopService(); err != nil {
			log.Printf("could not stop: %v", err)
		}
		if err := startService(); err != nil {
			log.Fatalf("could not start the service: %v", err)
		}
		log.Printf("Restarted, running %s.", version)
	case "sleep":
		// Handy for checking the machine will actually suspend before
		// involving the server at all.
		force := len(os.Args) > 2 && os.Args[2] == "--force"
		if err := suspend(force); err != nil {
			log.Fatalf("could not sleep: %v", err)
		}
	case "update":
		// Updating by hand, for a machine being looked at directly. The server
		// still supplies the binary, and the signature is still what decides
		// whether it is installed.
		cfg, err := loadConfig()
		if err != nil {
			log.Fatalf("not paired yet: %v", err)
		}
		if err := upgrade(cfg); err != nil {
			log.Fatalf("could not update: %v", err)
		}
	case "status":
		runStatus()
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `wol-agent %s - lets WoL-go put this computer to sleep

  wol-agent install --server http://host:9543 --code XXXX-XXXX
        Pair with the server and install as a Windows service.
        Use the server's address on your own network. A hostname protected by
        Cloudflare Access will answer with a sign-in page instead; to go
        through it anyway, add an Access service token:
          --cf-client-id XXXX.access --cf-client-secret YYYY

  wol-agent uninstall
        Remove the service and forget the token.

  wol-agent stop | start | restart
        Control the service.

  wol-agent update
        Fetch the newest signed agent from the server and install it. Normally
        done from the WoL-go panel instead. The service restarts; the computer
        does not, and nobody is signed out.

  wol-agent run
        Run in the foreground (what the service does).

  wol-agent sleep [--force]
        Put this computer to sleep now, without the server.

  wol-agent status
        Show what this machine reports about waking.
`, version)
}

// --- Configuration ---

// configPath keeps the token beside the executable, matching where the server
// keeps its own database.
func configPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "wol-agent.json"
	}
	return filepath.Join(filepath.Dir(exe), "wol-agent.json")
}

func loadConfig() (config, error) {
	var cfg config
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func saveConfig(cfg config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	// The token is a credential for this machine, so the file is written
	// read/write for its owner only.
	return os.WriteFile(configPath(), data, 0o600)
}

// --- Pairing ---

func runInstall(args []string) {
	flags := flag.NewFlagSet("install", flag.ExitOnError)
	server := flags.String("server", "", "Address of the WoL-go server, e.g. http://192.168.1.10:9543")
	code := flags.String("code", "", "Pairing code shown by the server")
	noService := flags.Bool("no-service", false, "Pair only; do not install the Windows service")
	clientID := flags.String("cf-client-id", "", "Cloudflare Access service token id, if the server is behind Access")
	clientSecret := flags.String("cf-client-secret", "", "Cloudflare Access service token secret")
	flags.Parse(args)

	if *server == "" || *code == "" {
		log.Fatal("both -server and -code are required")
	}

	cfg := config{
		Server:         strings.TrimRight(*server, "/"),
		CFClientID:     *clientID,
		CFClientSecret: *clientSecret,
	}

	token, device, err := enrol(cfg, *code)
	if err != nil {
		log.Fatalf("could not pair: %v", err)
	}
	cfg.Token = token
	if err := saveConfig(cfg); err != nil {
		log.Fatalf("could not save the token: %v", err)
	}
	log.Printf("Paired with %q as %s", device, hostname())

	if *noService {
		log.Printf("Not installing the service; run \"wol-agent run\" to start.")
		return
	}
	if err := installService(); err != nil {
		log.Fatalf("could not install the service: %v", err)
	}
	log.Printf("Installed and started. This computer can now be put to sleep from WoL-go.")
}

func enrol(cfg config, code string) (token string, device string, err error) {
	body, _ := json.Marshal(map[string]any{
		"code":     code,
		"hostname": hostname(),
		"version":  version,
		"macs":     localMACs(),
	})

	req, err := http.NewRequest(http.MethodPost, cfg.Server+"/api/agent/enrol", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	cfg.addAccessHeaders(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Bounded, because an unexpected reply can be an entire web page.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}

	var reply struct {
		Token  string `json:"token"`
		Device string `json:"device"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return "", "", err
	}
	return reply.Token, reply.Device, nil
}

func runUninstall(args []string) {
	if err := uninstallService(); err != nil {
		log.Printf("could not remove the service: %v", err)
	}
	if err := os.Remove(configPath()); err != nil && !os.IsNotExist(err) {
		log.Printf("could not remove %s: %v", configPath(), err)
	}
	log.Printf("Removed. Delete the agent from the WoL-go panel as well.")
}

// --- The loop ---

func runAgent(args []string) {
	flags := flag.NewFlagSet("run", flag.ExitOnError)
	flags.Parse(args)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("not paired yet: %v (run \"wol-agent install\" first)", err)
	}

	log.Printf("wol-agent %s reporting to %s", version, cfg.Server)
	serve(cfg)
}

// serve runs the heartbeat and the long poll until told to stop.
func serve(cfg config) {
	stop := serviceStopChannel()

	// The poll is held open for the best part of a minute. Without cancelling
	// the request in flight, stopping the service would wait for that to
	// finish - long enough for Windows to call it a failed stop, and exactly
	// when a person is trying to replace the executable.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-stop
		cancel()
	}()

	go func() {
		// The first heartbeat goes out immediately so the panel lights up.
		for {
			if err := heartbeat(cfg); err != nil {
				log.Printf("heartbeat: %v", err)
			}
			select {
			case <-time.After(heartbeatEvery):
			case <-stop:
				return
			}
		}
	}()

	// Long poll. The client timeout is longer than the server's hold, so an
	// idle wait ends server-side rather than as a client error.
	client := &http.Client{Timeout: longPollClientTimeout}

	for {
		select {
		case <-stop:
			log.Printf("stopping")
			return
		default:
		}

		command, err := pollOnce(ctx, client, cfg)
		if err != nil {
			// A cancelled request means we are shutting down, not a fault.
			if ctx.Err() != nil {
				log.Printf("stopping")
				return
			}
			// A machine that just woke, or a server being restarted, both look
			// like this. Wait a little rather than hammering.
			log.Printf("poll: %v", err)
			select {
			case <-time.After(5 * time.Second):
			case <-stop:
				return
			}
			continue
		}
		if command == "" {
			continue
		}

		log.Printf("received command %q", command)
		err = carryOut(cfg, command)
		report(cfg, command, err)
	}
}

const longPollClientTimeout = 75 * time.Second

func pollOnce(ctx context.Context, client *http.Client, cfg config) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Server+"/api/agent/commands", nil)
	if err != nil {
		return "", err
	}
	cfg.authorize(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusUnauthorized && looksLikeJSON(data) {
		return "", fmt.Errorf("this agent is no longer registered; pair it again")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}

	var reply struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return "", fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}
	return reply.Command, nil
}

func carryOut(cfg config, command string) error {
	switch command {
	case "sleep":
		return suspend(false)
	case "sleep-force":
		return suspend(true)
	case "upgrade":
		return upgrade(cfg)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func report(cfg config, command string, outcome error) {
	payload := map[string]any{"command": command, "ok": outcome == nil}
	if outcome != nil {
		payload["detail"] = outcome.Error()
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, cfg.Server+"/api/agent/result", bytes.NewReader(body))
	if err != nil {
		return
	}
	cfg.authorize(req)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}
}

func heartbeat(cfg config) error {
	report := machineReport()
	body, _ := json.Marshal(report)

	req, err := http.NewRequest(http.MethodPost, cfg.Server+"/api/agent/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	cfg.authorize(req)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("%s", describeResponse(resp.StatusCode, data))
	}
	return nil
}

// looksLikeJSON distinguishes an answer from this service from a sign-in page
// returned by something in front of it.
func looksLikeJSON(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// --- What the machine knows about itself ---

type machineFacts struct {
	Hostname      string   `json:"hostname"`
	Version       string   `json:"version"`
	WakeArmed     *bool    `json:"wake_armed"`
	FastStartup   *bool    `json:"fast_startup"`
	PowerRequests string   `json:"power_requests"`
	MACs          []string `json:"macs"`
}

func machineReport() machineFacts {
	r := machineFacts{
		Hostname: hostname(),
		Version:  version,
		MACs:     localMACs(),
	}
	if armed, ok := wakeArmed(); ok {
		r.WakeArmed = &armed
	}
	if fast, ok := fastStartupEnabled(); ok {
		r.FastStartup = &fast
	}
	r.PowerRequests = powerRequests()
	return r
}

func runStatus() {
	r := machineReport()
	fmt.Printf("hostname:       %s\n", r.Hostname)
	fmt.Printf("MAC addresses:  %s\n", strings.Join(r.MACs, ", "))
	fmt.Printf("wake armed:     %s\n", describeBool(r.WakeArmed))
	fmt.Printf("fast startup:   %s\n", describeBool(r.FastStartup))
	if r.PowerRequests != "" {
		fmt.Printf("keeping awake:  %s\n", r.PowerRequests)
	}
	if cfg, err := loadConfig(); err == nil {
		fmt.Printf("paired with:    %s\n", cfg.Server)
	} else {
		fmt.Printf("paired with:    not paired\n")
	}
}

func describeBool(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "yes"
	}
	return "no"
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

// localMACs lists this machine's hardware addresses, wired adapters first,
// because Wake-on-LAN over a cable is what actually works.
func localMACs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	type candidate struct {
		mac      string
		wireless bool
		up       bool
	}
	var found []candidate

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) != 6 {
			continue
		}
		if looksVirtualAdapter(iface.Name) {
			continue
		}
		found = append(found, candidate{
			mac:      strings.ToUpper(iface.HardwareAddr.String()),
			wireless: looksWireless(iface.Name),
			up:       iface.Flags&net.FlagUp != 0,
		})
	}

	sort.SliceStable(found, func(i, j int) bool {
		if found[i].wireless != found[j].wireless {
			return !found[i].wireless // wired first
		}
		return found[i].up && !found[j].up
	})

	var macs []string
	for _, c := range found {
		macs = append(macs, c.mac)
	}
	return macs
}

func looksVirtualAdapter(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range []string{
		"vmware", "vmnet", "virtualbox", "vbox", "hyper-v", "vethernet",
		"docker", "wsl", "tailscale", "zerotier", "tap", "tun", "loopback",
		"bluetooth", "vpn", "wintun", "wireguard",
	} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func looksWireless(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "wi-fi") || strings.Contains(lower, "wifi") ||
		strings.Contains(lower, "wireless") || strings.Contains(lower, "wlan")
}

var _ = runtime.GOOS
