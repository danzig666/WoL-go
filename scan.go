package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Discovery is one host found on the local network.
type Discovery struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	Known     bool   `json:"known"`
	KnownName string `json:"known_name"`
}

type scanJob struct {
	mu         sync.Mutex
	running    bool
	network    string
	total      int
	done       int32
	results    []Discovery
	errMsg     string
	startedAt  time.Time
	finishedAt time.Time
}

var currentScan = &scanJob{}

// Ports worth probing to decide a host is alive. Chosen to cover Windows
// file sharing, remote desktop, SSH, web UIs and printers.
var probePorts = []int{445, 139, 3389, 22, 80, 443, 8080, 9100}

const (
	maxScanHosts = 1024
	scanWorkers  = 96
)

// snapshot returns a copy safe to serialize while the scan is still running.
func (s *scanJob) snapshot() map[string]interface{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := make([]Discovery, len(s.results))
	copy(results, s.results)

	out := map[string]interface{}{
		"running": s.running,
		"network": s.network,
		"total":   s.total,
		"done":    int(atomic.LoadInt32(&s.done)),
		"results": results,
		"error":   s.errMsg,
	}
	if !s.finishedAt.IsZero() {
		out["finished_at"] = s.finishedAt.Unix()
		out["duration_ms"] = s.finishedAt.Sub(s.startedAt).Milliseconds()
	}
	return out
}

// localNetworks lists the IPv4 networks this machine is attached to, which is
// what the UI offers as scan targets.
func localNetworks() []map[string]interface{} {
	var nets []map[string]interface{}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nets
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || !ipnet.IP.IsPrivate() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			hosts := 1<<(32-ones) - 2
			if hosts < 1 {
				continue
			}
			nets = append(nets, map[string]interface{}{
				"cidr":      (&net.IPNet{IP: ipnet.IP.Mask(ipnet.Mask), Mask: ipnet.Mask}).String(),
				"interface": iface.Name,
				"address":   ipnet.IP.String(),
				"hosts":     hosts,
				"scannable": hosts <= maxScanHosts,
			})
		}
	}
	// Physical adapters first, so the dropdown opens on something meaningful.
	sort.Slice(nets, func(i, j int) bool {
		vi := looksVirtual(nets[i]["interface"].(string))
		vj := looksVirtual(nets[j]["interface"].(string))
		if vi != vj {
			return !vi
		}
		return nets[i]["cidr"].(string) < nets[j]["cidr"].(string)
	})
	return nets
}

// virtualAdapterHints match the interface names created by hypervisors and VPN
// clients. Their networks are real but almost never the one the user means,
// so they lose to a physical adapter when picking the default.
var virtualAdapterHints = []string{
	"vmware", "vmnet", "virtualbox", "vbox", "hyper-v", "vethernet",
	"docker", "wsl", "tailscale", "zerotier", "tap", "tun", "loopback",
	"bridge", "veth", "utun", "wg",
}

func looksVirtual(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range virtualAdapterHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

// defaultNetwork picks the network most likely to be the user's real LAN:
// a physical adapter, preferring the one carrying the default route.
func defaultNetwork() string {
	nets := localNetworks()

	gateway := outboundIP()
	best := ""
	bestScore := -1

	for _, n := range nets {
		if !n["scannable"].(bool) {
			continue
		}
		score := 0
		if !looksVirtual(n["interface"].(string)) {
			score += 2
		}
		// The address the OS would use to reach the internet is the strongest
		// signal available without parsing routing tables.
		if gateway != "" && n["address"].(string) == gateway {
			score += 4
		}
		if score > bestScore {
			bestScore = score
			best = n["cidr"].(string)
		}
	}
	return best
}

// outboundIP reports the local address the OS picks for external traffic. The
// UDP socket is never actually connected, so nothing is sent.
func outboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}

// hostsInCIDR expands a network into the addresses worth probing.
func hostsInCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("that does not look like a network address")
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 networks can be scanned")
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("only IPv4 networks can be scanned")
	}
	count := 1<<(32-ones) - 2
	if ones >= 31 {
		count = 1 << (32 - ones)
	}
	if count > maxScanHosts {
		return nil, fmt.Errorf("that network is too large to scan (%d addresses, limit %d)", count, maxScanHosts)
	}

	// Addresses assigned to this machine are skipped: the server is by
	// definition already awake and cannot be woken.
	self := localIPs()

	base := binary.BigEndian.Uint32(ipnet.IP.Mask(ipnet.Mask).To4())
	var hosts []string
	for i := 1; i <= count; i++ {
		addr := make(net.IP, 4)
		binary.BigEndian.PutUint32(addr, base+uint32(i))
		if !ipnet.Contains(addr) {
			continue
		}
		s := addr.String()
		if self[s] {
			continue
		}
		hosts = append(hosts, s)
	}
	return hosts, nil
}

func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			out[ipnet.IP.String()] = true
		}
	}
	return out
}

// startScan kicks off a background sweep. Only one runs at a time.
func startScan(cidr string) error {
	currentScan.mu.Lock()
	if currentScan.running {
		currentScan.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}

	if cidr == "" {
		cidr = defaultNetwork()
	}
	if cidr == "" {
		currentScan.mu.Unlock()
		return fmt.Errorf("could not work out which network to scan; enter one manually, for example 192.168.1.0/24")
	}

	hosts, err := hostsInCIDR(cidr)
	if err != nil {
		currentScan.mu.Unlock()
		return err
	}

	currentScan.running = true
	currentScan.network = cidr
	currentScan.total = len(hosts)
	currentScan.results = nil
	currentScan.errMsg = ""
	currentScan.startedAt = time.Now()
	currentScan.finishedAt = time.Time{}
	atomic.StoreInt32(&currentScan.done, 0)
	currentScan.mu.Unlock()

	go runScan(hosts)
	return nil
}

type probeResult struct {
	ip       string
	alive    bool
	netbios  string
	mac      string
	hostname string
}

func runScan(hosts []string) {
	log.Printf("Scanning %d addresses", len(hosts))

	results := make([]probeResult, len(hosts))
	var wg sync.WaitGroup
	queue := make(chan int, len(hosts))
	for i := range hosts {
		queue <- i
	}
	close(queue)

	for w := 0; w < scanWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range queue {
				results[idx] = probeHost(hosts[idx])
				atomic.AddInt32(&currentScan.done, 1)
			}
		}()
	}
	wg.Wait()

	// Probing forces the OS to resolve each responsive host at layer 2, so the
	// ARP cache now holds the MAC addresses - which is the whole point, since
	// a MAC is what Wake-on-LAN needs and it cannot be read from a TCP probe.
	arp := arpTable()

	known := knownDevicesByMAC()

	var discoveries []Discovery
	for _, r := range results {
		mac := r.mac
		if mac == "" {
			mac = arp[r.ip]
		}
		// A host with no MAC cannot be woken, so it is not worth listing.
		if !r.alive && mac == "" {
			continue
		}
		if mac == "" {
			continue
		}

		name := r.netbios
		if name == "" {
			name = r.hostname
		}

		d := Discovery{
			IP:       r.ip,
			MAC:      mac,
			Hostname: name,
			Vendor:   vendorForMAC(mac),
		}
		if dev, ok := known[mac]; ok {
			d.Known = true
			d.KnownName = dev.Name
			// Keep what was learned about a machine already on the list: its
			// current address, which moves with DHCP, the name it gave for
			// itself, and the fact it was reachable just now.
			if _, err := db.Exec(
				`UPDATE devices
				 SET ip = ?,
				     hostname = COALESCE(NULLIF(?, ''), hostname),
				     last_seen = ?
				 WHERE id = ?`,
				r.ip, name, time.Now().Unix(), dev.ID,
			); err != nil {
				log.Printf("Could not update device %d: %v", dev.ID, err)
			}
		}
		discoveries = append(discoveries, d)
	}

	// Many hosts answer at layer 2 but ignore every probe, so they never got a
	// reverse lookup during the sweep. Home routers usually publish the DHCP
	// hostname over DNS, which is the friendliest label available, so it is
	// worth a second pass over the ones still unnamed.
	resolveMissingNames(discoveries)

	sort.Slice(discoveries, func(i, j int) bool {
		return ipLess(discoveries[i].IP, discoveries[j].IP)
	})

	currentScan.mu.Lock()
	currentScan.results = discoveries
	currentScan.running = false
	currentScan.finishedAt = time.Now()
	currentScan.mu.Unlock()

	log.Printf("Scan finished: %d devices found", len(discoveries))
}

func resolveMissingNames(discoveries []Discovery) {
	var wg sync.WaitGroup
	queue := make(chan int, len(discoveries))
	for i := range discoveries {
		if discoveries[i].Hostname == "" {
			queue <- i
		}
	}
	close(queue)

	for w := 0; w < 32; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range queue {
				ip := discoveries[idx].IP
				if name := reverseDNS(ip, 700*time.Millisecond); name != "" {
					discoveries[idx].Hostname = name
					continue
				}
				// Apple devices, anything running Avahi, printers and most
				// smart-home gear answer mDNS but have no DNS or NetBIOS name.
				if name := mdnsName(ip, 700*time.Millisecond); name != "" {
					discoveries[idx].Hostname = name
				}
			}
		}()
	}
	wg.Wait()
}

func ipLess(a, b string) bool {
	ia, ib := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}

// probeHost checks one address. The NetBIOS query doubles as the packet that
// populates the ARP cache, and often returns the computer name for free.
func probeHost(ip string) probeResult {
	res := probeResult{ip: ip}

	if name, mac, ok := nbstat(ip, 400*time.Millisecond); ok {
		res.alive = true
		res.netbios = name
		res.mac = mac
	}

	if !res.alive {
		for _, port := range probePorts {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, fmt.Sprint(port)), 250*time.Millisecond)
			if err == nil {
				conn.Close()
				res.alive = true
				break
			}
		}
	}

	if res.alive && res.netbios == "" {
		res.hostname = reverseDNS(ip, 600*time.Millisecond)
	}
	return res
}

func reverseDNS(ip string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSpace(names[0]), ".")
}

// mdnsName asks the host directly for its own name using a reverse mDNS
// lookup. Sending it as a unicast query to port 5353 (a "legacy" query in
// RFC 6762 terms) means the reply comes straight back to us, so no multicast
// group membership is needed.
func mdnsName(ip string, timeout time.Duration) string {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return ""
	}
	arpa := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", parsed[3], parsed[2], parsed[1], parsed[0])

	question, err := dnsmessage.NewName(arpa)
	if err != nil {
		return ""
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0, RecursionDesired: false},
		Questions: []dnsmessage.Question{{
			Name:  question,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return ""
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "5353"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return ""
	}
	if _, err := conn.Write(packed); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	var reply dnsmessage.Message
	if err := reply.Unpack(buf[:n]); err != nil {
		return ""
	}
	for _, answer := range reply.Answers {
		if ptr, ok := answer.Body.(*dnsmessage.PTRResource); ok {
			return strings.TrimSuffix(ptr.PTR.String(), ".")
		}
	}
	return ""
}

// nbstat sends a NetBIOS adapter-status query (the same thing "nbtstat -A"
// does) and parses the computer name and MAC out of the reply. Windows and
// Samba hosts answer this without any authentication.
func nbstat(ip string, timeout time.Duration) (name string, mac string, ok bool) {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return "", "", false
	}
	defer conn.Close()

	req := []byte{
		0x82, 0x28, // transaction id
		0x00, 0x00, // flags: standard query
		0x00, 0x01, // one question
		0x00, 0x00, // no answers
		0x00, 0x00, // no authority records
		0x00, 0x00, // no additional records
		0x20,       // encoded name length (32)
		0x43, 0x4b, // "CK" - the encoded form of the "*" wildcard name
	}
	for i := 0; i < 30; i++ { // remaining wildcard padding
		req = append(req, 0x41)
	}
	req = append(req,
		0x00,       // end of name
		0x00, 0x21, // type NBSTAT
		0x00, 0x01, // class IN
	)

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", "", false
	}
	if _, err := conn.Write(req); err != nil {
		return "", "", false
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return "", "", false
	}

	// Header (12) + encoded name (34) + type (2) + class (2) + TTL (4) +
	// data length (2) puts the name count at offset 56.
	numNames := int(buf[56])
	if numNames == 0 || n < 57+numNames*18+6 {
		return "", "", false
	}

	for i := 0; i < numNames; i++ {
		off := 57 + i*18
		entry := strings.TrimSpace(string(buf[off : off+15]))
		suffix := buf[off+15]
		flags := binary.BigEndian.Uint16(buf[off+16 : off+18])
		isGroup := flags&0x8000 != 0
		// Suffix 0x00 on a unique name is the workstation name.
		if suffix == 0x00 && !isGroup && entry != "" && name == "" {
			name = entry
		}
	}

	macOff := 57 + numNames*18
	hw := net.HardwareAddr(buf[macOff : macOff+6])
	if hw.String() != "00:00:00:00:00:00" {
		mac = strings.ToUpper(hw.String())
	}
	return name, mac, true
}

var arpLineRE = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})\D+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})`)

var (
	arpMu       sync.Mutex
	arpCached   map[string]string
	arpCachedAt time.Time
)

// arpCacheFor is how long a reading is reused. The kernel's own table changes
// slowly, and every read costs a child process, so repeating it for each
// caller is wasteful - the status endpoint, the history tracker and each open
// browser tab would otherwise each spawn one.
const arpCacheFor = 5 * time.Second

// arpTable reads the OS ARP cache, reusing a recent reading when there is one.
func arpTable() map[string]string {
	arpMu.Lock()
	defer arpMu.Unlock()

	if arpCached != nil && time.Since(arpCachedAt) < arpCacheFor {
		return arpCached
	}
	arpCached = readARPTable()
	arpCachedAt = time.Now()
	return arpCached
}

// readARPTable parses the OS ARP cache. Parsing command output avoids needing
// raw sockets, which would require administrator rights on Windows.
func readARPTable() map[string]string {
	out := map[string]string{}

	commands := [][]string{{"arp", "-a"}}
	if runtime.GOOS == "linux" {
		commands = append(commands, []string{"ip", "neigh"})
	}

	for _, cmd := range commands {
		output, err := hiddenCommand(cmd[0], cmd[1:]...).Output()
		if err != nil {
			continue
		}
		for _, match := range arpLineRE.FindAllStringSubmatch(string(output), -1) {
			ip, raw := match[1], match[2]
			hw, err := net.ParseMAC(strings.ReplaceAll(raw, "-", ":"))
			if err != nil || len(hw) != 6 {
				continue
			}
			if hw.String() == "00:00:00:00:00:00" || strings.HasPrefix(ip, "224.") || strings.HasSuffix(ip, ".255") {
				continue
			}
			if _, exists := out[ip]; !exists {
				out[ip] = strings.ToUpper(hw.String())
			}
		}
		if len(out) > 0 {
			break
		}
	}
	return out
}
