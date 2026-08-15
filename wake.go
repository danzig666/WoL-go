package main

import (
	"fmt"
	"log"
	"net"
)

// buildMagicPacket returns the classic Wake-on-LAN payload: six 0xFF bytes
// followed by the target MAC repeated sixteen times.
func buildMagicPacket(target net.HardwareAddr) []byte {
	packet := make([]byte, 0, 6+16*len(target))
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, target...)
	}
	return packet
}

// wakeTarget is one place to send a packet: a destination address, and the
// local address to send it from.
type wakeTarget struct {
	iface string
	local net.IP // source address, which selects the outgoing interface
	dest  net.IP
}

func (t wakeTarget) String() string {
	if t.iface == "" {
		return t.dest.String()
	}
	return fmt.Sprintf("%s via %s", t.dest, t.iface)
}

// wakeTargets lists the directed broadcast of every up, non-loopback IPv4
// interface, each paired with that interface's own address, plus the global
// broadcast as a catch-all.
//
// Binding the source address matters: sending to 255.255.255.255 lets the
// routing table pick one interface, and on a machine with a VPN or with
// Hyper-V/VMware adapters that is regularly the wrong one. Sourcing each
// packet from a specific interface guarantees it leaves on that interface.
func wakeTargets() []wakeTarget {
	var targets []wakeTarget
	seen := map[string]bool{}

	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Could not list network interfaces: %v", err)
		return []wakeTarget{{dest: net.IPv4bcast}}
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			bcast := directedBroadcast(ipnet)
			if bcast == nil {
				continue
			}
			key := ipnet.IP.String() + "->" + bcast.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			targets = append(targets, wakeTarget{
				iface: iface.Name,
				local: ipnet.IP.To4(),
				dest:  bcast,
			})
		}
	}

	// Unbound global broadcast, for anything the loop above missed.
	targets = append(targets, wakeTarget{dest: net.IPv4bcast})
	return targets
}

// directedBroadcast computes the all-ones host address for an IPv4 network.
func directedBroadcast(ipnet *net.IPNet) net.IP {
	ip := ipnet.IP.To4()
	mask := net.IP(ipnet.Mask).To4()
	if ip == nil || mask == nil {
		return nil
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}

// broadcastAddresses reports just the destination addresses, for diagnostics.
func broadcastAddresses() []string {
	var out []string
	for _, t := range wakeTargets() {
		out = append(out, t.dest.String())
	}
	return out
}

// sendMagicPacket wakes the given MAC. An empty broadcast address means "every
// interface"; port 0 means the standard WoL ports. Ports 7 and 9 are both used
// because network cards differ in which one they listen on. unicastIP, when
// known, gets a copy too: it costs nothing and helps in the cases where a
// router holds a static ARP entry for a sleeping machine.
func sendMagicPacket(macAddr, broadcast string, port int, unicastIP string) error {
	target, err := net.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}
	if len(target) != 6 {
		return fmt.Errorf("invalid MAC address: %s", macAddr)
	}
	packet := buildMagicPacket(target)

	var targets []wakeTarget
	if broadcast != "" {
		ip := net.ParseIP(broadcast)
		if ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid broadcast address: %s", broadcast)
		}
		targets = []wakeTarget{{dest: ip.To4()}}
	} else {
		targets = wakeTargets()
	}

	ports := []int{9, 7}
	if port != 0 && port != 9 && port != 7 {
		ports = append([]int{port}, ports...)
	}

	var sent int
	var lastErr error
	for _, t := range targets {
		for _, p := range ports {
			if err := sendFrom(t.local, t.dest, p, packet); err != nil {
				lastErr = err
				log.Printf("  %s port %d: %v", t, p, err)
				continue
			}
			sent++
		}
	}

	// A sleeping machine sometimes still has a neighbour-table entry, in which
	// case a unicast packet reaches it directly. Failure here is expected and
	// not reported.
	if unicastIP != "" {
		if ip := net.ParseIP(unicastIP); ip != nil && ip.To4() != nil {
			for _, p := range ports {
				if err := sendFrom(nil, ip.To4(), p, packet); err == nil {
					sent++
				}
			}
		}
	}

	if sent == 0 {
		if lastErr != nil {
			return fmt.Errorf("could not send magic packet: %w", lastErr)
		}
		return fmt.Errorf("no usable network interface found")
	}
	log.Printf("Sent %d magic packets for %s across %d destination(s)", sent, macAddr, len(targets))
	return nil
}

// sendFrom sends one packet, optionally bound to a specific local address.
func sendFrom(local, dest net.IP, port int, packet []byte) error {
	var laddr *net.UDPAddr
	if local != nil {
		laddr = &net.UDPAddr{IP: local, Port: 0}
	}

	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Required by the socket API for any broadcast destination.
	if dest.Equal(net.IPv4bcast) || isDirectedBroadcast(dest) {
		if err := enableBroadcast(conn); err != nil {
			return fmt.Errorf("could not enable broadcast: %w", err)
		}
	}

	_, err = conn.WriteToUDP(packet, &net.UDPAddr{IP: dest, Port: port})
	return err
}

// isDirectedBroadcast reports whether dest is the broadcast address of one of
// this machine's own networks.
func isDirectedBroadcast(dest net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		if b := directedBroadcast(ipnet); b != nil && b.Equal(dest) {
			return true
		}
	}
	return false
}
