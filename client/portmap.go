package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// mappedEndpoint holds the external ip:port granted by the router (if any), so
// the announce path can advertise it even when STUN is unavailable.
var (
	mappedEndpointMu sync.RWMutex
	mappedEndpoint   string
)

func setMappedEndpoint(ep string) {
	mappedEndpointMu.Lock()
	mappedEndpoint = ep
	mappedEndpointMu.Unlock()
}

// MappedEndpoint returns the router-mapped external ip:port, or "".
func getMappedEndpoint() string {
	mappedEndpointMu.RLock()
	defer mappedEndpointMu.RUnlock()
	return mappedEndpoint
}

// portmap.go — serverless reachability. A home node asks its own router to
// open an inbound UDP pinhole for our listen port using NAT-PMP (RFC 6886),
// which PCP-capable routers also accept for backward compatibility. This makes
// the node dialable from the outside with NO port-forward, NO static IP, and
// NO VPS — the dynamic WAN IP is still discovered via STUN and announced on the
// tracker; the mapping just keeps the pinhole open so peers can actually reach
// it. Roaming/CGNAT peers then dial this node outbound (which always works) and
// the relay path heals the rest of the mesh.
//
// This is best-effort: if the router speaks neither NAT-PMP nor PCP, or blocks
// port 5351, mapping simply fails and we fall back to hole punching + relay.

const natpmpPort = 5351

// defaultGatewayIP returns the LAN default-gateway address, or nil.
func defaultGatewayIP() net.IP {
	// Linux: parse /proc/net/route for the 0.0.0.0 default route.
	if f, err := os.Open("/proc/net/route"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			if fields[1] != "00000000" { // not the default route
				continue
			}
			// Gateway is little-endian hex (e.g. 0102A8C0 -> 192.168.2.1).
			b, err := hexToBytesLE(fields[2])
			if err == nil && len(b) == 4 {
				return net.IPv4(b[0], b[1], b[2], b[3])
			}
		}
	}
	// Fallback (macOS/Windows/containers without /proc): assume the gateway is
	// .1 of our primary interface's subnet. Correct on the overwhelming
	// majority of home LANs.
	if ip := primaryOutboundIP(); ip != nil {
		ip4 := ip.To4()
		if ip4 != nil {
			return net.IPv4(ip4[0], ip4[1], ip4[2], 1)
		}
	}
	return nil
}

// hexToBytesLE decodes a little-endian hex word like "0102A8C0" into bytes in
// natural order (192,168,2,1).
func hexToBytesLE(s string) ([]byte, error) {
	if len(s) != 8 {
		return nil, errors.New("bad route hex")
	}
	out := make([]byte, 4)
	for i := 0; i < 4; i++ {
		var v int
		for _, c := range s[i*2 : i*2+2] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= int(c - '0')
			case c >= 'a' && c <= 'f':
				v |= int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				v |= int(c-'A') + 10
			default:
				return nil, errors.New("bad hex digit")
			}
		}
		out[3-i] = byte(v) // little-endian: first hex byte is the low octet
	}
	return out, nil
}

// primaryOutboundIP finds the local IP the kernel would use to reach the
// internet (no packets are actually sent — UDP connect just picks a route).
func primaryOutboundIP() net.IP {
	c, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP
	}
	return nil
}

// natpmpRequestExternal asks the gateway for its public IP (NAT-PMP op 0).
func natpmpRequestExternal(gw net.IP) (net.IP, error) {
	resp, err := natpmpExchange(gw, []byte{0, 0}) // version 0, op 0
	if err != nil {
		return nil, err
	}
	// Response: ver(1) op(1) result(2) epoch(4) extIP(4) = 12 bytes.
	if len(resp) < 12 || resp[1] != 128 {
		return nil, errors.New("natpmp: bad external-address reply")
	}
	if rc := binary.BigEndian.Uint16(resp[2:4]); rc != 0 {
		return nil, errors.New("natpmp: external-address result code nonzero")
	}
	return net.IPv4(resp[8], resp[9], resp[10], resp[11]), nil
}

// natpmpMap requests a UDP mapping internalPort->same external port for
// lifetime seconds. Returns the granted external port.
func natpmpMap(gw net.IP, internalPort int, lifetime uint32) (int, error) {
	req := make([]byte, 12)
	req[0] = 0 // version
	req[1] = 1 // op 1 = map UDP (op 2 would be TCP)
	// req[2:4] reserved = 0
	binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(req[6:8], uint16(internalPort)) // suggested ext port
	binary.BigEndian.PutUint32(req[8:12], lifetime)
	resp, err := natpmpExchange(gw, req)
	if err != nil {
		return 0, err
	}
	// Response: ver(1) op(1) result(2) epoch(4) intPort(2) extPort(2) life(4).
	if len(resp) < 16 || resp[1] != 129 {
		return 0, errors.New("natpmp: bad map reply")
	}
	if rc := binary.BigEndian.Uint16(resp[2:4]); rc != 0 {
		return 0, errors.New("natpmp: map result code nonzero")
	}
	return int(binary.BigEndian.Uint16(resp[14:16])), nil
}

// natpmpExchange sends one request to the gateway's NAT-PMP port and returns
// the reply, retrying briefly per the RFC's exponential backoff.
func natpmpExchange(gw net.IP, req []byte) ([]byte, error) {
	raddr := &net.UDPAddr{IP: gw, Port: natpmpPort}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	buf := make([]byte, 32)
	timeout := 250 * time.Millisecond
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			return buf[:n], nil
		}
		timeout *= 2
	}
	return nil, errors.New("natpmp: no reply from gateway")
}

// startPortMapping keeps an inbound UDP pinhole open for our listen port for as
// long as the process runs, refreshing the lease well before it expires. It is
// safe to run on every node: on a node whose router has no NAT-PMP/PCP it just
// logs one failure and stops. The mapped external endpoint is reported through
// mappedEndpoint for the announce path to prefer when STUN is unavailable.
func startPortMapping(internalPort int) {
	const lifetime = 3600 // seconds
	gw := defaultGatewayIP()
	if gw == nil {
		log.Printf("[portmap] no default gateway found; relying on STUN + relay")
		return
	}
	log.Printf("[portmap] gateway %s — requesting NAT-PMP/PCP mapping for udp/%d", gw, internalPort)
	first := true
	for {
		extPort, err := natpmpMap(gw, internalPort, lifetime)
		if err != nil {
			if first {
				log.Printf("[portmap] mapping failed (%v) — router may not support NAT-PMP/PCP; falling back to hole punching + relay", err)
				return
			}
			// A previously-working mapping lapsed (router reboot). Retry soon.
			time.Sleep(30 * time.Second)
			continue
		}
		if extIP, e := natpmpRequestExternal(gw); e == nil {
			setMappedEndpoint(net.JoinHostPort(extIP.String(), strconv.Itoa(extPort)))
			if first {
				log.Printf("[portmap] SUCCESS — this node is now reachable at %s:%d (no port-forward, no static IP). Other nodes can dial it directly.", extIP, extPort)
			}
		} else if first {
			log.Printf("[portmap] mapping created (ext port %d) but could not read external IP: %v", extPort, e)
		}
		first = false
		// Refresh at half the lease so we never lapse.
		time.Sleep(time.Duration(lifetime/2) * time.Second)
	}
}
