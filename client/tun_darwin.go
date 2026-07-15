//go:build darwin

package main

// macOS data-plane. We open a utun device directly via the AF_SYSTEM control
// socket (the same approach wireguard-go uses) instead of going through a TUN
// library, so there is no ambiguity about the 4-byte protocol-family header
// that every utun read/write carries: we strip it on read and prepend it on
// write, and nothing else touches it. Requires root (utun + ifconfig + route).

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

var globalTunIF io.ReadWriteCloser

// tunName is the utun interface name, remembered so an admin-assigned overlay IP
// can be applied live in-process (see reAddressTUN).
var tunName string

func createAndConfigureTUN(cfg *ClientConfig) error {
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1280
	}

	name, rwc, err := openUtun()
	if err != nil {
		return fmt.Errorf("open utun (are you running as root?): %w", err)
	}
	tunName = name
	globalTunIF = rwc
	log.Printf("TUN %s created (macOS utun)", name)

	if cfg.Tun.AddressCIDR == "" {
		return nil
	}
	ip, ipnet, err := net.ParseCIDR(cfg.Tun.AddressCIDR)
	if err != nil {
		return fmt.Errorf("parse addr %q: %w", cfg.Tun.AddressCIDR, err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", cfg.Tun.AddressCIDR)
	}
	ones, _ := ipnet.Mask.Size()

	// Address (with prefix) + point-to-point self, interface up, then MTU.
	if out, err := runCmd("ifconfig", name, "inet",
		fmt.Sprintf("%s/%d", ip4.String(), ones), ip4.String(), "up"); err != nil {
		return fmt.Errorf("ifconfig %s: %v (%s)", name, err, out)
	}
	if out, err := runCmd("ifconfig", name, "mtu", fmt.Sprintf("%d", cfg.Tun.MTU)); err != nil {
		log.Printf("warning: set mtu on %s: %v (%s)", name, err, out)
	}

	netCIDR := ipnet.String() // e.g. 10.28.55.0/24
	if out, err := runCmd("route", "-n", "add", "-inet", "-net", netCIDR, "-interface", name); err != nil {
		if !strings.Contains(out, "File exists") {
			return fmt.Errorf("route add %s: %v (%s)", netCIDR, err, out)
		}
	}
	log.Printf("Assigned %s to %s and routed %s via it", cfg.Tun.AddressCIDR, name, netCIDR)
	return nil
}

// openUtun creates a utun interface and returns its name and an io.ReadWriteCloser
// that speaks raw IP packets (the 4-byte utun header is handled internally).
func openUtun() (string, io.ReadWriteCloser, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return "", nil, fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return "", nil, fmt.Errorf("ioctl(CTLIOCGINFO): %w", err)
	}

	// Ask the kernel for the first free utun unit.
	var connErr error
	for unit := 0; unit < 256; unit++ {
		connErr = unix.Connect(fd, &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: uint32(unit) + 1})
		if connErr == nil {
			break
		}
	}
	if connErr != nil {
		unix.Close(fd)
		return "", nil, fmt.Errorf("connect utun: %w", connErr)
	}

	name, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		unix.Close(fd)
		return "", nil, fmt.Errorf("get utun name: %w", err)
	}

	return name, &utunRW{inner: os.NewFile(uintptr(fd), name)}, nil
}

// utunRW adapts a raw utun fd to IP packets by handling the 4-byte
// address-family header (AF_INET / AF_INET6, big-endian) the kernel adds.
type utunRW struct {
	inner *os.File
	rbuf  []byte
}

func (u *utunRW) Read(p []byte) (int, error) {
	if u.rbuf == nil {
		u.rbuf = make([]byte, 65540)
	}
	n, err := u.inner.Read(u.rbuf)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return copy(p, u.rbuf[4:n]), nil
}

func (u *utunRW) Write(p []byte) (int, error) {
	af := uint32(unix.AF_INET)
	if len(p) > 0 && p[0]>>4 == 6 {
		af = uint32(unix.AF_INET6)
	}
	buf := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(buf[:4], af)
	copy(buf[4:], p)
	n, err := u.inner.Write(buf)
	if err != nil {
		return 0, err
	}
	if n >= 4 {
		return n - 4, nil
	}
	return 0, nil
}

func (u *utunRW) Close() error { return u.inner.Close() }

// reAddressTUN changes the utun interface's IPv4 address live (no restart). The
// old point-to-point alias is removed first so a stale address doesn't linger.
func reAddressTUN(oldIP, newCIDR string) error {
	ip, ipnet, err := net.ParseCIDR(newCIDR)
	if err != nil {
		return err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("overlay address must be IPv4, got %q", newCIDR)
	}
	ones, _ := ipnet.Mask.Size()
	if oldIP != "" {
		_, _ = runCmd("ifconfig", tunName, "inet", oldIP, "delete")
	}
	if out, err := runCmd("ifconfig", tunName, "inet",
		fmt.Sprintf("%s/%d", ip4.String(), ones), ip4.String(), "up"); err != nil {
		return fmt.Errorf("ifconfig %s: %v (%s)", tunName, err, out)
	}
	return nil
}

func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
