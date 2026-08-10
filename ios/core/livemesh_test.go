package overlaymobile

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTun struct {
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{in: make(chan []byte, 64), closed: make(chan struct{})}
}
func (f *fakeTun) Read(p []byte) (int, error) {
	select {
	case b := <-f.in:
		return copy(p, b), nil
	case <-f.closed:
		return 0, io.EOF
	}
}
func (f *fakeTun) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeTun) Close() error                { f.once.Do(func() { close(f.closed) }); return nil }

// The mobile core keeps ONE node's state in package-level globals (correct for
// a phone: one tunnel per process). So a two-node test must use two PROCESSES.
// The test binary re-executes itself in "node mode" via APGO_NODE_PORT.
func TestMain(m *testing.M) {
	if os.Getenv("APGO_NODE_PORT") != "" {
		runNodeMode()
		return
	}
	os.Exit(m.Run())
}

func runNodeMode() {
	port, _ := strconv.Atoi(os.Getenv("APGO_NODE_PORT"))
	peer := os.Getenv("APGO_PEER")
	cfg := &ClientConfig{
		NetworkName:    "audit-net",
		PSK:            "base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		OverlayCIDR:    "10.99.0.0/24",
		UDPListenPort:  port,
		Trackers:       []string{},
		STUNServers:    []string{},
		StaticPeers:    []string{peer},
		TrackerMode:    "passive",
		NodePrivateKey: filepath.Join(os.Getenv("APGO_DIR"), "node-"+strconv.Itoa(port)+".key"),
	}
	cfg.Tun.AddressCIDR = os.Getenv("APGO_IP") + "/24"
	tun := newFakeTun()
	stop := make(chan struct{})
	go func() { _ = run(tun, cfg, stop) }()
	for i := 0; i < 300; i++ {
		if GlobalSessions != nil && len(GlobalSessions.EstablishedAddrs()) > 0 {
			os.Stdout.WriteString("SESSION_OK\n")
			os.Stdout.Sync()
			time.Sleep(500 * time.Millisecond)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	os.Stdout.WriteString("SESSION_FAIL\n")
	os.Stdout.Sync()
}

func TestTwoNodesFormDirectSession(t *testing.T) {
	dir := t.TempDir()
	start := func(port, peerPort int, ip string) (*exec.Cmd, *bufio.Scanner) {
		cmd := exec.Command(os.Args[0], "-test.run=TestTwoNodesFormDirectSession")
		cmd.Env = append(os.Environ(),
			"APGO_NODE_PORT="+strconv.Itoa(port),
			"APGO_PEER=127.0.0.1:"+strconv.Itoa(peerPort),
			"APGO_IP="+ip, "APGO_DIR="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil { t.Fatal(err) }
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil { t.Fatal(err) }
		return cmd, bufio.NewScanner(out)
	}
	a, sa := start(45011, 45012, "10.99.0.11")
	b, sb := start(45012, 45011, "10.99.0.12")
	defer func() { _ = a.Process.Kill(); _ = b.Process.Kill() }()

	res := make(chan string, 2)
	watch := func(s *bufio.Scanner) {
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "SESSION_OK" || line == "SESSION_FAIL" { res <- line; return }
		}
		res <- "NO_OUTPUT"
	}
	go watch(sa)
	go watch(sb)

	ok := 0
	for i := 0; i < 2; i++ {
		select {
		case r := <-res:
			t.Logf("node %d reported %s", i+1, r)
			if r == "SESSION_OK" { ok++ }
		case <-time.After(45 * time.Second):
			t.Fatal("timed out waiting for a node to report")
		}
	}
	if ok != 2 {
		t.Fatalf("only %d/2 nodes established a session — two static peers on loopback must connect", ok)
	}
}
