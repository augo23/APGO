package overlaymobile

// mobilelog.go gives the phone what the desktop has had all along: a log file
// you can actually read after the fact.
//
// On iOS the overlay core runs inside the NEPacketTunnelProvider extension and
// its log output goes to stderr, which lands in Apple's unified log. Reading
// that requires plugging the phone into a Mac and running Console.app — which
// is useless for diagnosing a problem that only happens on a network you are
// not on when you are near the Mac. Anything written here goes to a file in
// the SHARED APP GROUP container instead, so the app process can read it and
// hand it to the share sheet.
//
// The path and level come from the app in the tunnel's providerConfiguration
// (see mobileConfig.LogPath / LogLevel in bridge.go).

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Capture levels, matching the app's Settings picker.
const (
	logLevelOff     = 0
	logLevelNormal  = 1
	logLevelVerbose = 2
)

// mobileLogMaxBytes caps ONE file. On rotation the current file becomes
// <name>.1 and a fresh one starts, so the worst case on disk is twice this.
//
// 4 MB is deliberate. The writer streams to disk and never buffers a file, so
// it costs the extension nothing against its ~50 MB RSS ceiling — but the APP
// reads these files to build the export, and 8 MB total stays comfortable
// there too.
const mobileLogMaxBytes = 4 << 20

// normalSkip lists substrings of lines dropped at logLevelNormal.
//
// These are the two highest-frequency lines the core emits on a phone. A peer
// that cannot be punched re-logs the same handshake failure on every retry —
// every 10-20s, per unreachable peer — and the liveness sweep logs every
// teardown. On a capped file they bury the rare lines that actually explain a
// routing decision ([relay-policy], [nat-spray], [nat], [connect]), which is
// the whole reason this file exists. Verbose keeps them.
var normalSkip = []string{
	"no handshake reply",
	"[liveness] session ",
}

// mobileLogWriter appends to a size-capped file, rotating once through a
// single .1 generation.
//
// The log package serializes its own writes, but Stop can rotate or close
// underneath one, so the mutex is not redundant.
type mobileLogWriter struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	n       int64
	verbose bool
}

func newMobileLogWriter(path string, verbose bool) (*mobileLogWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	var n int64
	if st, sterr := f.Stat(); sterr == nil {
		n = st.Size()
	}
	return &mobileLogWriter{path: path, f: f, n: n, verbose: verbose}, nil
}

func (w *mobileLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		// Closed mid-write. Report success: the caller is log.Output, and a
		// failing writer there buys nothing but a broken log line on stderr.
		return len(p), nil
	}
	if !w.verbose && skipNormal(p) {
		return len(p), nil
	}
	if w.n+int64(len(p)) > mobileLogMaxBytes {
		w.rotateLocked()
	}
	n, err := w.f.Write(p)
	w.n += int64(n)
	return n, err
}

// rotateLocked moves the current file aside and starts a fresh one. Caller
// holds w.mu. Any failure leaves logging pointed at whatever still works
// rather than tearing the writer down.
func (w *mobileLogWriter) rotateLocked() {
	if w.f == nil {
		return
	}
	_ = w.f.Close()
	w.f = nil
	old := w.path + ".1"
	_ = os.Remove(old)
	if err := os.Rename(w.path, old); err != nil {
		// Couldn't rotate — truncate in place so the cap still holds.
		f, ferr := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if ferr != nil {
			return
		}
		w.f, w.n = f, 0
		return
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	w.f, w.n = f, 0
}

func (w *mobileLogWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
}

func skipNormal(p []byte) bool {
	s := string(p)
	for _, sub := range normalSkip {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

var (
	mobileLogMu sync.Mutex
	mobileLog   *mobileLogWriter
)

// startMobileLog points the standard logger at a file in the shared container,
// in addition to stderr. Called from Start before anything else can log, so a
// capture session includes startup — which is where the NAT classification and
// the first relay-policy verdicts happen.
//
// level 0 (or an empty path) leaves logging on stderr only, exactly as before.
func startMobileLog(path string, level int) {
	mobileLogMu.Lock()
	defer mobileLogMu.Unlock()

	if mobileLog != nil {
		mobileLog.Close()
		mobileLog = nil
	}
	log.SetOutput(os.Stderr)

	path = strings.TrimSpace(path)
	if level <= logLevelOff || path == "" {
		return
	}
	w, err := newMobileLogWriter(path, level >= logLevelVerbose)
	if err != nil {
		log.Printf("[log] cannot open %s: %v — logging to stderr only", path, err)
		return
	}
	mobileLog = w
	log.SetOutput(io.MultiWriter(os.Stderr, w))

	mode := "normal"
	if level >= logLevelVerbose {
		mode = "verbose"
	}
	// A session marker makes a shared log readable when it spans several
	// connects — otherwise the reader cannot tell a reconnect from a gap.
	log.Printf("[log] ===== capture started (%s) %s =====",
		mode, time.Now().Format(time.RFC3339))
}

// stopMobileLog returns logging to stderr and closes the file. Called from
// Stop so the app never shares a file with a half-written tail.
func stopMobileLog() {
	mobileLogMu.Lock()
	defer mobileLogMu.Unlock()
	if mobileLog == nil {
		return
	}
	log.Printf("[log] ===== capture stopped %s =====", time.Now().Format(time.RFC3339))
	log.SetOutput(os.Stderr)
	mobileLog.Close()
	mobileLog = nil
}
