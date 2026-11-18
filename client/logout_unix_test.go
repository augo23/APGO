//go:build !windows

package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBrokenStderrDoesNotKillClient re-runs this test binary with stderr
// connected to a pipe whose reader is already closed — what a podman
// container sees after conmon dies. The child must keep running and keep
// writing its LOG_FILE copy. The control run (no ignoreSIGPIPE) shows the test
// really reproduces the kill.
func TestBrokenStderrDoesNotKillClient(t *testing.T) {
	if mode := os.Getenv("APGO_SIGPIPE_CHILD"); mode != "" {
		if mode == "fixed" {
			ignoreSIGPIPE()
		}
		f, err := os.OpenFile(os.Getenv("APGO_SIGPIPE_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			os.Exit(3)
		}
		log.SetOutput(newLogWriter(f))
		for i := 0; i < 50; i++ {
			log.Printf("line %d", i)
		}
		if mode != "fixed" {
			// Unprotected: write straight to the broken stderr, like the old
			// io.MultiWriter(os.Stderr, f) did.
			for i := 0; i < 50; i++ {
				os.Stderr.WriteString("x\n")
			}
		}
		log.Printf("survived")
		os.Exit(0)
	}

	run := func(mode string) (string, error) {
		logPath := filepath.Join(t.TempDir(), "client.log")
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		r.Close() // no reader: every write to the child's stderr is EPIPE
		cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenStderrDoesNotKillClient$")
		cmd.Env = append(os.Environ(), "APGO_SIGPIPE_CHILD="+mode, "APGO_SIGPIPE_LOG="+logPath)
		cmd.Stderr = w
		err = cmd.Run()
		w.Close()
		b, _ := os.ReadFile(logPath)
		return string(b), err
	}

	out, err := run("fixed")
	if err != nil {
		t.Fatalf("client died with a broken stderr: %v", err)
	}
	if !strings.Contains(out, "line 49") || !strings.Contains(out, "survived") {
		t.Fatalf("LOG_FILE copy stopped when stderr broke:\n%s", out)
	}

	if _, err := run("control"); err == nil {
		t.Log("control run survived too; SIGPIPE may already be ignored by the test harness")
	}
}

func TestResilientLogWriterKeepsFileWhenConsoleFails(t *testing.T) {
	var file bytes.Buffer
	w := &resilientLogWriter{file: &file, console: failingWriter{}}
	for i := 0; i < 3; i++ {
		if n, err := w.Write([]byte("abc\n")); err != nil || n != 4 {
			t.Fatalf("Write = %d, %v; want 4, nil", n, err)
		}
	}
	if file.String() != "abc\nabc\nabc\n" {
		t.Fatalf("file got %q", file.String())
	}
	if !w.consoleDead.Load() {
		t.Fatal("console should be marked dead after a failed write")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }
