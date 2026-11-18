package main

// logout.go keeps the client alive when whatever holds its stdout/stderr goes
// away.
//
// THE FAILURE (zx3t, 2026-11-17)
//
// Under podman, a container's stdout/stderr are pipes held by conmon. When
// conmon died ~2 minutes after boot, the very next log line was written to a
// pipe with no reader. A Go program that has not asked for SIGPIPE is KILLED
// by it when the broken pipe is fd 1 or 2 — silently, with no panic and no
// exit code anyone recorded. Podman never saw the exit (conmon was the thing
// that would have reported it), so restart=always never fired and
// `podman ps` kept showing "Up" for ten hours while the node was gone from
// the mesh. The same applies to any supervisor that dies before its child:
// a shell pipeline, an ssh session, a parent app.
//
// THE REPAIR
//
//  1. ignoreSIGPIPE (per-OS file): a write to a broken stdout/stderr now
//     returns EPIPE instead of terminating the process.
//  2. resilientLogWriter: the LOG_FILE copy is written FIRST and console
//     errors are swallowed. io.MultiWriter stops at the first failing writer,
//     so with stderr gone it would have silently stopped the file log too —
//     the one log an operator could still read.

import (
	"io"
	"os"
	"sync/atomic"
)

type resilientLogWriter struct {
	file        io.Writer // may be nil
	console     io.Writer
	consoleDead atomic.Bool
}

func (w *resilientLogWriter) Write(p []byte) (int, error) {
	if w.file != nil {
		_, _ = w.file.Write(p)
	}
	if !w.consoleDead.Load() {
		if _, err := w.console.Write(p); err != nil {
			// The reader is gone (EPIPE) or the descriptor is closed. Stop
			// trying: retrying every line just repeats the failing syscall.
			w.consoleDead.Store(true)
		}
	}
	return len(p), nil
}

// newLogWriter returns the writer for the standard logger: stderr, plus the
// LOG_FILE copy when one is open.
func newLogWriter(file io.Writer) io.Writer {
	return &resilientLogWriter{file: file, console: os.Stderr}
}
