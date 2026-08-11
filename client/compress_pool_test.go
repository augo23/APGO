package main

import (
	"bytes"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
)

// Reusing one pooled buffer across packets must not let a previous packet's
// bytes leak into the next. This is the failure mode pooling invites, and it
// would show up in production as corrupt traffic, not as a crash.
func TestCompressPooledBufferNoBleed(t *testing.T) {
	compressSkip.Store(0)
	scratch := make([]byte, maxFrameSize)
	payloads := [][]byte{
		[]byte(strings.Repeat("AAAA-compressible-", 200)),
		[]byte(strings.Repeat("B", 4000)),
		[]byte(strings.Repeat("short-", 20)),
		[]byte(strings.Repeat("CCCCCCCCCCCCCCCC", 500)),
	}
	for i, want := range payloads {
		compressSkip.Store(0) // keep the gate open for every payload
		framed, err := compressAndFrameTo(scratch[:0], want)
		if err != nil {
			t.Fatalf("payload %d: compress failed: %v", i, err)
		}
		got, err := decompressAndUnframe(framed)
		if err != nil {
			t.Fatalf("payload %d: decompress failed: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("payload %d: round trip corrupted %d bytes -> %d bytes", i, len(want), len(got))
		}
	}
}

// sendPacket compresses concurrently (TUN reader + keepalive ticker), so the
// pool must hand out exclusive buffers.
func TestCompressPoolConcurrentRoundTrip(t *testing.T) {
	compressSkip.Store(0)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			buf := make([]byte, maxFrameSize)
			want := []byte(strings.Repeat(string(rune('a'+g))+"payload", 300))
			for i := 0; i < 200; i++ {
				compressSkip.Store(0)
				framed, err := compressAndFrameTo(buf[:0], want)
				if err != nil {
					errs <- "compress failed"
					return
				}
				got, err := decompressAndUnframe(framed)
				if err != nil || !bytes.Equal(got, want) {
					errs <- "concurrent round trip corrupted the payload"
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// A VPN mostly carries already-compressed bytes (TLS, video, a speed test).
// Paying a full LZ4 pass per packet to then discard the result is wasted CPU
// and battery on a phone, so the compressor must give up on such a stream.
func TestCompressBacksOffOnIncompressibleTraffic(t *testing.T) {
	compressSkip.Store(0)
	random := make([]byte, 1280)
	rand.Read(random)

	attempted := 0
	for i := 0; i < 2000; i++ {
		if compressWorthTrying() {
			attempted++
		}
		if _, err := compressAndFrameTo(nil, random); err == nil {
			t.Fatal("random data compressed?")
		}
	}
	if attempted > 100 {
		t.Errorf("compressor still attempted %d of 2000 incompressible packets; backoff is not engaging", attempted)
	}
	if attempted == 0 {
		t.Error("compressor never sampled at all; a stream that becomes compressible would never be noticed")
	}

	// ...and it must RECOVER: one success re-opens the gate fully.
	compressSkip.Store(0)
	good := []byte(strings.Repeat("compress-me-", 200))
	if _, err := compressAndFrameTo(nil, good); err != nil {
		t.Fatalf("compressible payload rejected: %v", err)
	}
	if !compressWorthTrying() {
		t.Error("gate stayed shut after a successful compression")
	}
}
