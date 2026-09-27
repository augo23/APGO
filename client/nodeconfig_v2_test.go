package main

import (
	"strings"
	"testing"
)

// Existing (v1) records must keep their exact signed string, or every node
// config an admin has already signed stops verifying after the upgrade.
func TestNodeConfigV1StringUnchanged(t *testing.T) {
	yes := true
	up := int64(1000)
	c := SignedNodeConfig{PubKey: "k", DHT: &yes, ExitUp: &up, Epoch: 5, Ts: 6}
	// Byte-for-byte what earlier builds produced — including the formatting
	// quirk (see canonicalNodeConfig) that existing signatures cover.
	want := "OVLYNODECFG1|k|true|-|-|-|-|-|-|-|-|-|-|-|-|-|-|1000|-|%!d(string=-)|5%!(EXTRA int64=6)"
	if got := canonicalNodeConfig(c); got != want {
		t.Fatalf("v1 canonical string changed:\n got %s\nwant %s", got, want)
	}
}

func TestNodeConfigV2Binding(t *testing.T) {
	yes := true
	n := int64(8)
	c := SignedNodeConfig{PubKey: "k", PublicExit: &yes, PublicExitMaxClients: &n, Epoch: 5, Ts: 6}
	got := canonicalNodeConfig(c)
	if !strings.HasPrefix(got, "OVLYNODECFG2|") || got != "OVLYNODECFG2|k|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|true|-|-|-|8|5|6" {
		t.Fatalf("v2 canonical string: %s", got)
	}
	// Stripping the v2 fields yields a different (v1) string: a v2 signature
	// can never be replayed as a v1 record, nor the reverse.
	stripped := c
	stripped.PublicExit, stripped.PublicExitMaxClients = nil, nil
	if canonicalNodeConfig(stripped) == got {
		t.Fatal("v2 fields are not covered by the signature")
	}
	off := false
	flipped := c
	flipped.PublicExit = &off
	if canonicalNodeConfig(flipped) == got {
		t.Fatal("public_exit value not covered by the signature")
	}
}
