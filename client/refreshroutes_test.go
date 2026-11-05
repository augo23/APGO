package main

import (
	"strings"
	"testing"
	"time"
)

func TestRelayFirstClearsWhenPairingBecomesPunchable(t *testing.T) {
	relayPolMu.Lock()
	relayPol = map[string]*relayPeerPolicy{}
	relayPolMu.Unlock()
	natMu.Lock()
	old := natInfo
	natInfo = natMapping{ip: "1.2.3.4", samples: 2, symmetric: true}
	natMu.Unlock()
	defer func() { natMu.Lock(); natInfo = old; natMu.Unlock() }()

	ip := "10.22.22.99"
	if noteConnectCandidates(ip, "nat="+natStable) {
		t.Fatal("sym/stable should go relay-first")
	}
	natMu.Lock()
	natInfo = natMapping{ip: "1.2.3.4", samples: 2, symmetric: false}
	natMu.Unlock()
	if !noteConnectCandidates(ip, "nat="+natStable) {
		t.Fatal("relay-first verdict must clear once the pairing is punchable")
	}
}

func TestRelayFirstClearsOnEstablished(t *testing.T) {
	relayPolMu.Lock()
	relayPol = map[string]*relayPeerPolicy{"10.22.22.98": {relayFirst: true, firstPunch: time.Now()}}
	relayPolMu.Unlock()
	relayPreferred("10.22.22.98", true)
	relayPolMu.Lock()
	defer relayPolMu.Unlock()
	if relayPol["10.22.22.98"].relayFirst {
		t.Fatal("an established direct session must clear relay-first")
	}
}

func TestRefreshRoutesPrimesAndIgnoresStale(t *testing.T) {
	refreshMu.Lock()
	refreshPrimed, refreshApplied = false, 0
	refreshMu.Unlock()
	now := time.Now().Unix()
	v := now
	maybeRefreshRoutes(SignedNodeConfig{RefreshRoutes: &v}) // first look: prime only
	refreshMu.Lock()
	if refreshApplied != now {
		t.Fatalf("prime should record %d, got %d", now, refreshApplied)
	}
	refreshMu.Unlock()

	relayPolMu.Lock()
	relayPol = map[string]*relayPeerPolicy{"x": {}}
	relayPolMu.Unlock()
	same := now
	maybeRefreshRoutes(SignedNodeConfig{RefreshRoutes: &same}) // repeat: no-op
	relayPolMu.Lock()
	if len(relayPol) != 1 {
		t.Fatal("a value already acted on must not refresh again")
	}
	relayPolMu.Unlock()

	old := now - 3600
	refreshMu.Lock()
	refreshApplied = old - 1
	refreshMu.Unlock()
	maybeRefreshRoutes(SignedNodeConfig{RefreshRoutes: &old}) // newer but an hour old
	relayPolMu.Lock()
	if len(relayPol) != 1 {
		t.Fatal("a request older than refreshMaxAge must be ignored")
	}
	relayPolMu.Unlock()
}

func TestCanonicalV3OnlyWhenV3FieldsPresent(t *testing.T) {
	tr := true
	base := SignedNodeConfig{PubKey: "k", DHT: &tr, Epoch: 5, Ts: 6}
	if !strings.HasPrefix(canonicalNodeConfig(base), "OVLYNODECFG1|") {
		t.Fatal("record without v2/v3 fields must stay v1")
	}
	base.IPv6 = &tr
	s := canonicalNodeConfig(base)
	if !strings.HasPrefix(s, "OVLYNODECFG3|") || !strings.HasSuffix(s, "|true|-|5|6") {
		t.Fatalf("unexpected v3 string: %s", s)
	}
}
