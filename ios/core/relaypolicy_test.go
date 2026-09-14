package overlaymobile

import (
	"strings"
	"testing"
	"time"
)

// resetRelayPolicy clears per-peer state between cases; the map is package
// global because the production callers are spread across the punch path.
func resetRelayPolicy() {
	relayPolMu.Lock()
	relayPol = map[string]*relayPeerPolicy{}
	relayPolMu.Unlock()
	natMu.Lock()
	natInfo = natMapping{}
	natMu.Unlock()
}

// setOurNAT forces this node's classification, the way probeNAT would.
func setOurNAT(ip string, symmetric bool, samples int) {
	natMu.Lock()
	natInfo = natMapping{ip: ip, port: 6969, symmetric: symmetric, samples: samples}
	natMu.Unlock()
}

// THE REGRESSION THIS FILE EXISTS FOR: a phone on symmetric carrier NAT and a
// desktop on a port-restricted home router punched each other for four hours
// (thirteen distinct external ports) before one attempt coincidentally
// landed. The pairing is unpunchable by construction and must be recognised
// from the candidate exchange, not discovered by exhaustion.
func TestSymmetricAgainstRestrictedIsNotPunchable(t *testing.T) {
	cases := []struct {
		mine, theirs string
		want         bool
	}{
		{natSymmetric, natStable, false}, // the field failure
		{natStable, natSymmetric, false}, // same pairing, other direction
		{natSymmetric, natSymmetric, false},
		{natStable, natStable, true},
		// Unknown on either side must stay punchable: NAT classification
		// needs two STUN servers to answer and frequently only one does, so a
		// classification-only rule would go dark exactly when the network is
		// worst. The escalation timer is the backstop there.
		{natUnknown, natSymmetric, true},
		{natSymmetric, natUnknown, true},
		{natUnknown, natUnknown, true},
	}
	for _, c := range cases {
		if got := directPunchViable(c.mine, c.theirs); got != c.want {
			t.Errorf("directPunchViable(%s,%s) = %v, want %v", c.mine, c.theirs, got, c.want)
		}
	}
}

// The NAT token has to survive the candidate list of an OLD peer untouched.
// Old builds run every candidate through isPunchableAddr, so the token must
// be rejected there — otherwise it is dialed as an endpoint.
func TestNATTokenIsIgnoredByOlderPeers(t *testing.T) {
	for _, tok := range []string{natTokenPfx + natSymmetric, natTokenPfx + natStable} {
		if isPunchableAddr(tok) {
			t.Fatalf("%q must not be punchable: an old peer would dial it as an endpoint", tok)
		}
	}
}

func TestParseNATClass(t *testing.T) {
	cands := "10.0.0.4:6969,1.2.3.4:6969," + natTokenPfx + natSymmetric
	if got := parseNATClass(cands); got != natSymmetric {
		t.Fatalf("parseNATClass = %q, want %q", got, natSymmetric)
	}
	// A list from a peer that predates the token reports unknown, which keeps
	// the previous punching behaviour rather than asserting anything.
	if got := parseNATClass("10.0.0.4:6969,1.2.3.4:6969"); got != natUnknown {
		t.Fatalf("parseNATClass(old peer) = %q, want %q", got, natUnknown)
	}
	// Junk must not be mistaken for a class.
	if got := parseNATClass("nat=,nat=wat,natfoo"); got != natUnknown {
		t.Fatalf("parseNATClass(junk) = %q, want %q", got, natUnknown)
	}
}

// natTokenFor must stay silent when the classification is not trustworthy.
// samples < 2 means "all reported ports agree" is vacuously true, and
// publishing that as port-stable is the lie that would send a peer punching
// at a symmetric NAT forever.
func TestNATTokenSuppressedWhenUnclassified(t *testing.T) {
	if tok := natTokenFor(natMapping{}); tok != "" {
		t.Fatalf("no classification should emit no token, got %q", tok)
	}
	if tok := natTokenFor(natMapping{ip: "1.2.3.4", samples: 1}); tok != "" {
		t.Fatalf("single STUN sample is UNKNOWN, must emit no token, got %q", tok)
	}
	if tok := natTokenFor(natMapping{ip: "1.2.3.4", samples: 2, symmetric: true}); tok != natTokenPfx+natSymmetric {
		t.Fatalf("got %q, want %q", tok, natTokenPfx+natSymmetric)
	}
}

// The token must appear in our own advertised candidates, so the peer can act
// on it. This is the wire contract the whole mechanism depends on.
func TestMyConnectCandidatesCarriesNATToken(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	setOurNAT("203.0.113.9", true, 3)
	myUDPPort = 6969
	got := myConnectCandidates()
	if !strings.Contains(got, natTokenPfx+natSymmetric) {
		t.Fatalf("candidates %q missing %q", got, natTokenPfx+natSymmetric)
	}
}

// noteConnectCandidates is the decision point in the punch path.
func TestNoteConnectCandidatesSuppressesHopelessPunch(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	setOurNAT("203.0.113.9", false, 3) // us: port-stable home router

	peer := "10.22.22.53"
	// Peer advertises symmetric (a phone on a carrier).
	if noteConnectCandidates(peer, "107.122.246.1:26912,"+natTokenPfx+natSymmetric) {
		t.Fatal("symmetric peer against our restricted NAT must not be punched directly")
	}
	if !relayPreferred(peer, false) {
		t.Fatal("relay must be preferred for an unpunchable pairing")
	}
}

func TestPunchableePairingIsLeftAlone(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	setOurNAT("203.0.113.9", false, 3)

	peer := "10.22.22.11"
	if !noteConnectCandidates(peer, "192.168.1.5:6969,"+natTokenPfx+natStable) {
		t.Fatal("two port-stable peers must still punch directly")
	}
	if relayPreferred(peer, false) {
		t.Fatal("a punchable pairing must not start out relay-preferred")
	}
}

// The timer is the independent trigger, for everything the classifier cannot
// see: one STUN server answering, a firewall dropping UDP to new
// destinations, a peer whose radio froze.
func TestEscalationByTimeWithoutClassification(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	peer := "10.22.22.7"

	if relayPreferred(peer, false) {
		t.Fatal("must not escalate immediately")
	}
	// Backdate the first punch past the escalation window.
	relayPolMu.Lock()
	relayPol[peer].firstPunch = time.Now().Add(-relayEscalateAfter - time.Second)
	relayPolMu.Unlock()

	if !relayPreferred(peer, false) {
		t.Fatal("must escalate to relay after relayEscalateAfter with no session")
	}
}

// Escalation must not be a one-way door: a phone that walks into Wi-Fi should
// go back to direct rather than staying relayed until the app restarts.
func TestEstablishedSessionClearsEscalation(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	peer := "10.22.22.7"

	relayPreferred(peer, false)
	relayPolMu.Lock()
	relayPol[peer].firstPunch = time.Now().Add(-relayEscalateAfter - time.Second)
	relayPolMu.Unlock()
	if !relayPreferred(peer, false) {
		t.Fatal("precondition: should have escalated")
	}
	// A direct session appears.
	if relayPreferred(peer, true) {
		t.Fatal("an established direct session must clear the relay preference")
	}
	if relayPreferred(peer, false) {
		t.Fatal("escalation must not immediately re-fire after a successful session")
	}
}

// The background direct-path probe is what upgrades a relayed session back to
// direct. It must be rate-limited, or relay-first becomes a punch storm.
func TestDirectProbeIsRateLimited(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()
	peer := "10.22.22.53"

	if !shouldProbeDirect(peer) {
		t.Fatal("first probe should be allowed")
	}
	if shouldProbeDirect(peer) {
		t.Fatal("second probe inside the window must be suppressed")
	}
	relayPolMu.Lock()
	relayPol[peer].lastProbe = time.Now().Add(-relayUpgradeProbeEvery - time.Second)
	relayPolMu.Unlock()
	if !shouldProbeDirect(peer) {
		t.Fatal("probe should be allowed again after relayUpgradeProbeEvery")
	}
}

// Bookkeeping must not grow without bound as peers churn.
func TestRelayPolicyForgetsStalePeers(t *testing.T) {
	resetRelayPolicy()
	defer resetRelayPolicy()

	relayPolMu.Lock()
	relayPol["10.22.22.99"] = &relayPeerPolicy{lastSeen: time.Now().Add(-relayPolicyForget - time.Minute)}
	relayPolMu.Unlock()

	// Any access runs the opportunistic sweep.
	relayPreferred("10.22.22.1", false)

	relayPolMu.Lock()
	_, stillThere := relayPol["10.22.22.99"]
	relayPolMu.Unlock()
	if stillThere {
		t.Fatal("a peer unseen for relayPolicyForget must be dropped")
	}
}
