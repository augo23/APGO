package main

import (
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestPeerStatsKeyedByStaticKeySurviveRoaming(t *testing.T) {
	tbl := &peerStatsTable{m: map[[32]byte]*peerCounters{}, started: time.Now()}
	var peer [32]byte
	peer[0] = 0x11

	// A peer sends from one endpoint, then roams (NAT rebind / Wi-Fi to LTE /
	// onto a relay circuit). Counters are keyed by identity, not address, so
	// the roam must not reset the totals — that is the whole point of the
	// design and the thing a "total transferred" column depends on.
	tbl.AddRx(peer, 1000)
	tbl.AddTx(peer, 500)
	tbl.AddRx(peer, 1000) // same peer, different endpoint — identical key
	tbl.AddTx(peer, 500)

	got := tbl.Traffic(peer)
	if got.RxBytes != 2000 || got.TxBytes != 1000 {
		t.Errorf("rx=%d tx=%d, want 2000/1000", got.RxBytes, got.TxBytes)
	}
	if got.Total != 3000 {
		t.Errorf("total = %d, want 3000", got.Total)
	}
	if got.RxPkts != 2 || got.TxPkts != 2 {
		t.Errorf("packets rx=%d tx=%d, want 2/2", got.RxPkts, got.TxPkts)
	}
}

func TestPeerStatsUnknownPeerIsZeroNotPanic(t *testing.T) {
	tbl := &peerStatsTable{m: map[[32]byte]*peerCounters{}, started: time.Now()}
	var unknown [32]byte
	got := tbl.Traffic(unknown)
	if got.Total != 0 || got.Sampled {
		t.Errorf("unknown peer should be zero and unsampled, got %+v", got)
	}
}

func TestPeerStatsForgetClearsRevokedPeer(t *testing.T) {
	tbl := &peerStatsTable{m: map[[32]byte]*peerCounters{}, started: time.Now()}
	var peer [32]byte
	peer[0] = 0x22
	tbl.AddRx(peer, 4096)
	if tbl.Traffic(peer).Total == 0 {
		t.Fatal("counters did not record")
	}
	tbl.Forget(peer)
	if tbl.Traffic(peer).Total != 0 {
		t.Error("a revoked peer's counters must be dropped")
	}
}

func TestTrafficForB64RejectsBadKeys(t *testing.T) {
	// Row types that have no static key (nothing exchanged yet) must produce a
	// zero value the UI can render as "—", not a panic and not a wrong peer's
	// numbers.
	for _, bad := range []string{"", "not-base64!!", "c2hvcnQ="} {
		if got := trafficForB64(bad); got.Total != 0 {
			t.Errorf("trafficForB64(%q) = %+v, want zero", bad, got)
		}
	}
}

// --- admission enforcement -------------------------------------------------
//
// These pin the behaviour that a default flip got wrong twice. admitted() is
// SYMMETRIC — it decides whether this node accepts its peers, not just whether
// peers accept it — so enforcing with an empty approval store disconnects a
// whole fleet rather than gating one device.

func resetAdmissionState(t *testing.T) {
	t.Helper()
	admissionEnvOnce = onceReset()
	admissionEnvForce = nil
	admissionEnforceLogged.Store(false)
	approvals.mu.Lock()
	approvals.recs = map[[32]byte]storedApproval{}
	approvals.mu.Unlock()
}

// installTestAdminKey makes admissionRequired() true, which is the precondition
// for any of this logic to engage. Without it these tests would skip, and the
// regression they exist to catch would go unnoticed.
func installTestAdminKey(t *testing.T) {
	t.Helper()
	seed := make([]byte, adminSig.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, _ := adminSig.DeriveKey(seed)
	raw, err := pub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !setAdminPubBytes(raw) {
		t.Fatal("could not install a test admin public key")
	}
	if !adminKeySet() {
		t.Fatal("adminKeySet() still false after installing a key")
	}
	t.Cleanup(func() { clearAdminPub() })
}

func withEnv(t *testing.T, k, v string) {
	t.Helper()
	old, had := os.LookupEnv(k)
	if v == "" {
		_ = os.Unsetenv(k)
	} else {
		_ = os.Setenv(k, v)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	})
}

// setTestAdminKey makes admissionRequired() true without a real key exchange.
func addApproval(pub [32]byte, action string) {
	approvals.mu.Lock()
	approvals.recs[pub] = storedApproval{Action: action, Seq: 1}
	approvals.mu.Unlock()
}

// THE REGRESSION. A network with an admin key but no approvals must NOT be
// enforced against: every node's store is empty, so enforcing rejects every
// peer in both directions at once. This is what produced 100% packet loss on a
// mesh that was otherwise healthy.
func TestNoEnforcementUntilFirstApproval(t *testing.T) {
	resetAdmissionState(t)
	installTestAdminKey(t)
	withEnv(t, "ADMISSION_ENFORCE", "")
	if admissionEnforced() {
		t.Fatal("with an admin key but ZERO approval records, enforcement must stay OFF — " +
			"turning it on rejects every peer this node has")
	}
	// One approval means an admin has started using the feature. From then on
	// the gate is real.
	var somebody [32]byte
	somebody[0] = 0x42
	addApproval(somebody, "approve")
	admissionEnforceLogged.Store(false)
	if !admissionEnforced() {
		t.Error("once any device is approved, enforcement must turn on by itself")
	}
}

// A "deny" record is not an approval and must not switch enforcement on.
func TestDenyRecordDoesNotEnableEnforcement(t *testing.T) {
	resetAdmissionState(t)
	installTestAdminKey(t)
	withEnv(t, "ADMISSION_ENFORCE", "")
	var somebody [32]byte
	somebody[0] = 0x43
	addApproval(somebody, "deny")
	if approvals.hasAnyApproval() {
		t.Error("a deny record must not count as an approval")
	}
}

func TestAdmissionEnforceEnvForcesOn(t *testing.T) {
	resetAdmissionState(t)
	installTestAdminKey(t)
	withEnv(t, "ADMISSION_ENFORCE", "1")
	if !admissionEnforced() {
		t.Error("ADMISSION_ENFORCE=1 must enforce even with an empty approval store")
	}
}

func TestAdmissionEnforceEnvForcesOff(t *testing.T) {
	resetAdmissionState(t)
	installTestAdminKey(t)
	withEnv(t, "ADMISSION_ENFORCE", "0")
	var somebody [32]byte
	somebody[0] = 0x44
	addApproval(somebody, "approve")
	if admissionEnforced() {
		t.Error("ADMISSION_ENFORCE=0 must disable enforcement even with approvals present")
	}
}

// No admin key at all: admission control is not in use and nothing engages.
func TestNoAdminKeyNeverEnforces(t *testing.T) {
	resetAdmissionState(t)
	withEnv(t, "ADMISSION_ENFORCE", "")
	clearAdminPub() // explicitly: no admin key on this network
	if admissionEnforced() {
		t.Error("with no admin key there is nothing to gate")
	}
}
