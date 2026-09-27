package main

import "testing"

// Full VPN must switch on and off in a running client (the desktop apps
// apply the Settings choice live). The selection loop starting while off is
// covered by the live netns test (mesh/livetoggle.sh).
func TestApplyUseExitLive(t *testing.T) {
	self := testKeypair(t)
	testNode(t, self, nil)
	oldPin := currentExitPin()
	t.Cleanup(func() {
		_ = applyUseExit(false, nil)
		setExitPin(oldPin)
	})
	_ = applyUseExit(false, nil)
	if usingExit() {
		t.Fatal("setup: full VPN should be off")
	}
	if err := applyUseExitRequest(true, strPtr("node-x")); err != nil {
		t.Fatal(err)
	}
	if !usingExit() || currentExitPin() != "node-x" {
		t.Fatalf("not applied: useExit=%v pin=%q", usingExit(), currentExitPin())
	}
	// An exit is selected by the running loop (started while off).
	exitMu.Lock()
	selectedExit = &exitInfo{rttMs: 1}
	exitMu.Unlock()
	if err := applyUseExit(false, nil); err != nil {
		t.Fatal(err)
	}
	if usingExit() {
		t.Fatal("full VPN still on")
	}
	if a, _ := currentExit(); a != nil {
		t.Fatal("an exit is still selected after turning full VPN off")
	}
}

func strPtr(s string) *string { return &s }
