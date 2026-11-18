package main

import "testing"

// The admin signs canonicalNodeConfig's string and every node verifies its own
// copy of it (client/nodeconfig.go). These vectors were produced by the
// client's function; if this test fails, records signed here are rejected by
// every node as "invalid signature".
func TestCanonicalNodeConfigMatchesClientV3(t *testing.T) {
	tr, f := true, false
	var n int64 = 1700000000
	r := "https://rv.example"
	c := SignedNodeConfig{PubKey: "QUJD", DHT: &tr, ExitNode: &f, Rendezvous: &r,
		IPv6: &f, RefreshRoutes: &n, Epoch: 7, Ts: 8}
	want := "OVLYNODECFG3|QUJD|true|-|-|false|-|-|https://rv.example|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|false|1700000000|7|8"
	if got := canonicalNodeConfig(c); got != want {
		t.Fatalf("v3 canonical string differs from the client's:\n got %s\nwant %s", got, want)
	}
	c.RefreshRoutes = nil
	want = "OVLYNODECFG3|QUJD|true|-|-|false|-|-|https://rv.example|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|false|-|7|8"
	if got := canonicalNodeConfig(c); got != want {
		t.Fatalf("v3 (ipv6 only) canonical string differs from the client's:\n got %s\nwant %s", got, want)
	}
}
