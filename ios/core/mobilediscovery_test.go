package overlaymobile

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRendezvousCredentialNeverSentOverPublicHTTP(t *testing.T) {
	old := gRendezvousCred
	t.Cleanup(func() { gRendezvousCred = old })
	gRendezvousCred = "user:secret"
	for url, want := range map[string]bool{
		"https://apgo.example.com/api/rendezvous": true,
		"http://192.168.1.10:8080/api/rendezvous": true,
		"http://10.22.22.22/api/rendezvous":       true,
		"http://127.0.0.1/api/rendezvous":         true,
		"http://apgo.example.com/api/rendezvous":  false,
		"http://8.8.8.8/api/rendezvous":           false,
	} {
		req, _ := http.NewRequest(http.MethodPost, url, nil)
		applyRendezvousAuth(req)
		if got := req.Header.Get("Authorization") != ""; got != want {
			t.Errorf("%s: credential sent=%v, want %v", url, got, want)
		}
	}
}

// The phone DHT is read-only: it must not answer (or store from) queries.
func TestPhoneDHTIgnoresQueries(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Built directly (no startDHT goroutine): this tests the receive path only.
	d := &dhtState{
		table: &dhtRoutingTable{},
		conn:  conn,
		tx:    map[string]chan map[string]interface{}{},
		peers: map[string]map[string]time.Time{},
	}
	d.enabled.Store(true)
	gDHT = d
	t.Cleanup(func() { gDHT = nil })

	asker, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer asker.Close()
	q, _ := bencode(map[string]interface{}{"t": "aa", "y": "q", "q": "announce_peer",
		"a": map[string]interface{}{"id": string(make([]byte, 20)), "info_hash": string(make([]byte, 20)), "port": 1, "token": "x"}})
	dhtHandlePacket(q, asker.LocalAddr().(*net.UDPAddr))

	d.peersMu.Lock()
	n := len(d.peers)
	d.peersMu.Unlock()
	if n != 0 {
		t.Fatalf("read-only phone DHT stored %d announced key(s)", n)
	}
	_ = asker.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := asker.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatal("read-only phone DHT answered a query")
	}
}
