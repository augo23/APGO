package main

import "testing"

func TestParseDefaultRoute(t *testing.T) {
	// A multi-homed Mac with Full VPN routes from an earlier run still present.
	out := `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
0/1                utun0              USc                 utun0
default            10.202.2.1         UGScg                 en9
default            10.202.3.1         UGScIg                en0
default            link#22            UCSIg               utun0
10.202.2/24        link#9             UCS                   en9      !
128.0/1            utun0              USc                 utun0
`
	if gw, nif := parseDefaultRoute(out); gw != "10.202.2.1" || nif != "en9" {
		t.Fatalf("got %s %s", gw, nif)
	}
	// Only a scoped default (primary interface on a tunnel): use it.
	out = `default            link#22            UCSg                utun3
default            192.168.1.1        UGScIg                en0
`
	if gw, nif := parseDefaultRoute(out); gw != "192.168.1.1" || nif != "en0" {
		t.Fatalf("got %s %s", gw, nif)
	}
	// IPv6 with a zoned link-local gateway.
	out = `default                                 fe80::1%en9                     UGcg                en9
default                                 fe80::%utun0                    UGcIg             utun0
`
	if gw, nif := parseDefaultRoute(out); gw != "fe80::1%en9" || nif != "en9" {
		t.Fatalf("got %s %s", gw, nif)
	}
	if gw, _ := parseDefaultRoute("Internet:\n"); gw != "" {
		t.Fatal("no default route should give nothing")
	}
}
