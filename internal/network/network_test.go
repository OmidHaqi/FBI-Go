package network

import (
	"net"
	"testing"
)

func TestClassify(t *testing.T) {
	r := []Route{{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "wlan0"}}
	ok, _ := Classify("wlan0", net.FlagUp, "wifi", []string{"192.0.2.9/24"}, r)
	if !ok {
		t.Fatal("expected candidate")
	}
	ok, _ = Classify("tun0", net.FlagUp, "vpn", []string{"192.0.2.9/24"}, []Route{{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "tun0"}})
	if ok {
		t.Fatal("VPN must be excluded")
	}
}
func TestNoCarrierOrOperDown(t *testing.T) {
	routes := []Route{{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "198.51.100.1", Interface: "wan0"}}
	addr := []string{"198.51.100.9/24"}
	no := false
	yes := true
	for _, tc := range []struct {
		name, oper string
		carrier    *bool
	}{{"no carrier", "down", &no}, {"oper down", "down", &yes}, {"lower layer", "lowerlayerdown", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			ready := linkReady(true, tc.oper, tc.carrier)
			if ready {
				t.Fatal("link reported ready")
			}
			candidate, _ := classifyLink("wan0", net.FlagUp, "ethernet_or_other", addr, routes, ready)
			if candidate {
				t.Fatal("inactive link selected as WAN")
			}
		})
	}
	if !linkReady(true, "up", &yes) {
		t.Fatal("active link rejected")
	}
}

func TestNetlinkOperStateMapping(t *testing.T) {
	for value, want := range map[byte]string{0: "unknown", 1: "notpresent", 2: "down", 3: "lowerlayerdown", 4: "testing", 5: "dormant", 6: "up", 255: "unknown"} {
		if got := operStateName(value); got != want {
			t.Fatalf("operstate %d: got %q want %q", value, got, want)
		}
	}
}
