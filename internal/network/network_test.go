package network

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLinkInfoKind(t *testing.T) {
	value := make([]byte, 12)
	binary.NativeEndian.PutUint16(value[:2], 8)
	binary.NativeEndian.PutUint16(value[2:4], 1)
	copy(value[4:], "tun\x00")
	if got := linkInfoKind(value); got != "tun" {
		t.Fatalf("link kind: %q", got)
	}
	if got := linkInfoKind([]byte{0, 0, 1, 0}); got != "" {
		t.Fatalf("malformed attribute: %q", got)
	}
}

func TestUSBClassificationUsesDeviceAncestry(t *testing.T) {
	root := t.TempDir()
	usb := filepath.Join(root, "devices", "usb1", "1-2")
	pci := filepath.Join(root, "devices", "pci0000:00", "0000:00:1f.6")
	for _, path := range []string{usb, pci, filepath.Join(root, "class", "usb0"), filepath.Join(root, "class", "enx123"), filepath.Join(root, "class", "wwan0")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"usb0": usb, "enx123": pci, "wwan0": usb} {
		if err := os.Symlink(target, filepath.Join(root, "class", name, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if got := deviceKindAt(filepath.Join(root, "class"), "usb0", 0); got != "usb_network" {
		t.Fatalf("USB path: %s", got)
	}
	if got := deviceKindAt(filepath.Join(root, "class"), "wwan0", 0); got != "usb_network" {
		t.Fatalf("USB modem path: %s", got)
	}
	if got := deviceKindAt(filepath.Join(root, "class"), "enx123", 0); got != "ethernet_or_other" {
		t.Fatalf("name-only USB guess: %s", got)
	}
	if got := deviceKindAt(filepath.Join(root, "class"), "tun0", 0); got != "vpn" {
		t.Fatalf("VPN: %s", got)
	}
}

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
