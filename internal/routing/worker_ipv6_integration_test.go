//go:build integration

package routing

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// verifyWorkerIPv6PacketGuard runs only after the restricted worker's IPC
// INSTALL_IPV6_GUARD and VERIFY replies and durable snapshot checks.
func verifyWorkerIPv6PacketGuard(t *testing.T, app, gatewayA, gatewayB *NamespaceEngine, wan, evidence string, guestVM bool) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	clientPath, err := filepath.Abs("testdata/worker_ipv6_client.py")
	if err != nil {
		t.Fatal(err)
	}
	capturePath, err := filepath.Abs("testdata/ipv6_capture.py")
	if err != nil {
		t.Fatal(err)
	}
	var captures [2]string
	for i, peer := range []struct {
		gateway                *NamespaceEngine
		iface, other, addr, gw string
	}{
		{gatewayA, "fbi_ca", "fbi_aa", "2001:db8:200::9/64", "2001:db8:200::1/64"},
		{gatewayB, "fbi_cb", "fbi_bb", "2001:db8:201::9/64", "2001:db8:201::1/64"},
	} {
		labRun(t, app, "ip", "-6", "addr", "add", peer.addr, "dev", peer.iface)
		labRun(t, peer.gateway, "ip", "-6", "addr", "add", peer.gw, "dev", peer.other)
		captures[i] = filepath.Join(evidence, "gateway-"+peer.iface+".jsonl")
		ready := captures[i] + ".ready"
		cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, capturePath, peer.other, captures[i], ready)
		cmd.ExtraFiles = []*os.File{peer.gateway.fd}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	waitFile := func(path string) {
		deadline := time.Now().Add(4 * time.Second)
		for {
			if _, err := os.Stat(path); err == nil {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("test readiness file missing: %s", path)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	for _, path := range captures {
		waitFile(path + ".ready")
	}
	before := guardDropCount(t, app)
	for round, route := range []struct{ gateway, iface string }{{"2001:db8:200::1", "fbi_ca"}, {"2001:db8:201::1", "fbi_cb"}} {
		ready := filepath.Join(evidence, "worker-ipv6-client-"+string(rune('a'+round))+".ready")
		signal := ready + ".signal"
		result := ready + ".json"
		done := make(chan error, 1)
		go func() {
			done <- RunManaged(context.Background(), ManagedLaunch{NamespaceFD: app.fd, NamespaceName: app.Name(), WAN: wan, Command: []string{python, clientPath, ready, signal, result}, GuestVMTest: guestVM})
		}()
		waitFile(ready)
		labRun(t, app, "ip", "-6", "route", "replace", "default", "via", route.gateway, "dev", route.iface)
		if err := os.WriteFile(signal, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatalf("managed IPv6 attempt: %v", err)
		}
		b, err := os.ReadFile(result)
		if err != nil {
			t.Fatal(err)
		}
		var observations []struct{ Protocol, Outcome string }
		if err := json.Unmarshal(b, &observations); err != nil || len(observations) != 2 {
			t.Fatalf("invalid IPv6 result: %v %s", err, b)
		}
		for _, observation := range observations {
			if observation.Outcome == "sent" {
				t.Fatalf("forbidden IPv6 %s escaped via %s", observation.Protocol, route.iface)
			}
		}
	}
	after := guardDropCount(t, app)
	if after <= before {
		t.Fatalf("worker guard drop counter did not advance: %.0f to %.0f", before, after)
	}
	for _, path := range captures {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSpace(string(b)) != "" {
			t.Fatalf("forbidden IPv6 gateway packet: %s", b)
		}
	}
	t.Logf("restricted worker IPv6 guard: drop counter %.0f -> %.0f; TCP/UDP attempts after selected and alternative default routes; forbidden gateway packets=0", before, after)
	labRun(t, app, "ip", "-6", "route", "del", "default")
}
