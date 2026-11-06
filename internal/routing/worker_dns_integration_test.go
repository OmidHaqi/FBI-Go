//go:build integration

package routing

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func verifyWorkerDNS(t *testing.T, app, gateway *NamespaceEngine, wan, source, evidence string, guestVM bool) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	server, err := filepath.Abs("testdata/dns_http_server.py")
	if err != nil {
		t.Fatal(err)
	}
	client, err := filepath.Abs("testdata/dns_query.py")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(evidence, "worker-dns.jsonl")
	cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, server, "203.0.113.7", logPath, wan)
	cmd.ExtraFiles = []*os.File{gateway.fd}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(logPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker DNS server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, protocol := range []string{"udp", "tcp"} {
		for _, kind := range []string{"A", "AAAA"} {
			if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: app.fd, NamespaceName: app.Name(), WAN: wan, Command: []string{python, client, "203.0.113.7", protocol, kind}, GuestVMTest: guestVM}); err != nil {
				t.Fatalf("managed DNS %s %s after worker guard: %v", protocol, kind, err)
			}
		}
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Protocol, Source string
			QType            int
			Answered         bool
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Source != source || !row.Answered {
			t.Fatalf("wrong worker DNS packet: %s", line)
		}
		seen[row.Protocol+"/"+map[int]string{1: "A", 28: "AAAA"}[row.QType]] = true
	}
	for _, key := range []string{"dns_udp/A", "dns_udp/AAAA", "dns_tcp/A", "dns_tcp/AAAA"} {
		if !seen[key] {
			t.Fatalf("missing worker DNS packet %s: %s", key, b)
		}
	}
	t.Logf("restricted-worker guard then managed DNS packet evidence: WAN=%s UDP/TCP A/AAAA from %s", wan, source)
	if curl, err := exec.LookPath("curl"); err == nil {
		resolver, err := os.CreateTemp(evidence, "resolv-*.conf")
		if err != nil {
			t.Fatal(err)
		}
		defer resolver.Close()
		if _, err := resolver.WriteString("nameserver 203.0.113.7\noptions timeout:1 attempts:1\n"); err != nil {
			t.Fatal(err)
		}
		if guestVM {
			if err := resolver.Chown(1000, 1000); err != nil {
				t.Fatal(err)
			}
		}
		var nss *os.File
		if guestVM {
			nss = guestNSSwitchFile(t, evidence)
		}
		if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: app.fd, ResolverFD: resolver, NSSwitchFD: nss, NamespaceName: app.Name(), WAN: wan, Command: []string{curl, "--noproxy", "*", "--max-time", "5", "--fail", "--silent", "http://service.lab.test:8080/"}, GuestVMTest: guestVM}); err != nil {
			t.Fatalf("managed curl domain HTTP: %v", err)
		}
		b, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
			var row struct{ Protocol, Source string }
			if json.Unmarshal(line, &row) == nil && row.Protocol == "http_tcp" && row.Source == source {
				found = true
			}
		}
		if !found {
			t.Fatalf("curl returned without expected gateway HTTP packet: %s", b)
		}
		t.Logf("managed curl HTTP gateway observation: WAN=%s source=%s", wan, source)
	} else {
		t.Log("curl unavailable: actual curl runtime NOT_VERIFIED")
	}
}
