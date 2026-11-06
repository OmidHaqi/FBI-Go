//go:build integration

package routing

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type dnsHTTPRecord struct {
	WAN      string `json:"wan"`
	Protocol string `json:"protocol"`
	Source   string `json:"source"`
	Query    string `json:"query"`
	QType    int    `json:"qtype"`
}

func verifyManagedDNSHTTP(t *testing.T, apps [2]*NamespaceEngine, gateways [2][2]*NamespaceEngine, binary string, resolver *os.File, evidence string) {
	t.Helper()
	server, err := filepath.Abs("testdata/dns_http_server.py")
	if err != nil {
		t.Fatal(err)
	}
	client, err := filepath.Abs("testdata/dns_query.py")
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skipf("application HTTP compatibility requires curl: %v", err)
	}
	curl, err = filepath.Abs(curl)
	if err != nil {
		t.Fatal(err)
	}
	goClient := filepath.Join(t.TempDir(), "fbi-go-http-client")
	build := exec.Command("go", "build", "-o", goClient, "./testdata/go_http_client.go")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Go HTTP client: %v: %s", err, out)
	}
	var paths [2][2]string
	for i := range gateways {
		for j, gateway := range gateways[i] {
			path := filepath.Join(evidence, fmt.Sprintf("dns-http-%d-%d.jsonl", i, j))
			paths[i][j] = path
			wan := "wan-a"
			if j == 1 {
				wan = "wan-b"
			}
			cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, server, "203.0.113.7", path, wan)
			cmd.ExtraFiles = []*os.File{gateway.fd}
			stderr, err := os.Create(path + ".stderr")
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout, cmd.Stderr = stderr, stderr
			if err := cmd.Start(); err != nil {
				_ = stderr.Close()
				t.Fatal(err)
			}
			_ = stderr.Close()
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		ready := true
		for _, pair := range paths {
			for _, path := range pair {
				if _, err := os.Stat(path); err != nil {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("synthetic DNS/HTTP server startup timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	run := func(i int, cmdPath string, args ...string) {
		wan := "wan-a"
		if i == 1 {
			wan = "wan-b"
		}
		cmd := exec.Command(binary, append([]string{"app", "run", "--wan", wan, "--", cmdPath}, args...)...)
		cmd.ExtraFiles = []*os.File{apps[i].fd, resolver}
		cmd.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_RESOLVER_FD=4", "FBI_GO_APP_NETNS_NAME="+apps[i].Name(), "FBI_GO_APP_WAN="+wan)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("managed DNS/HTTP app %d %s %v: %v: %s", i, cmdPath, args, err, out)
		}
		if (cmdPath == curl || cmdPath == goClient) && !strings.Contains(string(out), "fbi-go-test-ok") {
			t.Fatalf("HTTP response: %s", out)
		}
	}
	for i := range apps {
		for _, transport := range []string{"udp", "tcp"} {
			for _, kind := range []string{"A", "AAAA"} {
				run(i, python, client, "203.0.113.7", transport, kind)
			}
		}
		// "service" requires the lab.test search domain from the private resolver.
		run(i, curl, "--noproxy", "*", "-4", "--max-time", "4", "http://service:8080/managed")
		run(i, goClient)
	}
	// A host-local systemd-resolved stub is not valid in this private netns.
	stubPath := filepath.Join(evidence, "dns-host-stub.conf")
	if err := os.WriteFile(stubPath, []byte("nameserver 127.0.0.53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stub, err := os.Open(stubPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stub.Close()
	if err := validateManagedResolver(stub); err == nil || !strings.Contains(err.Error(), "host-stub") {
		t.Fatalf("host stub accepted: %v", err)
	}
	// An unavailable resolver must cause a bounded domain lookup failure.
	badPath := filepath.Join(evidence, "dns-unavailable.conf")
	if err := os.WriteFile(badPath, []byte("nameserver 203.0.113.8\noptions timeout:1 attempts:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bad, err := os.Open(badPath)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	cmd := exec.Command(binary, "app", "run", "--wan", "wan-a", "--", curl, "--noproxy", "*", "-4", "--max-time", "3", "http://service.lab.test:8080/unavailable")
	cmd.ExtraFiles = []*os.File{apps[0].fd, bad}
	cmd.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_RESOLVER_FD=4", "FBI_GO_APP_NETNS_NAME="+apps[0].Name(), "FBI_GO_APP_WAN=wan-a")
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("unavailable DNS unexpectedly resolved: %s", out)
	}
	// Removing the selected policy route must not redirect a DNS query to the
	// competing WAN. Restore it and prove that new DNS traffic recovers.
	labRun(t, apps[0], "ip", "-4", "route", "del", "table", "30000", "default", "via", "192.0.2.1", "dev", "fbi_ca")
	noRoute := exec.Command(binary, "app", "run", "--wan", "wan-a", "--", python, client, "203.0.113.7", "udp", "A")
	noRoute.ExtraFiles = []*os.File{apps[0].fd, resolver}
	noRoute.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_RESOLVER_FD=4", "FBI_GO_APP_NETNS_NAME="+apps[0].Name(), "FBI_GO_APP_WAN=wan-a")
	if out, err := noRoute.CombinedOutput(); err == nil {
		t.Fatalf("disabled WAN delivered DNS: %s", out)
	}
	labRun(t, apps[0], "ip", "-4", "route", "add", "table", "30000", "default", "via", "192.0.2.1", "dev", "fbi_ca", "src", "192.0.2.9")
	run(0, python, client, "203.0.113.7", "udp", "A")
	for i, pair := range paths {
		wantSource := "192.0.2.9"
		wantWAN := 0
		if i == 1 {
			wantSource, wantWAN = "198.51.100.99", 1
		}
		counts := map[string]int{}
		for j, path := range pair {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if line == "" {
					continue
				}
				var record dnsHTTPRecord
				if err := json.Unmarshal([]byte(line), &record); err != nil {
					t.Fatal(err)
				}
				if j != wantWAN || record.Source != wantSource {
					t.Errorf("DNS/HTTP packet escaped selected WAN: app=%d gateway=%d record=%+v", i, j, record)
				}
				counts[fmt.Sprintf("%s/%d", record.Protocol, record.QType)]++
			}
		}
		for _, key := range []string{"dns_udp/1", "dns_udp/28", "dns_tcp/1", "dns_tcp/28", "http_tcp/0"} {
			if counts[key] == 0 {
				t.Errorf("app %d missing packet observation %s: %v", i, key, counts)
			}
		}
		t.Logf("app %d DNS/HTTP packet evidence: %v", i, counts)
	}
}
