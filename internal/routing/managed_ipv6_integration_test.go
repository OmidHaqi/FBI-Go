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

func guardDropCount(t *testing.T, app *NamespaceEngine) float64 {
	t.Helper()
	out := labRun(t, app, "nft", "-j", "list", "table", "ip6", ipv6GuardTable(app.TableName()))
	var doc struct {
		NFTables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, entry := range doc.NFTables {
		if raw, ok := entry["rule"]; ok {
			var rule struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			}
			if json.Unmarshal(raw, &rule) != nil {
				t.Fatal("invalid guard rule")
			}
			for _, expr := range rule.Expr {
				if counter, ok := expr["counter"]; ok {
					var value struct {
						Packets float64 `json:"packets"`
					}
					if json.Unmarshal(counter, &value) != nil {
						t.Fatal("invalid guard counter")
					}
					return value.Packets
				}
			}
		}
	}
	t.Fatal("IPv6 guard drop counter absent")
	return 0
}

func verifyManagedIPv6Guard(t *testing.T, apps [2]*NamespaceEngine, gateways [2][2]*NamespaceEngine, binary string, resolver *os.File, evidence string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	client, err := filepath.Abs("testdata/ipv6_guard_client.py")
	if err != nil {
		t.Fatal(err)
	}
	capture, err := filepath.Abs("testdata/ipv6_capture.py")
	if err != nil {
		t.Fatal(err)
	}
	var captures [2][2]string
	for i, app := range apps {
		for j, pair := range []struct{ client, gateway, iface, peer string }{
			{"2001:db8:200::9/64", "2001:db8:200::1/64", "fbi_ca", "fbi_ga"},
			{"2001:db8:201::9/64", "2001:db8:201::1/64", "fbi_cb", "fbi_gb"},
		} {
			labRun(t, app, "ip", "-6", "addr", "add", pair.client, "dev", pair.iface)
			labRun(t, gateways[i][j], "ip", "-6", "addr", "add", pair.gateway, "dev", pair.peer)
			captures[i][j] = filepath.Join(evidence, fmt.Sprintf("ipv6-capture-%d-%d.jsonl", i, j))
			ready := captures[i][j] + ".ready"
			cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, capture, pair.peer, captures[i][j], ready)
			cmd.ExtraFiles = []*os.File{gateways[i][j].fd}
			stderr, err := os.Create(captures[i][j] + ".stderr")
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
		for _, pair := range captures {
			for _, path := range pair {
				if _, err := os.Stat(path + ".ready"); err != nil {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IPv6 gateway capture startup timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	before := [2]float64{guardDropCount(t, apps[0]), guardDropCount(t, apps[1])}
	evidenceFile, err := os.OpenFile(filepath.Join(evidence, "ipv6-guard-evidence.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil { t.Fatal(err) }
	defer evidenceFile.Close()
	for round := 0; round < 4; round++ {
		var cmds [2]*exec.Cmd
		for i, app := range apps {
			wan := "wan-a"
			if i == 1 {
				wan = "wan-b"
			}
			ready := filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.ready", round, i))
			signal := filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.signal", round, i))
			result := filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.result.json", round, i))
			cmd := exec.Command(binary, "app", "run", "--wan", wan, "--", python, client, ready, signal, result)
			cmd.ExtraFiles = []*os.File{app.fd, resolver}
			cmd.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_RESOLVER_FD=4", "FBI_GO_APP_NETNS_NAME="+app.Name(), "FBI_GO_APP_WAN="+wan)
			log, err := os.Create(result + ".stderr")
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				_ = log.Close()
				t.Fatal(err)
			}
			_ = log.Close()
			cmds[i] = cmd
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		}
		deadline := time.Now().Add(4 * time.Second)
		for {
			ready := true
			for i := range apps {
				if _, err := os.Stat(filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.ready", round, i))); err != nil {
					ready = false
				}
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("managed IPv6 client did not start")
			}
			time.Sleep(20 * time.Millisecond)
		}
		for i, app := range apps {
			gateway, iface := "2001:db8:200::1", "fbi_ca"
			if i == 1 {
				gateway, iface = "2001:db8:201::1", "fbi_cb"
			}
			if round == 1 || round == 3 {
				labRun(t, app, "ip", "-6", "route", "del", "default")
			}
			if round == 2 {
				if i == 0 {
					gateway, iface = "2001:db8:201::1", "fbi_cb"
				} else {
					gateway, iface = "2001:db8:200::1", "fbi_ca"
				}
			}
			if round != 1 {
				labRun(t, app, "ip", "-6", "route", "add", "default", "via", gateway, "dev", iface)
			}
			if err := os.WriteFile(filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.signal", round, i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for i, cmd := range cmds {
			if err := cmd.Wait(); err != nil {
				t.Fatalf("managed IPv6 client %d round %d: %v", i, round, err)
			}
			resultPath := filepath.Join(evidence, fmt.Sprintf("ipv6-%d-%d.result.json", round, i))
			data, err := os.ReadFile(resultPath)
			if err != nil { t.Fatal(err) }
			var attempts []map[string]string
			if err := json.Unmarshal(data, &attempts); err != nil || len(attempts) != 4 { t.Fatalf("invalid IPv6 client evidence: %v %s", err, data) }
			for _, attempt := range attempts {
				line, err := json.Marshal(map[string]any{"app":i, "round":round, "wan":map[bool]string{true:"wan-a", false:"wan-b"}[i==0], "attempt":attempt})
				if err != nil { t.Fatal(err) }
				if _, err := evidenceFile.Write(append(line, '\n')); err != nil { t.Fatal(err) }
			}
		}
		t.Logf("IPv6 guard scenario %d completed (0=selected, 1=disabled, 2=alternate, 3=recovered)", round)
	}
	for i, app := range apps {
		after := guardDropCount(t, app)
		if after <= before[i] {
			t.Errorf("IPv6 guard drop counter did not advance for app %d: before %.0f after %.0f", i, before[i], after)
		}
		t.Logf("app %d IPv6 guard drops: before=%.0f after=%.0f", i, before[i], after)
		line, err := json.Marshal(map[string]any{"app":i, "counter_before":before[i], "counter_after":after, "event":"nft_drop_counter"})
		if err != nil { t.Fatal(err) }
		if _, err := evidenceFile.Write(append(line, '\n')); err != nil { t.Fatal(err) }
		for _, path := range captures[i] {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(string(b)) != "" {
				t.Errorf("forbidden IPv6 TCP/UDP reached gateway: %s", b)
			}
			line, err := json.Marshal(map[string]any{"app":i, "event":"gateway_capture", "path":path, "forbidden_packets":len(strings.Fields(string(b)))})
			if err != nil { t.Fatal(err) }
			if _, err := evidenceFile.Write(append(line, '\n')); err != nil { t.Fatal(err) }
			t.Logf("app %d gateway capture %s: zero forbidden IPv6 TCP/UDP packets", i, path)
		}
		labRun(t, app, "ip", "-6", "route", "del", "default")
	}
}
