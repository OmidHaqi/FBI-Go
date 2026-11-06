//go:build integration

package routing

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type packetRecord struct {
	Proto   string `json:"proto"`
	Flow    string `json:"flow"`
	Source  string `json:"source"`
	Port    int    `json:"port"`
	StartNS int64  `json:"start_ns"`
	EndNS   int64  `json:"end_ns"`
}

func requireDisposableVM(t *testing.T) {
	t.Helper()
	if os.Getenv("FBI_GO_RUN_NETNS") != "1" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" {
		t.Skip("requires explicit disposable VM opt-in")
	}
	if out, err := exec.Command("systemd-detect-virt", "--vm", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("disposable VM not detected: %v %s", err, out)
	}
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var caps uint64
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			caps, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, bit := range []uint{12, 13, 21} {
		if caps&(uint64(1)<<bit) == 0 {
			t.Fatalf("missing effective capability bit %d; no automatic elevation", bit)
		}
	}
}

func labRun(t *testing.T, ns *NamespaceEngine, args ...string) string {
	t.Helper()
	out, err := ns.run("", args...)
	if err != nil {
		logLabDiagnostics(t, ns)
		t.Fatalf("owned namespace %s operation %q failed: %v", ns.Name(), args, err)
	}
	return out
}

func labRouteTable(t *testing.T, ns *NamespaceEngine, phase string, family, table int, allowMissing bool) string {
	t.Helper()
	out, err := ns.readRouteTable(family, table, allowMissing)
	if err != nil {
		logLabDiagnostics(t, ns)
		t.Fatalf("%s: owned namespace %s route table %d read failed (IPv%d, missing allowed=%t): %v", phase, ns.Name(), table, family, allowMissing, err)
	}
	return out
}

func logLabDiagnostics(t *testing.T, ns *NamespaceEngine) {
	t.Helper()
	if id, err := namespaceIdentity(filepath.Join("/run/netns", ns.Name())); err == nil {
		t.Logf("namespace %s identity %s", ns.Name(), id)
	}
	for _, kind := range []string{"link", "addr", "route", "rule"} {
		out, err := ns.run("", "ip", "-j", kind, "show")
		t.Logf("namespace %s: ip -j %s show: %s (error: %v)", ns.Name(), kind, out, err)
	}
}

func checkLabLink(t *testing.T, ns *NamespaceEngine, iface, cidr string) {
	t.Helper()
	link := labRun(t, ns, "ip", "-j", "link", "show", "dev", iface)
	var links []struct {
		Name  string   `json:"ifname"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal([]byte(link), &links); err != nil || len(links) != 1 || links[0].Name != iface {
		t.Fatalf("unexpected link in %s: %s: %v", ns.Name(), link, err)
	}
	up := false
	for _, flag := range links[0].Flags {
		if flag == "UP" {
			up = true
		}
	}
	if !up {
		t.Fatalf("%s is not administratively UP in %s: %s", iface, ns.Name(), link)
	}
	addr := labRun(t, ns, "ip", "-j", "addr", "show", "dev", iface)
	var addrs []struct {
		Info []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(addr), &addrs); err != nil || len(addrs) != 1 {
		t.Fatalf("unexpected address in %s: %s: %v", ns.Name(), addr, err)
	}
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	ones, _ := subnet.Mask.Size()
	for _, a := range addrs[0].Info {
		if a.Local == ip.String() && a.Prefix == ones {
			return
		}
	}
	t.Fatalf("%s missing %s in %s: %s", iface, cidr, ns.Name(), addr)
}

func labRecords(t *testing.T, paths [2]string) [2][]packetRecord {
	t.Helper()
	var result [2][]packetRecord
	for i, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scan := bufio.NewScanner(f)
		for scan.Scan() {
			var r packetRecord
			if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			result[i] = append(result[i], r)
		}
		if err := scan.Err(); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
	}
	return result
}

func verifyStage(t *testing.T, logs [2][]packetRecord, prefix string, wantFlows, wantPackets int) ([2]int, [2][]packetRecord) {
	t.Helper()
	var counts [2]int
	var selected [2][]packetRecord
	seen := map[string]int{}
	packetCounts := map[string]int{}
	for wan, items := range logs {
		wantSource := "192.0.2.9"
		if wan == 1 {
			wantSource = "198.51.100.99"
		}
		for _, r := range items {
			if !strings.HasPrefix(r.Flow, prefix+"-") {
				continue
			}
			selected[wan] = append(selected[wan], r)
			if r.Source != wantSource {
				t.Errorf("%s via WAN %d has source %s, want %s", r.Flow, wan, r.Source, wantSource)
			}
			if previous, ok := seen[r.Flow]; ok && previous != wan {
				t.Errorf("flow %s crossed WANs", r.Flow)
			}
			if _, ok := seen[r.Flow]; !ok {
				counts[wan]++
			}
			seen[r.Flow] = wan
			packetCounts[r.Flow]++
		}
	}
	if len(seen) != wantFlows {
		t.Errorf("%s: observed %d/%d flows", prefix, len(seen), wantFlows)
	}
	for id, n := range packetCounts {
		if n != wantPackets {
			t.Errorf("%s: %d/%d packets", id, n, wantPackets)
		}
	}
	t.Logf("%s packet evidence: WAN A=%d flows, WAN B=%d flows", prefix, counts[0], counts[1])
	return counts, selected
}

func TestNamespacePacketEgress(t *testing.T) {
	requireDisposableVM(t)
	runPacketEgress(t, NewTestNamespace)
}

func TestRootlessPacketEgress(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatalf("rootless isolation BLOCKED: %v", err)
	}
	runPacketEgress(t, NewRootlessTestNamespace)
}

// The helper intentionally exits without defer/Cleanup so a second process
// must discover and reconcile its journal and namespace registry entries.
func TestRootlessCrashHelper(t *testing.T) {
	if os.Getenv("FBI_GO_CRASH_HELPER") != "1" {
		t.Skip("crash helper")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatal(err)
	}
	client, err := NewRootlessTestNamespace()
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewRootlessTestNamespace()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewRootlessTestNamespace()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range []struct {
		ns                                 *NamespaceEngine
		clientIf, peerIf, clientIP, peerIP string
	}{{a, "fbi_ca", "fbi_aa", "192.0.2.9/24", "192.0.2.1/24"}, {b, "fbi_cb", "fbi_bb", "198.51.100.99/24", "198.51.100.216/24"}} {
		labRun(t, client, "ip", "link", "add", peer.clientIf, "type", "veth", "peer", "name", peer.peerIf)
		labRun(t, client, "ip", "link", "set", peer.peerIf, "netns", peer.ns.Name())
		labRun(t, client, "ip", "addr", "add", peer.clientIP, "dev", peer.clientIf)
		labRun(t, peer.ns, "ip", "addr", "add", peer.peerIP, "dev", peer.peerIf)
		labRun(t, client, "ip", "link", "set", peer.clientIf, "up")
		labRun(t, peer.ns, "ip", "link", "set", peer.peerIf, "up")
	}
	p := M2Plan{SafeToApply: true, NFTTable: client.TableName(), IPv6Policy: "system", WANs: []Allocation{
		{Interface: "fbi_ca", Gateway: "192.0.2.1", SourceCIDR: "192.0.2.9/24", SourceIP: "192.0.2.9", Weight: 3, Table: 30000, Priority: 15000, Mark: 0x40000001},
		{Interface: "fbi_cb", Gateway: "198.51.100.216", SourceCIDR: "198.51.100.99/24", SourceIP: "198.51.100.99", Weight: 1, Table: 30001, Priority: 15001, Mark: 0x40000002},
	}}
	stage := os.Getenv("FBI_GO_CRASH_STAGE")
	if stage != "" {
		client.afterStage = func(current string) {
			if current == stage {
				if stage == "after-intent" || stage == "before-nft-batch" || stage == "after-nft-batch" || stage == "after-nft-modified" || stage == "during-snapshot" || stage == "rolling-back" || strings.HasPrefix(stage, "ipv6-") {
					if stage == "after-nft-batch" {
						if _, err := client.run("", "nft", "add", "table", "ip", "fbi_foreign_probe"); err != nil {
							t.Fatal(err)
						}
					}
					if stage == "after-nft-modified" {
						if _, err := client.run("", "nft", "add", "rule", "ip", p.NFTTable, "output", "counter"); err != nil {
							t.Fatal(err)
						}
					}
					_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
				}
				os.Exit(77)
			}
		}
		if stage == "rolling-back" {
			client.failAfter = 5
		}
	}
	if err := client.Apply(p); err != nil {
		t.Fatal(err)
	}
	if stage == "ipv6-install-fail" {
		client.failCommand = "nft -f"
		if err := client.InstallIPv6Guard(); err == nil {
			t.Fatal("injected guard installation failure was ignored")
		}
		os.Exit(77)
	}
	if strings.HasPrefix(stage, "ipv6-") {
		if err := client.InstallIPv6Guard(); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(77)
}

func TestRootlessIPv6GuardCrashRecovery(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("FBI_GO_JOURNAL_DIR")
	for _, stage := range []string{"ipv6-install-fail", "ipv6-after-intent", "ipv6-after-batch", "ipv6-before-snapshot", "ipv6-after-snapshot"} {
		t.Run(stage, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRootlessCrashHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "FBI_GO_CRASH_HELPER=1", "FBI_GO_CRASH_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			wantExit := -1
			if stage == "ipv6-install-fail" {
				wantExit = 77
			}
			if !errors.As(err, &exit) || exit.ExitCode() != wantExit {
				t.Fatalf("IPv6 crash helper did not SIGKILL at %s: %v: %s", stage, err, out)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				j, err := loadJournal(filepath.Join(dir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if j.IPv6GuardIntent {
					found = true
					if j.IPv6GuardHash == "" {
						t.Fatal("guard intent has no durable fingerprint")
					}
				}
			}
			if !found {
				t.Fatal("SIGKILL left no IPv6 guard ownership intent")
			}
			if err := ReconcileIsolatedJournals(); err != nil {
				t.Fatalf("exact-match guard recovery at %s: %v", stage, err)
			}
			entries, err = os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					t.Fatalf("recovery left journal %s", entry.Name())
				}
			}
		})
	}
}

func TestRootlessCrashRecovery(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("FBI_GO_JOURNAL_DIR")
	for _, stage := range []string{"before-intent", "after-intent", "before-first", "after-route", "after-rule", "before-nft-batch", "after-nft-batch", "after-nft-modified", "during-snapshot", "after-snapshot", "after-nft", "during-verification", "after-verification", "rolling-back", "after-commit", "active"} {
		t.Run(stage, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRootlessCrashHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "FBI_GO_CRASH_HELPER=1", "FBI_GO_CRASH_STAGE="+stage)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			killed := stage == "after-intent" || stage == "before-nft-batch" || stage == "after-nft-batch" || stage == "after-nft-modified" || stage == "during-snapshot" || stage == "rolling-back"
			if !errors.As(err, &exit) || (!killed && exit.ExitCode() != 77) || (killed && exit.ExitCode() != -1) {
				t.Fatalf("crash helper did not terminate at %s: %v: %s", stage, err, out)
			}
			entries, err := os.ReadDir(dir)
			journalCount := 0
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".json") {
					journalCount++
				}
			}
			if err != nil || journalCount != 3 {
				t.Fatalf("%s: expected three durable ownership records: %v %+v", stage, err, entries)
			}
			if stage == "after-intent" {
				found := false
				for _, entry := range entries {
					if !strings.HasSuffix(entry.Name(), ".json") {
						continue
					}
					j, err := loadJournal(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if j.Plan != nil {
						found = true
						if j.Phase != "applying" || j.OperationID == "" || j.NFTScriptHash == "" || j.NFTState != "" {
							t.Fatalf("durable pre-mutation intent invalid: %+v", j)
						}
					}
				}
				if !found {
					t.Fatal("SIGKILL left no durable apply intent")
				}
			}
			if stage == "after-nft-batch" || stage == "after-nft-modified" || stage == "during-snapshot" {
				var pending ownershipJournal
				for _, entry := range entries {
					if !strings.HasSuffix(entry.Name(), ".json") {
						continue
					}
					j, err := loadJournal(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if j.NFTState == "" && j.Plan != nil {
						pending = j
					}
				}
				if pending.OperationID == "" {
					t.Fatal("missing durable nftables intent")
				}
				out, err := exec.Command("ip", "netns", "exec", pending.Name, "nft", "-j", "list", "table", "ip", pending.NFTTable).CombinedOutput()
				if err != nil || nftTableComment(string(out)) != "fbi-go:"+pending.OperationID {
					t.Fatalf("post-crash nftables ownership token unavailable: %v %s", err, out)
				}
				decision := "MANUAL_INTERVENTION_REQUIRED"
				if stage == "after-nft-modified" {
					decision = "CONFLICT"
				}
				if err := ReconcileIsolatedJournals(); err == nil || !strings.Contains(err.Error(), decision) {
					t.Fatalf("recovery must refuse with %s: %v", decision, err)
				}
				rules, err := exec.Command("ip", "netns", "exec", pending.Name, "ip", "-4", "rule", "show").CombinedOutput()
				if err != nil {
					t.Fatalf("post-refusal rule inspection: %v %s", err, rules)
				}
				for _, w := range pending.Plan.WANs {
					priority := strconv.Itoa(w.Priority) + ":"
					count := 0
					for _, line := range strings.Split(string(rules), "\n") {
						if strings.HasPrefix(strings.TrimSpace(line), priority) {
							count++
							if !hasFWMark(strings.Fields(line), w.Mark) {
								t.Fatalf("mark changed after refused recovery: %s", line)
							}
						}
					}
					if count != 1 {
						t.Fatalf("expected one owned rule at priority %d after refused recovery, found %d", w.Priority, count)
					}
				}
				if stage == "after-nft-batch" {
					out, err := exec.Command("ip", "netns", "exec", pending.Name, "nft", "list", "tables").CombinedOutput()
					if err != nil || !hasNFTTable(string(out), "fbi_foreign_probe") {
						t.Fatalf("foreign test table removed by refused recovery: %v %s", err, out)
					}
					if out, err := exec.Command("ip", "netns", "exec", pending.Name, "nft", "delete", "table", "ip", "fbi_foreign_probe").CombinedOutput(); err != nil {
						t.Fatalf("foreign test table cleanup: %v %s", err, out)
					}
				}
				// The test has independently inspected its own namespace and token.
				// Remove this test-owned table, then let normal recovery clear routes/rules.
				if out, err := exec.Command("ip", "netns", "exec", pending.Name, "nft", "delete", "table", "ip", pending.NFTTable).CombinedOutput(); err != nil {
					t.Fatalf("test table cleanup: %v %s", err, out)
				}
			}
			if err := ReconcileIsolatedJournals(); err != nil {
				t.Fatalf("%s: stale owned resources not recovered: %v", stage, err)
			}
			entries, err = os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("%s: journals remain after recovery: %v %+v", stage, err, entries)
			}
			if names := labRegistryNames(); len(names) != 0 {
				t.Fatalf("%s: owned namespace registry not empty: %v", stage, names)
			}
		})
	}
	if err := ReconcileIsolatedJournals(); err != nil {
		t.Fatalf("repeated reconciliation failed: %v", err)
	}
	lockDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lockDir.Close()
	if err := syscall.Flock(int(lockDir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileIsolatedJournals(); err == nil || !strings.Contains(err.Error(), "RECOVERY_BUSY") {
		t.Fatalf("concurrent recovery not rejected: %v", err)
	}
	if err := syscall.Flock(int(lockDir.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func labRegistryNames() []string {
	entries, err := os.ReadDir("/run/netns")
	if err != nil {
		return []string{err.Error()}
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func runPacketEgress(t *testing.T, create func() (*NamespaceEngine, error)) {
	client, err := create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("client cleanup: %v", err)
		}
	})
	a, err := create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Errorf("WAN A cleanup: %v", err)
		}
	})
	b, err := create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("WAN B cleanup: %v", err)
		}
	})
	labRun(t, client, "ip", "link", "set", "lo", "up")
	// Reverse-path filtering can drop the WAN B replies because the lab's
	// ordinary default route points to WAN A. These sysctls exist only here.
	labRun(t, client, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
	labRun(t, client, "sysctl", "-q", "-w", "net.ipv4.conf.default.rp_filter=0")
	for _, peer := range []struct {
		ns                                 *NamespaceEngine
		clientIf, peerIf, clientIP, peerIP string
	}{{a, "fbi_ca", "fbi_aa", "192.0.2.9/24", "192.0.2.1/24"}, {b, "fbi_cb", "fbi_bb", "198.51.100.99/24", "198.51.100.216/24"}} {
		labRun(t, client, "ip", "link", "add", peer.clientIf, "type", "veth", "peer", "name", peer.peerIf)
		labRun(t, client, "ip", "link", "set", peer.peerIf, "netns", peer.ns.Name())
		labRun(t, client, "ip", "addr", "add", peer.clientIP, "dev", peer.clientIf)
		labRun(t, peer.ns, "ip", "addr", "add", peer.peerIP, "dev", peer.peerIf)
		labRun(t, client, "ip", "link", "set", peer.clientIf, "up")
		labRun(t, peer.ns, "ip", "link", "set", peer.peerIf, "up")
		labRun(t, peer.ns, "ip", "link", "set", "lo", "up")
		labRun(t, peer.ns, "ip", "addr", "add", "203.0.113.7/32", "dev", "lo")
		checkLabLink(t, client, peer.clientIf, peer.clientIP)
		checkLabLink(t, peer.ns, peer.peerIf, peer.peerIP)
		gateway, _, err := net.ParseCIDR(peer.peerIP)
		if err != nil {
			t.Fatal(err)
		}
		connected := labRun(t, client, "ip", "-4", "route", "get", gateway.String())
		if !strings.Contains(connected, "dev "+peer.clientIf) {
			t.Fatalf("gateway %s lacks connected route on %s: %s", gateway, peer.clientIf, connected)
		}
		labRun(t, client, "ping", "-I", peer.clientIf, "-c", "1", "-W", "1", gateway.String())
	}
	labRun(t, client, "ip", "route", "add", "default", "via", "192.0.2.1", "dev", "fbi_ca")
	in := Inventory{RulesComplete: true, TablesComplete: true, MarksComplete: true, NFTComplete: true, IPv6Policy: "system", WANHealth: map[string]health.State{"fbi_ca": health.Healthy, "fbi_cb": health.Healthy}, Snapshot: network.Snapshot{Devices: []network.Device{{Name: "fbi_ca", State: "up", Candidate: true, Addresses: []string{"192.0.2.9/24"}}, {Name: "fbi_cb", State: "up", Candidate: true, Addresses: []string{"198.51.100.99/24"}}}, Routes: []network.Route{{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "fbi_ca", Table: 254}, {Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "198.51.100.216", Interface: "fbi_cb", Table: 254}}}}
	p := PlanM2(in)
	if !p.SafeToApply {
		t.Fatal(p.Reasons)
	}
	p.NFTTable = client.TableName()
	p.WANs[0].Weight = 3
	p.WANs[1].Weight = 1
	// Occupied-resource preflight must refuse without touching the fixture.
	table := strconv.Itoa(p.WANs[0].Table)
	labRun(t, client, "ip", "route", "add", "table", table, "203.0.113.128/25", "dev", "fbi_ca")
	if err := client.Apply(p); err == nil {
		t.Fatal("occupied table accepted")
	}
	labRun(t, client, "ip", "route", "del", "table", table, "203.0.113.128/25", "dev", "fbi_ca")
	client.failCommand = "ip -4 route add table " + strconv.Itoa(p.WANs[1].Table)
	if err := client.Apply(p); err == nil || !strings.Contains(err.Error(), "injected kernel command failure") {
		t.Fatalf("injected command failure not propagated: %v", err)
	}
	if client.journalPhase != "created" {
		t.Fatalf("command failure left journal phase %q", client.journalPhase)
	}
	// Every route/rule step, the nft batch, and verification have a private,
	// deterministic fault boundary. None is exposed through IPC or CLI.
	for fault := 1; fault <= 10; fault++ {
		client.failAfter = fault
		if err := client.Apply(p); err == nil {
			t.Fatalf("fault %d ignored", fault)
		}
		if client.journalPhase != "created" {
			t.Fatalf("fault %d left journal phase %q", fault, client.journalPhase)
		}
		for _, w := range p.WANs {
			if out := labRouteTable(t, client, "rollback verification", 4, w.Table, true); strings.TrimSpace(out) != "" {
				t.Fatalf("fault %d left route: %s", fault, out)
			}
			if rules := labRun(t, client, "ip", "-4", "rule", "show"); strings.Contains(rules, fmt.Sprintf("%d:", w.Priority)) {
				t.Fatalf("fault %d left owned priority %d: %s", fault, w.Priority, rules)
			}
		}
		if out := labRun(t, client, "nft", "list", "tables"); strings.TrimSpace(out) != "" {
			t.Fatalf("fault %d left nftables table: %s", fault, out)
		}
	}
	client.failAfter = 0
	apply := client.Apply
	var isolated *IsolatedExecutor
	if client.rootless {
		isolated, err = NewIsolatedExecutor(client)
		if err != nil {
			t.Fatal(err)
		}
		if isolated.State() != StateCleaned {
			t.Fatalf("post-rollback executor state=%s", isolated.State())
		}
		apply = isolated.Apply
	}
	if isolated != nil {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); results <- isolated.Apply(p) }()
		}
		wg.Wait()
		close(results)
		ok, refused := 0, 0
		for err := range results {
			if err == nil {
				ok++
			} else if strings.Contains(err.Error(), "already has an applied") {
				refused++
			} else {
				t.Fatalf("concurrent apply: %v", err)
			}
		}
		if ok != 1 || refused != 1 {
			t.Fatalf("concurrent applies: success=%d refusal=%d", ok, refused)
		}
	} else if err := apply(p); err != nil {
		logLabDiagnostics(t, client)
		t.Fatal(err)
	}
	if isolated != nil {
		if err := isolated.Verify(); err != nil {
			t.Fatalf("installed resource verification: %v", err)
		}
		if isolated.State() != StateActive {
			t.Fatalf("executor state=%s, want ACTIVE", isolated.State())
		}
	}
	for _, w := range p.WANs {
		routes := labRouteTable(t, client, "post-apply verification", 4, w.Table, false)
		if err := verifyRequiredRoutes(w, routes); err != nil {
			t.Fatal(err)
		}
		route := labRun(t, client, "ip", "-4", "route", "get", "203.0.113.7", "mark", fmt.Sprintf("%#x", w.Mark))
		if !strings.Contains(route, "dev "+w.Interface) || !strings.Contains(route, "src "+w.SourceIP) {
			t.Errorf("mark %#x resolved through wrong route/source: %s", w.Mark, route)
		}
	}
	if err := client.Apply(p); err == nil {
		t.Fatal("duplicate apply accepted")
	}
	labRun(t, client, "ping", "-c", "1", "-W", "1", "192.0.2.1") // local subnet must bypass balancing
	labRun(t, client, "ping", "-c", "1", "-W", "1", "198.51.100.216")
	// The foreign rule is inserted only in the disposable client namespace.
	labRun(t, client, "ip", "-4", "rule", "add", "priority", "9000", "fwmark", "0x2023/0xffffffff", "lookup", "main")
	foreignBefore := labRun(t, client, "ip", "-4", "rule", "show")
	labRun(t, client, "ip", "-4", "route", "add", "table", "31001", "203.0.113.128/25", "dev", "fbi_ca")
	foreignRouteBefore := labRun(t, client, "ip", "-4", "route", "show", "table", "31001")
	foreignTable := "fbi_foreign_" + strings.TrimPrefix(client.TableName(), "fbi_m2t_")
	foreignScript := fmt.Sprintf("add table ip %s\nadd chain ip %s output { type filter hook output priority -149; policy accept; }\nadd rule ip %s output meta mark 0x2023 counter\n", foreignTable, foreignTable, foreignTable)
	if _, err := client.run(foreignScript, "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	evidence := os.Getenv("FBI_GO_EVIDENCE_DIR")
	if evidence == "" {
		evidence = t.TempDir()
	} else {
		if err := os.MkdirAll(evidence, 0700); err != nil {
			t.Fatal(err)
		}
	}
	paths := [2]string{filepath.Join(evidence, client.Name()+"-wan-a.jsonl"), filepath.Join(evidence, client.Name()+"-wan-b.jsonl")}
	serverPath, err := filepath.Abs("testdata/flow_server.py")
	if err != nil {
		t.Fatal(err)
	}
	for i, ns := range []*NamespaceEngine{a, b} {
		cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "python3", serverPath, "203.0.113.7", "49494", paths[i])
		cmd.ExtraFiles = []*os.File{ns.fd}
		serverOutput, err := os.Create(paths[i] + ".stderr")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = serverOutput
		cmd.Stderr = serverOutput
		if err := cmd.Start(); err != nil {
			_ = serverOutput.Close()
			t.Fatal(err)
		}
		_ = serverOutput.Close()
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, e1 := os.Stat(paths[0]); e1 == nil {
			if _, e2 := os.Stat(paths[1]); e2 == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			for _, path := range paths {
				if output, err := os.ReadFile(path + ".stderr"); err == nil && len(output) > 0 {
					t.Logf("receiver stderr %s: %s", path, output)
				}
			}
			t.Fatal("receiver startup timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
	clientPath, err := filepath.Abs("testdata/flow_client.py")
	if err != nil {
		t.Fatal(err)
	}
	send := func(proto, prefix string, count int, mark string) {
		args := []string{"python3", clientPath, proto, prefix, strconv.Itoa(count)}
		if mark != "" {
			args = append(args, mark)
		}
		labRun(t, client, args...)
	}
	await := func(prefix string, wantFlows, wantPackets int) {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			logs := labRecords(t, paths)
			seen := map[string]bool{}
			packets := 0
			for _, items := range logs {
				for _, r := range items {
					if strings.HasPrefix(r.Flow, prefix+"-") {
						seen[r.Flow] = true
						packets++
					}
				}
			}
			if len(seen) >= wantFlows && packets >= wantFlows*wantPackets {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		for _, path := range paths {
			if output, err := os.ReadFile(path + ".stderr"); err == nil && len(output) > 0 {
				t.Logf("receiver stderr %s: %s", path, output)
			}
		}
		t.Fatalf("timeout waiting for %s evidence", prefix)
	}
	send("udp", "weighted", 400, "")
	await("weighted", 400, 3)
	logs := labRecords(t, paths)
	weighted, _ := verifyStage(t, logs, "weighted", 400, 3)
	if weighted[0] < 240 || weighted[0] > 360 || weighted[1] == 0 {
		t.Errorf("3:1 weighted distribution outside broad expected range: %v", weighted)
	}
	send("tcp", "tcp", 100, "")
	await("tcp", 100, 1)
	logs = labRecords(t, paths)
	tcp, intervals := verifyStage(t, logs, "tcp", 100, 1)
	if tcp[0] == 0 || tcp[1] == 0 {
		t.Error("TCP did not use both WANs")
	}
	overlap := false
	for _, x := range intervals[0] {
		for _, y := range intervals[1] {
			if x.StartNS < y.EndNS && y.StartNS < x.EndNS {
				overlap = true
				break
			}
		}
	}
	if !overlap {
		t.Error("no observed concurrent TCP flows across WANs")
	}
	send("tcp_affinity", "tcp-affinity", 20, "")
	await("tcp-affinity", 20, 3)
	logs = labRecords(t, paths)
	_, tcpAffinity := verifyStage(t, logs, "tcp-affinity", 20, 3)
	ports := map[string]int{}
	for _, records := range tcpAffinity {
		for _, r := range records {
			if prior, ok := ports[r.Flow]; ok && prior != r.Port {
				t.Errorf("TCP connection %s changed source port from %d to %d", r.Flow, prior, r.Port)
			}
			ports[r.Flow] = r.Port
		}
	}
	send("udp", "foreign", 20, "0x2023")
	await("foreign", 20, 3)
	logs = labRecords(t, paths)
	foreign, _ := verifyStage(t, logs, "foreign", 20, 3)
	if foreign[1] != 0 {
		t.Errorf("foreign marked flows entered balancing: %v", foreign)
	}
	markEvidence := labRun(t, client, "nft", "list", "chain", "ip", foreignTable, "output")
	match := regexp.MustCompile(`counter packets ([0-9]+)`).FindStringSubmatch(markEvidence)
	if len(match) != 2 {
		t.Errorf("foreign mark counter missing: %s", markEvidence)
	} else if n, _ := strconv.Atoi(match[1]); n < 20 {
		t.Errorf("foreign packet mark not preserved for all flows: %s", markEvidence)
	}
	if err := client.UpdateWeights(map[string]int{"fbi_ca": 1, "fbi_cb": 0}); err != nil {
		t.Fatal(err)
	}
	send("udp", "disabled", 100, "")
	await("disabled", 100, 3)
	logs = labRecords(t, paths)
	disabled, _ := verifyStage(t, logs, "disabled", 100, 3)
	if disabled[1] != 0 {
		t.Errorf("disabled WAN received new flows: %v", disabled)
	}
	if err := client.UpdateWeights(map[string]int{"fbi_ca": 3, "fbi_cb": 1}); err != nil {
		t.Fatal(err)
	}
	send("udp", "recovered", 200, "")
	await("recovered", 200, 3)
	logs = labRecords(t, paths)
	recovered, _ := verifyStage(t, logs, "recovered", 200, 3)
	if recovered[1] == 0 {
		t.Error("recovered WAN received no new flows")
	}
	// A managed-flow mark pinned to B must not fall through to the healthy A
	// route when B's gateway route disappears. Application classification is M3.
	strictWAN := p.WANs[1]
	labRun(t, client, "ip", "-4", "route", "del", "table", strconv.Itoa(strictWAN.Table), "default", "via", strictWAN.Gateway, "dev", strictWAN.Interface)
	strictRoutes := labRouteTable(t, client, "strict fail-closed", 4, strictWAN.Table, false)
	if !strings.Contains(strictRoutes, "unreachable default") {
		t.Fatalf("pinned table lost unreachable fallback: %s", strictRoutes)
	}
	strictProbe, err := filepath.Abs("testdata/strict_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	labRun(t, client, "python3", strictProbe, fmt.Sprintf("%#x", strictWAN.Mark))
	labRun(t, client, "ping", "-I", "fbi_ca", "-c", "1", "-W", "1", "192.0.2.1")
	logs = labRecords(t, paths)
	for _, records := range logs {
		for _, r := range records {
			if r.Flow == "strict-leak" {
				t.Error("STRICT flow escaped through another WAN")
			}
		}
	}
	disable := client.Disable
	if isolated != nil {
		disable = isolated.Rollback
	}
	if err := disable(); err != nil {
		t.Fatal(err)
	}
	if isolated != nil && isolated.State() != StateCleaned {
		t.Fatalf("post-disable executor state=%s", isolated.State())
	}
	if err := disable(); err != nil {
		t.Fatal(err)
	}
	if out := labRun(t, client, "nft", "list", "tables"); strings.Contains(out, p.NFTTable) || !strings.Contains(out, foreignTable) {
		t.Errorf("cleanup changed unrelated nftables ownership: %s", out)
	}
	for _, w := range p.WANs {
		if out := labRouteTable(t, client, "post-disable verification", 4, w.Table, true); strings.TrimSpace(out) != "" {
			t.Errorf("owned routing table remains: %s", out)
		}
	}
	foreignAfter := labRun(t, client, "ip", "-4", "rule", "show")
	for _, w := range p.WANs {
		if strings.Contains(foreignAfter, fmt.Sprintf("%d:", w.Priority)) {
			t.Errorf("owned policy rule %d remains", w.Priority)
		}
	}
	findForeign := func(s string) string {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "9000:") {
				return line
			}
		}
		return ""
	}
	if findForeign(foreignBefore) == "" || findForeign(foreignBefore) != findForeign(foreignAfter) {
		t.Error("foreign rule changed by cleanup")
	}
	if route := labRun(t, client, "ip", "-4", "route", "show", "table", "31001"); route != foreignRouteBefore {
		t.Errorf("foreign route changed by cleanup: before=%q after=%q", foreignRouteBefore, route)
	}
	name := client.Name()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join("/run/netns", name)); !os.IsNotExist(err) {
		t.Errorf("owned namespace still listed: %v", err)
	}
	t.Logf("raw packet evidence: %s and %s", paths[0], paths[1])
	t.Log(fmt.Sprintf("weighted=%v tcp=%v disabled=%v recovered=%v", weighted, tcp, disabled, recovered))
}
