package routing

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"os"
	"strings"
	"testing"
)

type fakeRouteExit int

func (e fakeRouteExit) Error() string { return "ip route failed" }
func (e fakeRouteExit) ExitCode() int { return int(e) }

func TestRouteTableReadContexts(t *testing.T) {
	missing4 := "Error: ipv4: FIB table does not exist.\nDump terminated\n"
	missing6 := "Error: ipv6: FIB table does not exist.\nDump terminated\n"
	routes := "192.0.2.0/24 dev fbi_ca scope link src 192.0.2.9\n"
	for _, tc := range []struct {
		name         string
		family       int
		output       string
		err          error
		allowMissing bool
		want         string
		wantErr      bool
	}{
		{"missing custom table during preflight", 4, missing4, fmt.Errorf("ip: %w", fakeRouteExit(2)), true, "", false},
		{"missing IPv6 custom table during preflight", 6, missing6, fakeRouteExit(2), true, "", false},
		{"existing empty table", 4, "", nil, true, "", false},
		{"existing table with routes", 4, routes, nil, true, routes, false},
		{"unexpected permission error", 4, "RTNETLINK answers: Operation not permitted", fakeRouteExit(2), true, "", true},
		{"unexpected command failure", 4, "", errors.New("command not found"), true, "", true},
		{"missing table after apply", 4, missing4, fakeRouteExit(2), false, "", true},
		{"absent owned table after rollback", 4, missing4, fakeRouteExit(2), true, "", false},
		{"wrong exit code", 4, missing4, fakeRouteExit(1), true, "", true},
		{"wrong address family", 4, missing6, fakeRouteExit(2), true, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeRouteTableRead(tc.family, tc.output, tc.err, tc.allowMissing)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("output=%q err=%v", got, err)
			}
		})
	}
	if _, err := (&NamespaceEngine{}).readRouteTable(4, 0, true); err == nil {
		t.Fatal("invalid table ID accepted")
	}
	if err := requireUnoccupiedTable(30001, ""); err != nil {
		t.Fatal("empty table rejected:", err)
	}
	if err := requireUnoccupiedTable(30001, routes); err == nil {
		t.Fatal("occupied table accepted")
	}
}

func TestRequiredRoutesAfterApply(t *testing.T) {
	w := Allocation{Table: 30001, Interface: "fbi_cb", SourceCIDR: "198.51.100.99/24", SourceIP: "198.51.100.99", Gateway: "198.51.100.216"}
	connected := "198.51.100.0/24 dev fbi_cb scope link src 198.51.100.99\n"
	if err := verifyRequiredRoutes(w, connected); err == nil {
		t.Fatal("missing default route accepted")
	}
	if err := verifyRequiredRoutes(w, ""); err == nil {
		t.Fatal("missing owned table accepted")
	}
	if err := verifyRequiredRoutes(w, connected+"default via 198.51.100.216 dev fbi_cb src 198.51.100.99\n"); err != nil {
		t.Fatal(err)
	}
}

func TestFedoraTopologyNoCollision(t *testing.T) {
	b, e := os.ReadFile("testdata/fedora_topology.json")
	if e != nil {
		t.Fatal(e)
	}
	var in Inventory
	if e = json.Unmarshal(b, &in); e != nil {
		t.Fatal(e)
	}
	noCarrier := false
	for _, d := range in.Snapshot.Devices {
		if d.Name == "eno9" {
			noCarrier = d.AdminUp && d.Carrier != nil && !*d.Carrier && d.State == "down" && !d.Candidate
		}
	}
	if !noCarrier {
		t.Fatal("missing disconnected admin-UP interface in fixture")
	}
	p := PlanM2(in)
	defaults := 0
	ipv6Defaults := 0
	for _, r := range in.Snapshot.Routes {
		if r.Family == "ipv4" && r.Destination == "0.0.0.0/0" && r.Table == 254 {
			defaults++
			if r.Metric != 100 {
				t.Fatal("unequal fixture default metrics")
			}
		}
		if r.Family == "ipv6" && r.Destination == "::/0" {
			ipv6Defaults++
		}
	}
	if defaults != 2 || ipv6Defaults != 1 {
		t.Fatal("fixture topology incomplete")
	}
	if p.SafeToApply || len(p.WANs) != 2 {
		t.Fatalf("expected VPN rejection and two proposed allocations: %+v", p)
	}
	if p.WANs[0].Table == p.WANs[1].Table || p.WANs[0].Priority == p.WANs[1].Priority || p.WANs[0].Mark == p.WANs[1].Mark {
		t.Fatal("allocation collision")
	}
	for _, w := range p.WANs {
		if w.Table == 2022 || w.Table == 1245622400 || w.Priority == 1 || w.Priority == 9000 || w.Priority == 9001 || w.Priority == 9002 || w.Priority == 32768 || w.Mark == 0x2023 || w.Mark == 0x2024 {
			t.Fatalf("foreign resource reused: %+v", w)
		}
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "IPv6") {
		t.Fatal("missing IPv6 warning")
	}
	in.VPNPresent = false
	in.WANHealth = map[string]health.State{"wifi0": health.Healthy, "usb0": health.Healthy}
	for i, d := range in.Snapshot.Devices {
		if d.Kind == "vpn" {
			in.Snapshot.Devices = append(in.Snapshot.Devices[:i], in.Snapshot.Devices[i+1:]...)
			break
		}
	}
	p = PlanM2(in)
	if !p.SafeToApply {
		t.Fatal(p.Reasons)
	}
	script, e := NFTScript(p)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(script, "meta mark != 0 return") || !strings.Contains(script, "ct mark set meta mark") {
		t.Fatal(script)
	}
	if !strings.Contains(script, "ip daddr 192.0.2.0/24 return") || !strings.Contains(script, "ip daddr 198.51.100.0/24 return") {
		t.Fatal("WAN-local subnets are not excluded")
	}
	in.UsedTables = append(in.UsedTables, 30000)
	in.Rules = append(in.Rules, Rule{Priority: 15000, Table: 30000, Mark: 0x40000001, Mask: 0xffffffff, HasMark: true})
	in.ForeignMarks = append(in.ForeignMarks, 0x40000001)
	p = PlanM2(in)
	if !p.SafeToApply {
		t.Fatal(p.Reasons)
	}
	for _, w := range p.WANs {
		if w.Table == 30000 || w.Priority == 15000 || w.Mark == 0x40000001 {
			t.Fatalf("occupied resource allocated: %+v", w)
		}
	}
}

func TestM2FailsClosed(t *testing.T) {
	p := PlanM2(Inventory{})
	if p.SafeToApply {
		t.Fatal("incomplete inventory accepted")
	}
}

func TestNamespaceOwnershipGuard(t *testing.T) {
	p := M2Plan{SafeToApply: true, NFTTable: "fbi_m2t_test", IPv6Policy: "system", WANs: []Allocation{{Interface: "a", Gateway: "192.0.2.1", SourceCIDR: "192.0.2.9/24", SourceIP: "192.0.2.9", Weight: 1, Table: 30000, Priority: 15000, Mark: 0x40000001}, {Interface: "b", Gateway: "198.51.100.1", SourceCIDR: "198.51.100.9/24", SourceIP: "198.51.100.9", Weight: 1, Table: 30001, Priority: 15001, Mark: 0x40000002}}}
	if err := (&NamespaceEngine{}).Apply(p); err == nil {
		t.Fatal("zero-value engine applied to arbitrary namespace")
	}
	if err := validateNamespacePlan(p, "fbi_m2t_other"); err == nil {
		t.Fatal("foreign NFT table accepted")
	}
	p.WANs[1].Table = p.WANs[0].Table
	if err := validateNamespacePlan(p, p.NFTTable); err == nil {
		t.Fatal("duplicate table accepted")
	}
}

func TestRootlessNamespaceGuardRejectsUnlaunchedProcess(t *testing.T) {
	t.Setenv("FBI_GO_ROOTLESS_TEST", "")
	t.Setenv("FBI_GO_PARENT_NETNS", "")
	t.Setenv("FBI_GO_PARENT_USERNS", "")
	if _, err := NewRootlessTestNamespace(); err == nil {
		t.Fatal("rootless namespace constructor accepted a process outside the launcher")
	}
}

func TestRootlessProbeInitializesLinkBeforeRoute(t *testing.T) {
	b, err := os.ReadFile("../../scripts/test-rootless-netns.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(b)
	steps := []string{
		"probe 'veth move to owned child namespace'",
		"probe 'client veth exists after move'",
		"probe 'gateway veth exists after move'",
		"probe 'client IPv4 address'",
		"probe 'gateway IPv4 address'",
		"probe 'client veth up'",
		"probe 'gateway veth up'",
		"probe 'client link and address validation'",
		"probe 'gateway link and address validation'",
		"probe 'gateway reachability'",
		"probe 'route add'",
	}
	previous := -1
	for _, step := range steps {
		at := strings.Index(script, step)
		if at <= previous {
			t.Fatalf("missing or out-of-order rootless probe step %q", step)
		}
		previous = at
	}
	if strings.Contains(script, " onlink") {
		t.Fatal("probe must not bypass gateway reachability with onlink")
	}
}

func TestWeightUpdateKeepsRestoreRules(t *testing.T) {
	p := M2Plan{SafeToApply: true, NFTTable: "fbi_m2t_test", WANs: []Allocation{{Interface: "a", SourceCIDR: "192.0.2.9/24", SourceIP: "192.0.2.9", Weight: 3, Mark: 0x40000001}, {Interface: "b", SourceCIDR: "198.51.100.9/24", SourceIP: "198.51.100.9", Weight: 0, Mark: 0x40000002}}}
	s, e := NFTWeightUpdate(p)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(s, "flush chain ip fbi_m2t_test output") || !strings.Contains(s, "ct mark 0x40000002 meta mark set ct mark") || strings.Contains(s, "0 : 0x40000002") || strings.Contains(s, "1 : 0x40000002") || strings.Contains(s, "2 : 0x40000002") {
		t.Fatal(s)
	}
	if strings.Index(s, "meta mark != 0 return") > strings.Index(s, "ct mark 0x40000001") {
		t.Fatal("foreign mark guard must precede restore")
	}
}

func TestExactCleanupMatching(t *testing.T) {
	if !hasFWMark(strings.Fields("15000: from all fwmark 0x40000001/0xffffffff lookup 30000"), 0x40000001) {
		t.Fatal("full mask not recognized")
	}
	if hasFWMark(strings.Fields("15000: from all fwmark 0x400000011 lookup 30000"), 0x40000001) {
		t.Fatal("prefix collision accepted")
	}
	if !hasFieldPair(strings.Fields("default via 192.0.2.1 dev a src 192.0.2.9"), "src", "192.0.2.9") {
		t.Fatal("exact source not recognized")
	}
}

func TestVirtualTunnelDetected(t *testing.T) {
	if !isLikelyTunnel("throne-tun", []network.Route{{Interface: "throne-tun", Table: 2022}}) {
		t.Fatal("TUN hidden by generic virtual classification")
	}
	if isLikelyTunnel("docker0", []network.Route{{Interface: "docker0", Table: 254}}) {
		t.Fatal("Docker bridge mistaken for VPN")
	}
}

func TestOnlyDefaultRules(t *testing.T) {
	if err := onlyDefaultRules("0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"); err != nil {
		t.Fatal(err)
	}
	if err := onlyDefaultRules("9000: from all fwmark 0x2023 lookup 2022\n"); err == nil {
		t.Fatal("foreign policy rule accepted")
	}
}
