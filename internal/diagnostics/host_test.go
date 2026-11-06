package diagnostics

import (
	"github.com/omidhaqi/FBI-Go/internal/network"
	"strings"
	"testing"
)

func TestAnalyzeHostCompatibility(t *testing.T) {
	in := Input{
		Snapshot: network.Snapshot{Devices: []network.Device{{Name: "vpn-tun", Kind: "virtual"}, {Name: "docker0", Kind: "virtual"}}, Routes: []network.Route{{Family: "ipv6", Destination: "::/0"}}},
		Rules4:   `[{"priority":9000,"fwmark":"0x2023","table":2022},{"priority":15000,"table":30000}]`,
		Rules6:   `[]`, Routes4: `[{"table":2022},{"table":30000}]`,
		NFT:            `{"nftables":[{"chain":{"family":"ip","table":"foreign","name":"output","hook":"output"}}]}`,
		NetworkManager: "active\n", DockerSocket: true,
		Sysctls: map[string]string{"all/rp_filter": "1", "all/src_valid_mark": "0"}, Resolver: "nameserver 127.0.0.53\n",
		Errors: map[string]string{},
	}
	r := Analyze(in)
	if !r.ReadOnly {
		t.Fatal("diagnostics must be read only")
	}
	var codes []string
	for _, f := range r.Findings {
		codes = append(codes, f.Code)
	}
	joined := strings.Join(codes, ",")
	for _, want := range []string{"vpn_tun", "docker_bridge", "foreign_fwmark", "foreign_table", "priority_conflict", "table_conflict", "nft_chain", "networkmanager", "ipv6_default", "rp_filter", "src_valid_mark", "dns"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
}

func TestFailedInventoryIsUnknown(t *testing.T) {
	r := Analyze(Input{Snapshot: network.Snapshot{Warnings: []string{"netlink route read unavailable"}}, Errors: map[string]string{"nft": "Operation not permitted", "rules4": "netlink denied"}})
	ipv6Unknown := false
	for _, f := range r.Findings {
		if (f.Code == "nft" || f.Code == "rules4") && f.Status != "UNKNOWN" {
			t.Fatalf("failed inventory treated as known: %+v", f)
		}
		if f.Code == "ipv6_default" && f.Status == "UNKNOWN" {
			ipv6Unknown = true
		}
	}
	if !ipv6Unknown {
		t.Fatal("incomplete route discovery treated as no IPv6 default")
	}
}

func TestWANCountAndForeignTableFindingsAreConcise(t *testing.T) {
	in := Input{
		Snapshot: network.Snapshot{Devices: []network.Device{
			{Name: "wifi0", Kind: "wifi", State: "up", Candidate: true},
			{Name: "ether0", Kind: "ethernet_or_other", State: "down", Candidate: false},
			{Name: "tun0", Kind: "vpn", State: "up"},
		}},
		Routes4: `[{"table":2022},{"table":2022}]`, Rules4: `[]`, NFT: `{"nftables":[]}`,
		Errors: map[string]string{},
	}
	report := Analyze(in)
	counts := map[string]int{}
	for _, f := range report.Findings {
		counts[f.Code]++
		if f.Code == "wan_candidates" && (f.Status != "BLOCKED" || !strings.Contains(f.Detail, "1 operational")) {
			t.Fatalf("unexpected candidate finding: %+v", f)
		}
	}
	if counts["wan_candidates"] != 1 || counts["foreign_table"] != 1 {
		t.Fatalf("duplicate or missing findings: %+v", report.Findings)
	}
}
