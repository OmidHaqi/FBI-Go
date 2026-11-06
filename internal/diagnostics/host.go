// Package diagnostics reports host compatibility without changing network state.
package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Finding struct {
	Code   string `json:"code"`
	Status string `json:"status"` // INFO, WARNING, BLOCKED, UNKNOWN
	Detail string `json:"detail"`
}
type Report struct {
	ReadOnly bool      `json:"read_only"`
	Findings []Finding `json:"findings"`
}
type Input struct {
	Snapshot                     network.Snapshot
	Rules4, Rules6, Routes4, NFT string
	NetworkManager               string
	DockerSocket                 bool
	Sysctls                      map[string]string
	Resolver                     string
	Errors                       map[string]string
}

func readCommand(ctx context.Context, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(commandCtx, args[0], args[1:]...).CombinedOutput()
	return string(out), err
}

// CollectHost performs only GET/read operations. A failed inventory read is
// reported as UNKNOWN, never interpreted as absence of a conflict.
func CollectHost() Report {
	return CollectHostContext(context.Background())
}

func CollectHostContext(ctx context.Context) Report {
	in := Input{Sysctls: map[string]string{}, Errors: map[string]string{}}
	var err error
	in.Snapshot, err = network.Scan()
	if err != nil {
		in.Errors["network"] = err.Error()
	}
	for _, item := range []struct {
		key  string
		args []string
		dst  *string
	}{
		{"rules4", []string{"ip", "-j", "-4", "rule", "show"}, &in.Rules4},
		{"rules6", []string{"ip", "-j", "-6", "rule", "show"}, &in.Rules6},
		{"routes4", []string{"ip", "-j", "-4", "route", "show", "table", "all"}, &in.Routes4},
		{"nft", []string{"nft", "-j", "list", "ruleset"}, &in.NFT},
		{"networkmanager", []string{"systemctl", "is-active", "NetworkManager"}, &in.NetworkManager},
	} {
		*item.dst, err = readCommand(ctx, item.args...)
		if err != nil {
			in.Errors[item.key] = fmt.Sprintf("%v: %s", err, strings.TrimSpace(*item.dst))
		}
	}
	keys := []string{"all/rp_filter", "default/rp_filter", "all/src_valid_mark", "default/src_valid_mark"}
	for _, d := range in.Snapshot.Devices {
		keys = append(keys, d.Name+"/rp_filter", d.Name+"/src_valid_mark")
	}
	for _, key := range keys {
		b, e := os.ReadFile(filepath.Join("/proc/sys/net/ipv4/conf", key))
		if e != nil {
			in.Errors[key] = e.Error()
		} else {
			in.Sysctls[key] = strings.TrimSpace(string(b))
		}
	}
	b, e := os.ReadFile("/etc/resolv.conf")
	if e != nil {
		in.Errors["dns"] = e.Error()
	} else {
		in.Resolver = string(b)
	}
	_, e = os.Stat("/run/docker.sock")
	in.DockerSocket = e == nil
	return Analyze(in)
}

func Analyze(in Input) Report {
	r := Report{ReadOnly: true, Findings: []Finding{}}
	seen := map[string]bool{}
	add := func(code, status, detail string) {
		key := code + "\x00" + status + "\x00" + detail
		if seen[key] {
			return
		}
		seen[key] = true
		r.Findings = append(r.Findings, Finding{code, status, detail})
	}
	for key, detail := range in.Errors {
		add(key, "UNKNOWN", detail)
	}
	for _, warning := range in.Snapshot.Warnings {
		add("network_discovery", "UNKNOWN", warning)
	}
	usableCandidates := 0
	for _, d := range in.Snapshot.Devices {
		if d.Candidate && d.State == "up" && d.Kind != "vpn" && d.Kind != "virtual" {
			usableCandidates++
		}
		lower := strings.ToLower(d.Name)
		if d.Kind == "vpn" || strings.Contains(lower, "tun") || strings.HasPrefix(lower, "wg") || strings.HasPrefix(lower, "tap") {
			add("vpn_tun", "BLOCKED", d.Name+": explicit VPN compatibility policy required")
		}
		if strings.HasPrefix(lower, "docker") || strings.HasPrefix(lower, "br-") || strings.HasPrefix(lower, "veth") {
			add("docker_bridge", "WARNING", d.Name+": Docker/virtual traffic must remain outside automatic routing")
		}
	}
	if usableCandidates < 2 {
		add("wan_candidates", "BLOCKED", fmt.Sprintf("%d operational physical WAN candidates; automatic dual-WAN activation requires two independently verified uplinks", usableCandidates))
	} else {
		add("wan_candidates", "INFO", fmt.Sprintf("%d operational physical WAN candidates; uplink independence and health still require verification", usableCandidates))
	}
	if in.DockerSocket {
		add("docker_socket", "INFO", "Docker socket present")
	}
	ipv6DefaultSeen := false
	for _, route := range in.Snapshot.Routes {
		if route.Family == "ipv6" && route.Destination == "::/0" {
			add("ipv6_default", "WARNING", "IPv6 default remains under system routing; no strict IPv6 guarantee")
			ipv6DefaultSeen = true
			break
		}
	}
	if !ipv6DefaultSeen && (len(in.Snapshot.Warnings) != 0 || in.Errors["network"] != "") {
		add("ipv6_default", "UNKNOWN", "route discovery was incomplete; IPv6 default route presence is unknown")
	}
	if strings.TrimSpace(in.NetworkManager) == "active" {
		add("networkmanager", "INFO", "NetworkManager active; no configuration changes planned")
	}
	if _, bad := in.Errors["rules4"]; !bad {
		var rules []map[string]any
		if err := json.Unmarshal([]byte(in.Rules4), &rules); err != nil {
			add("rules4", "UNKNOWN", "cannot parse IPv4 policy rules")
		} else {
			for _, rule := range rules {
				priority := number(rule["priority"])
				if priority >= 15000 && priority <= 15999 {
					add("priority_conflict", "BLOCKED", fmt.Sprintf("existing policy rule priority %d in reserved range", priority))
				}
				if mark, ok := rule["fwmark"]; ok {
					add("foreign_fwmark", "WARNING", fmt.Sprintf("existing fwmark %v mask %v; exact overlap must be checked", mark, rule["fwmask"]))
				}
				table := number(rule["table"])
				if table != 0 && table != 253 && table != 254 && table != 255 {
					add("foreign_table", "WARNING", fmt.Sprintf("policy rule references non-main table %d", table))
				}
			}
		}
	}
	if _, bad := in.Errors["routes4"]; !bad {
		var routes []map[string]any
		if err := json.Unmarshal([]byte(in.Routes4), &routes); err != nil {
			add("routes4", "UNKNOWN", "cannot parse IPv4 routing tables")
		} else {
			for _, route := range routes {
				table := number(route["table"])
				if table >= 30000 && table <= 30999 {
					add("table_conflict", "BLOCKED", fmt.Sprintf("existing route in reserved table %d", table))
				}
				if table != 0 && table != 254 && table != 255 && table != 253 {
					add("foreign_table", "WARNING", fmt.Sprintf("existing non-main routing table %d", table))
				}
			}
		}
	}
	if _, bad := in.Errors["nft"]; !bad {
		var ruleset struct {
			NFTables []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(in.NFT), &ruleset); err != nil {
			add("nft", "UNKNOWN", "cannot parse nftables ruleset")
		} else {
			for _, item := range ruleset.NFTables {
				if raw, ok := item["chain"]; ok {
					var chain struct{ Family, Table, Name, Hook string }
					if json.Unmarshal(raw, &chain) == nil {
						add("nft_chain", "WARNING", fmt.Sprintf("existing %s %s/%s hook=%s", chain.Family, chain.Table, chain.Name, chain.Hook))
					}
				}
			}
		}
	}
	for key, value := range in.Sysctls {
		if strings.HasSuffix(key, "/rp_filter") && value != "0" {
			add("rp_filter", "WARNING", key+"="+value+" may reject asymmetric replies")
		}
		if strings.HasSuffix(key, "/src_valid_mark") && value == "0" {
			add("src_valid_mark", "WARNING", key+"=0; marked reverse-path behavior requires validation")
		}
	}
	if in.Resolver != "" {
		add("dns", "WARNING", "DNS routing remains system-managed; per-WAN resolver affinity is unverified")
	}
	sort.Slice(r.Findings, func(i, j int) bool {
		if r.Findings[i].Code == r.Findings[j].Code {
			return r.Findings[i].Detail < r.Findings[j].Detail
		}
		return r.Findings[i].Code < r.Findings[j].Code
	})
	return r
}

func number(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		var n int
		_, _ = fmt.Sscanf(x, "%d", &n)
		return n
	}
	return 0
}
