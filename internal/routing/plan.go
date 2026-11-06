package routing

import (
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"net"
	"sort"
)

// Plan contains proposals only. M1 has no apply path and allocates no host resources.
type Plan struct {
	ReadOnly   bool          `json:"read_only"`
	Candidates []string      `json:"candidates"`
	WANs       []WANProposal `json:"wans"`
	Actions    []string      `json:"proposed_actions"`
	Warnings   []string      `json:"warnings"`
}
type WANProposal struct {
	Interface       string   `json:"interface"`
	Gateways        []string `json:"gateways"`
	SourceAddresses []string `json:"source_addresses"`
	Health          string   `json:"health"`
	RoutingTable    string   `json:"routing_table"`
	FWMark          string   `json:"fwmark"`
}

func Generate(s network.Snapshot) Plan {
	p := Plan{ReadOnly: true, Candidates: []string{}, WANs: []WANProposal{}, Actions: []string{}, Warnings: append([]string{}, s.Warnings...)}
	gateways := map[string]string{}
	subnets := map[string]string{}
	for _, d := range s.Devices {
		if !d.Candidate {
			continue
		}
		p.Candidates = append(p.Candidates, d.Name)
		p.WANs = append(p.WANs, WANProposal{Interface: d.Name, Gateways: append([]string{}, d.Gateways...), SourceAddresses: append([]string{}, d.Addresses...), Health: "UNKNOWN", RoutingTable: "unallocated", FWMark: "unallocated"})
		p.Actions = append(p.Actions, fmt.Sprintf("Future: validate dedicated IPv4 table, mark and nftables ownership for %s; no change in M1", d.Name))
		for _, g := range d.Gateways {
			if other, ok := gateways[g]; ok && other != d.Name {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s and %s share gateway %s; independence unverified", other, d.Name, g))
			} else {
				gateways[g] = d.Name
			}
		}
		for _, a := range d.Addresses {
			ip, n, err := net.ParseCIDR(a)
			if err != nil || ip.To4() == nil {
				continue
			}
			key := n.String()
			if other, ok := subnets[key]; ok && other != d.Name {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s and %s share subnet %s", other, d.Name, key))
			} else {
				subnets[key] = d.Name
			}
		}
	}
	if len(p.Candidates) == 0 {
		p.Warnings = append(p.Warnings, "no verified IPv4 WAN candidates; discovery does not test internet reachability")
	}
	p.Warnings = append(p.Warnings, "WAN health, uplink independence, VPN conflicts, policy rules, and enforcement capabilities are not verified in M1")
	sort.Strings(p.Candidates)
	sort.Slice(p.WANs, func(i, j int) bool { return p.WANs[i].Interface < p.WANs[j].Interface })
	sort.Strings(p.Actions)
	sort.Strings(p.Warnings)
	return p
}
