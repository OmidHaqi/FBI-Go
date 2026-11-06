package routing

import (
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"net"
	"sort"
	"strings"
)

// Inventory is a complete, explicit preflight snapshot. Missing ownership data fails closed.
type Inventory struct {
	Snapshot       network.Snapshot        `json:"snapshot"`
	Rules          []Rule                  `json:"rules"`
	UsedTables     []int                   `json:"used_tables"`
	ForeignMarks   []uint32                `json:"foreign_marks"`
	NFTTables      []string                `json:"nft_tables"`
	RulesComplete  bool                    `json:"rules_complete"`
	TablesComplete bool                    `json:"tables_complete"`
	MarksComplete  bool                    `json:"marks_complete"`
	NFTComplete    bool                    `json:"nft_complete"`
	VPNPresent     bool                    `json:"vpn_present"`
	WANHealth      map[string]health.State `json:"wan_health"`
	IPv6Policy     string                  `json:"ipv6_policy"` // "system" explicitly leaves IPv6 to existing routing.
}
type Rule struct {
	Priority int    `json:"priority"`
	Table    int    `json:"table"`
	Mark     uint32 `json:"mark"`
	Mask     uint32 `json:"mask"`
	HasMark  bool   `json:"has_mark"`
}
type Allocation struct {
	Interface  string `json:"interface"`
	Gateway    string `json:"gateway"`
	SourceCIDR string `json:"source_cidr"`
	SourceIP   string `json:"source_ip"`
	Weight     int    `json:"weight"`
	Table      int    `json:"table"`
	Priority   int    `json:"priority"`
	Mark       uint32 `json:"mark"`
}
type M2Plan struct {
	SafeToApply bool         `json:"safe_to_apply"`
	Reasons     []string     `json:"reasons"`
	Warnings    []string     `json:"warnings"`
	NFTTable    string       `json:"nft_table"`
	WANs        []Allocation `json:"wans"`
	IPv6Policy  string       `json:"ipv6_policy"`
}

// PlanM2 allocates only unused resources. It never mutates the inventory or the host.
func PlanM2(in Inventory) M2Plan {
	p := M2Plan{NFTTable: "fbi_m2", WANs: []Allocation{}, Reasons: []string{}, Warnings: []string{}, IPv6Policy: in.IPv6Policy}
	if !in.RulesComplete || !in.TablesComplete || !in.MarksComplete || !in.NFTComplete {
		p.Reasons = append(p.Reasons, "incomplete rule, table, mark, or nftables ownership inventory")
	}
	for _, name := range in.NFTTables {
		if name == p.NFTTable {
			p.Reasons = append(p.Reasons, "nftables table name already exists: "+name)
		}
	}
	if in.VPNPresent {
		p.Reasons = append(p.Reasons, "VPN/TUN present; explicit compatibility verification required before activation")
	}
	if in.IPv6Policy != "system" {
		p.Reasons = append(p.Reasons, "IPv6 policy must explicitly be system routing for IPv4-only M2")
	}
	usedTables := map[int]bool{0: true, 253: true, 254: true, 255: true}
	usedPriorities := map[int]bool{}
	for _, t := range in.UsedTables {
		usedTables[t] = true
	}
	for _, r := range in.Rules {
		usedPriorities[r.Priority] = true
		usedTables[r.Table] = true
	}
	for _, r := range in.Snapshot.Routes {
		usedTables[r.Table] = true
	}
	devices := append([]network.Device(nil), in.Snapshot.Devices...)
	sort.Slice(devices, func(i, j int) bool { return devices[i].Name < devices[j].Name })
	for _, d := range devices {
		if d.Kind == "vpn" || d.Kind == "virtual" && isLikelyTunnel(d.Name, in.Snapshot.Routes) {
			p.Reasons = append(p.Reasons, "VPN/TUN device present: "+d.Name)
		}
		if !d.Candidate {
			continue
		}
		if in.WANHealth[d.Name] != health.Healthy && in.WANHealth[d.Name] != health.Degraded {
			p.Reasons = append(p.Reasons, d.Name+": WAN health is not verified")
		}
		if d.State != "up" || d.Carrier != nil && !*d.Carrier {
			p.Reasons = append(p.Reasons, d.Name+": candidate link is not operational")
			continue
		}
		gateway, source, ip := ipv4WAN(d, in.Snapshot.Routes)
		if gateway == "" || source == "" {
			p.Reasons = append(p.Reasons, d.Name+": missing unambiguous IPv4 gateway/source")
			continue
		}
		table := firstFreeInt(30000, 30999, usedTables)
		priority := firstFreeInt(15000, 15999, usedPriorities)
		mark := firstFreeMark(in.ForeignMarks, in.Rules, p.WANs)
		if table == 0 || priority == 0 || mark == 0 {
			p.Reasons = append(p.Reasons, d.Name+": no collision-free table, priority, or mark")
			continue
		}
		usedTables[table] = true
		usedPriorities[priority] = true
		p.WANs = append(p.WANs, Allocation{Interface: d.Name, Gateway: gateway, SourceCIDR: source, SourceIP: ip, Weight: 1, Table: table, Priority: priority, Mark: mark})
	}
	if len(p.WANs) < 2 {
		p.Reasons = append(p.Reasons, "at least two eligible IPv4 WANs required")
	}
	for _, r := range in.Rules {
		if r.Priority >= 15000 || r.Table == 255 {
			continue
		}
		if !r.HasMark {
			p.Reasons = append(p.Reasons, fmt.Sprintf("unconditional foreign rule priority %d may preempt FBI-Go", r.Priority))
			continue
		}
		for _, w := range p.WANs {
			if w.Mark&r.Mask == r.Mark&r.Mask {
				p.Reasons = append(p.Reasons, fmt.Sprintf("foreign rule priority %d matches proposed mark %#x", r.Priority, w.Mark))
			}
		}
	}
	for _, r := range in.Snapshot.Routes {
		if r.Family == "ipv6" && r.Destination == "::/0" {
			p.Warnings = append(p.Warnings, "IPv6 default route remains under system routing; no strict IPv6 guarantee")
			break
		}
	}
	for i := 0; i < len(p.WANs); i++ {
		for j := i + 1; j < len(p.WANs); j++ {
			a, b := p.WANs[i], p.WANs[j]
			if a.Gateway == b.Gateway {
				p.Reasons = append(p.Reasons, "WANs share gateway: "+a.Gateway)
			}
			_, an, _ := net.ParseCIDR(a.SourceCIDR)
			_, bn, _ := net.ParseCIDR(b.SourceCIDR)
			if an != nil && bn != nil && (an.Contains(bn.IP) || bn.Contains(an.IP)) {
				p.Reasons = append(p.Reasons, "WAN source subnets overlap")
			}
		}
	}
	p.SafeToApply = len(p.Reasons) == 0
	return p
}

func isLikelyTunnel(name string, routes []network.Route) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "tun") || strings.HasPrefix(lower, "tap") || strings.HasPrefix(lower, "wg") || strings.HasPrefix(lower, "ppp") {
		return true
	}
	for _, r := range routes {
		if r.Interface == name && r.Table != 254 && r.Table != 255 && r.Table != 253 {
			return true
		}
	}
	return false
}

func ipv4WAN(d network.Device, routes []network.Route) (string, string, string) {
	var gateway string
	for _, r := range routes {
		if r.Interface == d.Name && r.Family == "ipv4" && r.Destination == "0.0.0.0/0" && r.Gateway != "" {
			if gateway != "" && gateway != r.Gateway {
				return "", "", ""
			}
			gateway = r.Gateway
		}
	}
	var cidr, source string
	for _, a := range d.Addresses {
		ip, _, e := net.ParseCIDR(a)
		if e == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			if cidr != "" {
				return "", "", ""
			}
			cidr = a
			source = ip.String()
		}
	}
	return gateway, cidr, source
}
func firstFreeInt(start, end int, used map[int]bool) int {
	for n := start; n <= end; n++ {
		if !used[n] {
			return n
		}
	}
	return 0
}
func firstFreeMark(foreign []uint32, rules []Rule, allocated []Allocation) uint32 {
	for n := uint32(0x40000001); n < 0x40001000; n++ {
		bad := false
		for _, f := range foreign {
			if f == n {
				bad = true
			}
		}
		for _, a := range allocated {
			if a.Mark == n {
				bad = true
			}
		}
		for _, r := range rules {
			if r.HasMark && n&r.Mask == r.Mark&r.Mask {
				bad = true
			}
		}
		if !bad {
			return n
		}
	}
	return 0
}

// outputRules describes connection-scoped IPv4 marking. Restored marks keep
// established flows on their WAN even when that WAN's weight becomes zero.
func outputRules(p M2Plan) (string, error) {
	return outputRulesMode(p, true)
}

// outputRulesMode keeps the ordinary M2 selector unchanged. The false mode is
// used only by the owned cgroup experiment, where unmatched applications must
// retain the namespace's existing system route and an unmodified packet mark.
func outputRulesMode(p M2Plan, automatic bool) (string, error) {
	if !p.SafeToApply {
		return "", errors.New("unsafe M2 plan")
	}
	total := 0
	for _, w := range p.WANs {
		if w.Weight < 0 || w.Weight > 256 {
			return "", errors.New("weight outside 0..256")
		}
		total += w.Weight
	}
	if total > 256 || automatic && total == 0 {
		return "", errors.New("total weight must be 1..256")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add rule ip %s output meta mark != 0 return\n", p.NFTTable)
	for _, w := range p.WANs {
		fmt.Fprintf(&b, "add rule ip %s output ct mark %#x meta mark set ct mark\n", p.NFTTable, w.Mark)
	}
	fmt.Fprintf(&b, "add rule ip %s output meta mark != 0 return\n", p.NFTTable)
	fmt.Fprintf(&b, "add rule ip %s output ct mark != 0 return\n", p.NFTTable)
	fmt.Fprintf(&b, "add rule ip %s output fib daddr type local return\n", p.NFTTable)
	fmt.Fprintf(&b, "add rule ip %s output ip daddr { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 } return\n", p.NFTTable)
	for _, w := range p.WANs {
		_, subnet, err := net.ParseCIDR(w.SourceCIDR)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "add rule ip %s output ip daddr %s return\n", p.NFTTable, subnet.String())
	}
	if !automatic {
		return b.String(), nil
	}
	fmt.Fprintf(&b, "add rule ip %s output meta l4proto { tcp, udp } ct state new meta mark set numgen random mod %d map { ", p.NFTTable, total)
	first := true
	slot := 0
	for _, w := range p.WANs {
		for i := 0; i < w.Weight; i++ {
			if !first {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%d : %#x", slot, w.Mark)
			slot++
			first = false
		}
	}
	b.WriteString(" }\n")
	fmt.Fprintf(&b, "add rule ip %s output meta mark != 0 ct mark set meta mark\n", p.NFTTable)
	return b.String(), nil
}

// NFTScript creates only an FBI-Go-owned table in a fresh test namespace.
// Existing nonzero packet and foreign conntrack marks are never changed.
func NFTScript(p M2Plan) (string, error) {
	output, err := outputRules(p)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "add table ip %s\nadd chain ip %s output { type route hook output priority mangle; policy accept; }\n", p.NFTTable, p.NFTTable)
	b.WriteString(output)
	fmt.Fprintf(&b, "add chain ip %s postrouting { type nat hook postrouting priority srcnat; policy accept; }\n", p.NFTTable)
	for _, w := range p.WANs {
		fmt.Fprintf(&b, "add rule ip %s postrouting meta mark %#x oifname %q snat to %s\n", p.NFTTable, w.Mark, w.Interface, w.SourceIP)
	}
	return b.String(), nil
}

// NFTWeightUpdate atomically replaces selection rules inside the owned output
// chain. Conntrack restore rules remain, preserving existing flow affinity.
func NFTWeightUpdate(p M2Plan) (string, error) {
	output, err := outputRules(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("flush chain ip %s output\n", p.NFTTable) + output, nil
}
