// Package network reads Linux interface and routing metadata without changing it.
package network

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

type Route struct {
	Family      string `json:"family"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface"`
	Table       int    `json:"table"`
	Metric      int    `json:"metric"`
	Source      string `json:"source,omitempty"`
}
type Device struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	State     string   `json:"state"`
	AdminUp   bool     `json:"admin_up"`
	OperState string   `json:"oper_state,omitempty"`
	Carrier   *bool    `json:"carrier,omitempty"`
	Addresses []string `json:"addresses"`
	Gateways  []string `json:"gateways,omitempty"`
	RXBytes   uint64   `json:"rx_bytes"`
	TXBytes   uint64   `json:"tx_bytes"`
	Candidate bool     `json:"candidate"`
	Reasons   []string `json:"reasons"`
}
type Snapshot struct {
	Devices  []Device `json:"devices"`
	Routes   []Route  `json:"routes"`
	Warnings []string `json:"warnings,omitempty"`
}

type Status struct {
	Snapshot               Snapshot `json:"snapshot"`
	EnforcementActive      bool     `json:"enforcement_active"`
	HealthMonitoringActive bool     `json:"health_monitoring_active"`
}

// Classify is deliberately conservative: a route is evidence of a candidate, not of internet reachability.
func Classify(name string, flags net.Flags, kind string, addresses []string, routes []Route) (bool, []string) {
	return classifyLink(name, flags, kind, addresses, routes, true)
}

func classifyLink(name string, flags net.Flags, kind string, addresses []string, routes []Route, linkReady bool) (bool, []string) {
	var reasons []string
	if flags&net.FlagUp == 0 {
		reasons = append(reasons, "interface is down")
	}
	if !linkReady {
		reasons = append(reasons, "link has no carrier or is not operational")
	}
	if kind == "loopback" || kind == "virtual" || kind == "vpn" {
		reasons = append(reasons, "excluded device type: "+kind)
	}
	hasV4 := false
	for _, a := range addresses {
		if ip, _, err := net.ParseCIDR(a); err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			hasV4 = true
		}
	}
	if !hasV4 {
		reasons = append(reasons, "no usable IPv4 source address")
	}
	defaultRoute := false
	for _, r := range routes {
		if r.Interface == name && r.Family == "ipv4" && r.Destination == "0.0.0.0/0" && r.Gateway != "" {
			defaultRoute = true
		}
	}
	if !defaultRoute {
		reasons = append(reasons, "no IPv4 default route with gateway")
	}
	return len(reasons) == 0, reasons
}

func deviceKind(name string, flags net.Flags) string {
	if flags&net.FlagLoopback != 0 {
		return "loopback"
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "wireless")); err == nil {
		return "wifi"
	}
	if strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "wg") {
		return "vpn"
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", name, "device")); err != nil {
		return "virtual"
	}
	if strings.HasPrefix(name, "usb") || strings.HasPrefix(name, "enx") {
		return "usb_or_ethernet"
	}
	return "ethernet_or_other"
}

func readCounter(name, counter string) uint64 {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "statistics", counter))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// Scan uses RTM_GETROUTE via Linux netlink. It never invokes ip or changes host state.
func Scan() (Snapshot, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		ifs, err = sysInterfaces()
		if err != nil {
			return Snapshot{}, err
		}
	}
	routes, routeErr := readRoutes(ifs)
	linkStates, linkStateErr := readNetlinkStates()
	s := Snapshot{Routes: routes}
	if linkStateErr != nil {
		s.Warnings = append(s.Warnings, "netlink link-state read unavailable; using sysfs fallback")
	}
	if routeErr != nil {
		routes, err = readProcRoutes()
		if err != nil {
			return Snapshot{}, fmt.Errorf("netlink: %v; proc routes: %w", routeErr, err)
		}
		s.Routes = routes
		s.Warnings = append(s.Warnings, "netlink route read unavailable; /proc fallback omits non-main routing tables and policy rules")
	}
	for _, in := range ifs {
		addrs, err := in.Addrs()
		if err != nil {
			addrs = sysAddresses(in.Name)
			s.Warnings = append(s.Warnings, in.Name+": netlink address read unavailable; using ioctl and /proc fallback")
		}
		id := in.Name
		if len(in.HardwareAddr) > 0 && !isZeroMAC(in.HardwareAddr) {
			id = fmt.Sprintf("mac:%s", in.HardwareAddr.String())
		}
		d := Device{ID: id, Name: in.Name, Kind: deviceKind(in.Name, in.Flags), State: "down", Addresses: []string{}, RXBytes: readCounter(in.Name, "rx_bytes"), TXBytes: readCounter(in.Name, "tx_bytes")}
		d.AdminUp = in.Flags&net.FlagUp != 0
		if state, ok := linkStates[in.Name]; ok {
			d.OperState, d.Carrier = state.oper, state.carrier
		} else {
			d.OperState, d.Carrier = readLinkState(in.Name)
		}
		ready := linkReady(d.AdminUp, d.OperState, d.Carrier)
		if ready {
			d.State = "up"
		}
		for _, a := range addrs {
			d.Addresses = append(d.Addresses, a.String())
		}
		sort.Strings(d.Addresses)
		for _, r := range routes {
			if r.Interface == in.Name && r.Gateway != "" && (r.Destination == "0.0.0.0/0" || r.Destination == "::/0") {
				d.Gateways = append(d.Gateways, r.Gateway)
			}
		}
		sort.Strings(d.Gateways)
		d.Candidate, d.Reasons = classifyLink(d.Name, in.Flags, d.Kind, d.Addresses, routes, ready)
		s.Devices = append(s.Devices, d)
	}
	sort.Slice(s.Devices, func(i, j int) bool { return s.Devices[i].Name < s.Devices[j].Name })
	return s, nil
}

type netlinkState struct {
	oper    string
	carrier *bool
}

func readNetlinkStates() (map[string]netlinkState, error) {
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETLINK, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		return nil, err
	}
	states := make(map[string]netlinkState)
	for _, message := range messages {
		if message.Header.Type != syscall.RTM_NEWLINK || len(message.Data) < syscall.SizeofIfInfomsg {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nil, err
		}
		var name string
		state := netlinkState{}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_IFNAME:
				name = strings.TrimRight(string(attr.Value), "\x00")
			case syscall.IFLA_OPERSTATE:
				if len(attr.Value) > 0 {
					state.oper = operStateName(attr.Value[0])
				}
			case 33: // IFLA_CARRIER; absent from Go's syscall constants.
				if len(attr.Value) > 0 {
					carrier := attr.Value[0] != 0
					state.carrier = &carrier
				}
			}
		}
		if name != "" {
			states[name] = state
		}
	}
	return states, nil
}

func operStateName(value byte) string {
	switch value {
	case 0:
		return "unknown"
	case 1:
		return "notpresent"
	case 2:
		return "down"
	case 3:
		return "lowerlayerdown"
	case 4:
		return "testing"
	case 5:
		return "dormant"
	case 6:
		return "up"
	default:
		return "unknown"
	}
}

func readLinkState(name string) (string, *bool) {
	base := filepath.Join("/sys/class/net", name)
	op, _ := os.ReadFile(filepath.Join(base, "operstate"))
	oper := strings.TrimSpace(string(op))
	b, err := os.ReadFile(filepath.Join(base, "carrier"))
	if err != nil {
		return oper, nil
	}
	v := strings.TrimSpace(string(b)) == "1"
	return oper, &v
}
func linkReady(admin bool, oper string, carrier *bool) bool {
	if !admin {
		return false
	}
	if carrier != nil && !*carrier {
		return false
	}
	switch oper {
	case "down", "lowerlayerdown", "dormant", "notpresent", "testing":
		return false
	}
	return true
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}

func sysInterfaces() ([]net.Interface, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, err
	}
	var out []net.Interface
	for _, e := range entries {
		name := e.Name()
		idxb, _ := os.ReadFile(filepath.Join("/sys/class/net", name, "ifindex"))
		idx, _ := strconv.Atoi(strings.TrimSpace(string(idxb)))
		fb, _ := os.ReadFile(filepath.Join("/sys/class/net", name, "flags"))
		fv, _ := strconv.ParseUint(strings.TrimSpace(string(fb)), 0, 32)
		flags := net.Flags(0)
		if fv&uint64(syscall.IFF_UP) != 0 {
			flags |= net.FlagUp
		}
		if fv&uint64(syscall.IFF_LOOPBACK) != 0 {
			flags |= net.FlagLoopback
		}
		macb, _ := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))
		mac, _ := net.ParseMAC(strings.TrimSpace(string(macb)))
		out = append(out, net.Interface{Index: idx, Name: name, Flags: flags, HardwareAddr: mac})
	}
	return out, nil
}

type ifreq struct {
	Name [16]byte
	Data [24]byte
}

func ioctlAddress(name string, request uintptr) net.IP {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil
	}
	defer syscall.Close(fd)
	var q ifreq
	copy(q.Name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(&q)))
	if errno != 0 {
		return nil
	}
	return net.IPv4(q.Data[4], q.Data[5], q.Data[6], q.Data[7])
}
func sysAddresses(name string) []net.Addr {
	var a []net.Addr
	ip := ioctlAddress(name, syscall.SIOCGIFADDR)
	mask := ioctlAddress(name, syscall.SIOCGIFNETMASK)
	if ip != nil && mask != nil {
		ones, _ := net.IPMask(mask.To4()).Size()
		a = append(a, &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, 32)})
	}
	b, err := os.ReadFile("/proc/net/if_inet6")
	if err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			v := strings.Fields(line)
			if len(v) != 6 || v[5] != name {
				continue
			}
			raw, e := hex.DecodeString(v[0])
			prefix, e2 := strconv.ParseInt(v[2], 16, 32)
			if e == nil && e2 == nil && len(raw) == 16 {
				a = append(a, &net.IPNet{IP: net.IP(raw), Mask: net.CIDRMask(int(prefix), 128)})
			}
		}
	}
	return a
}

func readProcRoutes() ([]Route, error) {
	var routes []Route
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if s.Scan() { /* header */
	}
	for s.Scan() {
		v := strings.Fields(s.Text())
		if len(v) < 8 {
			continue
		}
		dst, e1 := parseProcV4(v[1])
		gw, e2 := parseProcV4(v[2])
		mask, e3 := parseProcV4(v[7])
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		ones, _ := net.IPMask(mask.To4()).Size()
		metric, _ := strconv.Atoi(v[6])
		r := Route{Family: "ipv4", Destination: dst.String() + "/" + strconv.Itoa(ones), Interface: v[0], Metric: metric, Table: 254}
		if !gw.IsUnspecified() {
			r.Gateway = gw.String()
		}
		routes = append(routes, r)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	f6, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return routes, err
	}
	defer f6.Close()
	s6 := bufio.NewScanner(f6)
	for s6.Scan() {
		v := strings.Fields(s6.Text())
		if len(v) < 10 {
			continue
		}
		dst, e1 := hex.DecodeString(v[0])
		gw, e2 := hex.DecodeString(v[4])
		bits, e3 := strconv.ParseInt(v[1], 16, 32)
		metric, e4 := strconv.ParseInt(v[5], 16, 32)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(dst) != 16 || len(gw) != 16 {
			continue
		}
		r := Route{Family: "ipv6", Destination: net.IP(dst).String() + "/" + strconv.FormatInt(bits, 10), Interface: v[9], Metric: int(metric), Table: 254}
		if !net.IP(gw).IsUnspecified() {
			r.Gateway = net.IP(gw).String()
		}
		routes = append(routes, r)
	}
	if err := s6.Err(); err != nil {
		return nil, err
	}
	return routes, nil
}
func parseProcV4(s string) (net.IP, error) {
	v, e := strconv.ParseUint(s, 16, 32)
	if e != nil {
		return nil, e
	}
	return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)), nil
}

func readRoutes(ifs []net.Interface) ([]Route, error) {
	names := map[int]string{}
	for _, in := range ifs {
		names[in.Index] = in.Name
	}
	var routes []Route
	for _, family := range []int{syscall.AF_INET, syscall.AF_INET6} {
		b, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, family)
		if err != nil {
			return nil, err
		}
		msgs, err := syscall.ParseNetlinkMessage(b)
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < 12 {
				continue
			}
			f := int(m.Data[0])
			if f != family {
				continue
			}
			// rtmsg: family, dst_len, src_len, tos, table, protocol, scope, type, flags.
			if m.Data[7] != syscall.RTN_UNICAST {
				continue
			}
			r := Route{Table: int(m.Data[4]), Metric: 0}
			bits := 32
			r.Family = "ipv4"
			if family == syscall.AF_INET6 {
				bits = 128
				r.Family = "ipv6"
			}
			r.Destination = "0.0.0.0/0"
			if bits == 128 {
				r.Destination = "::/0"
			}
			attrs, err := syscall.ParseNetlinkRouteAttr(&m)
			if err != nil {
				return nil, err
			}
			for _, a := range attrs {
				switch a.Attr.Type {
				case syscall.RTA_DST:
					if len(a.Value) <= bits/8 {
						full := make([]byte, bits/8)
						copy(full, a.Value)
						r.Destination = net.IP(full).String() + "/" + strconv.Itoa(int(m.Data[1]))
					}
				case syscall.RTA_GATEWAY:
					r.Gateway = net.IP(a.Value).String()
				case syscall.RTA_PREFSRC:
					r.Source = net.IP(a.Value).String()
				case syscall.RTA_OIF:
					if len(a.Value) >= 4 {
						r.Interface = names[int(binary.NativeEndian.Uint32(a.Value))]
					}
				case syscall.RTA_PRIORITY:
					if len(a.Value) >= 4 {
						r.Metric = int(binary.NativeEndian.Uint32(a.Value))
					}
				case syscall.RTA_TABLE:
					if len(a.Value) >= 4 {
						r.Table = int(binary.NativeEndian.Uint32(a.Value))
					}
				}
			}
			if r.Interface != "" {
				routes = append(routes, r)
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool {
		a, b := routes[i], routes[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Table != b.Table {
			return a.Table < b.Table
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		return a.Destination < b.Destination
	})
	return routes, nil
}
