//go:build integration

package routing

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This is deliberately a test-only guest-initial-netns gate. It is not an
// executor method, CLI command, or public IPC operation.
type guestLink struct {
	IfIndex   int    `json:"ifindex"`
	Name      string `json:"ifname"`
	LinkIndex int    `json:"link_index"`
	LinkName  string `json:"link"`
	Address   string `json:"address"`
	Alias     string `json:"ifalias"`
	Master    string `json:"master"`
	LinkInfo  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
}

type guestWANIntent struct {
	Version    int          `json:"version"`
	Operation  string       `json:"operation"`
	InitialNS  string       `json:"initial_ns"`
	GatewayNS  [2]string    `json:"gateway_ns"`
	Names      [4]string    `json:"names"`
	Phase      string       `json:"phase"`
	Links      [4]guestLink `json:"links"`
	LocalIPv4  [2]string    `json:"local_ipv4"`
	PeerIPv4   [2]string    `json:"peer_ipv4"`
	BridgeName string       `json:"bridge_name,omitempty"`
	Bridge     guestLink    `json:"bridge,omitempty"`
}

func readGuestIntent(path string) (guestWANIntent, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return guestWANIntent{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return guestWANIntent{}, fmt.Errorf("unsafe guest-WAN journal: %v", err)
	}
	var intent guestWANIntent
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return guestWANIntent{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return guestWANIntent{}, fmt.Errorf("unexpected trailing journal data: %v", err)
	}
	return intent, nil
}

func guestIPv4(name string, gateway *NamespaceEngine) ([]string, error) {
	var raw string
	var err error
	if gateway == nil {
		raw, err = guestRun("ip", "-j", "-4", "addr", "show", "dev", name)
	} else {
		raw, err = gateway.run("", "ip", "-j", "-4", "addr", "show", "dev", name)
	}
	if err != nil {
		return nil, err
	}
	var links []struct {
		Addresses []struct {
			Local  string `json:"local"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal([]byte(raw), &links); err != nil || len(links) > 1 {
		return nil, fmt.Errorf("decode IPv4 addresses for %s: %v", name, err)
	}
	if len(links) == 0 {
		return []string{}, nil
	}
	result := make([]string, 0, len(links[0].Addresses))
	for _, address := range links[0].Addresses {
		result = append(result, fmt.Sprintf("%s/%d", address.Local, address.Prefix))
	}
	return result, nil
}

func guestConnectedRoute(name, cidr string, gateway *NamespaceEngine) error {
	if cidr == "" {
		return nil
	}
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	var raw string
	if gateway == nil {
		raw, err = guestRun("ip", "-j", "-4", "route", "show", "dev", name)
	} else {
		raw, err = gateway.run("", "ip", "-j", "-4", "route", "show", "dev", name)
	}
	if err != nil {
		return err
	}
	var routes []struct {
		Dst     string `json:"dst"`
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal([]byte(raw), &routes); err != nil {
		return err
	}
	// iproute2 omits "dev" in JSON when the query already filters by dev.
	if len(routes) != 1 || routes[0].Dst != subnet.String() || routes[0].Dev != "" && routes[0].Dev != name || routes[0].Gateway != "" {
		return fmt.Errorf("unexpected route on %s: %.400s", name, raw)
	}
	return nil
}

func guestRun(args ...string) (string, error) {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %.400s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}

func guestLinkRead(name string, gateway *NamespaceEngine) (guestLink, error) {
	var raw string
	var err error
	if gateway == nil {
		raw, err = guestRun("ip", "-j", "-d", "link", "show", "dev", name)
	} else {
		raw, err = gateway.run("", "ip", "-j", "-d", "link", "show", "dev", name)
	}
	if err != nil {
		return guestLink{}, err
	}
	var links []guestLink
	if err := json.Unmarshal([]byte(raw), &links); err != nil || len(links) != 1 {
		return guestLink{}, fmt.Errorf("decode one link %s: %v", name, err)
	}
	return links[0], nil
}

func guestLinkMatches(expected, actual guestLink) bool {
	return expected.IfIndex > 0 && expected.IfIndex == actual.IfIndex &&
		expected.Name == actual.Name && expected.LinkIndex == actual.LinkIndex && expected.LinkName == actual.LinkName &&
		expected.Address == actual.Address && expected.Alias == actual.Alias && expected.Master == actual.Master &&
		expected.LinkInfo.Kind == "veth" && actual.LinkInfo.Kind == "veth"
}

func guestSameNSPeers(a, b guestLink) bool {
	return a.LinkName == b.Name && b.LinkName == a.Name && a.IfIndex > 0 && b.IfIndex > 0 && a.IfIndex != b.IfIndex
}

func guestNamesAvailable(snapshot network.Snapshot, names [4]string) error {
	for _, device := range snapshot.Devices {
		for _, name := range names {
			if device.Name == name {
				return fmt.Errorf("CONFLICT: foreign interface name already exists: %s", name)
			}
		}
	}
	return nil
}

func writeGuestIntent(path string, intent guestWANIntent) error {
	b, err := json.MarshalIndent(intent, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.OpenFile(path+".next", os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(path + ".next")
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(path+".next", path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func requireGuestWANGate(t *testing.T) string {
	t.Helper()
	if os.Getenv("FBI_GO_VM_GUEST_WANS") != "YES" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" || os.Getenv("FBI_GO_VM_SNAPSHOT_CREATED") != "YES" || os.Getenv("FBI_GO_VM_SNAPSHOT_ID") == "" {
		t.Skip("requires the separately approved disposable-VM guest-WAN harness")
	}
	if os.Geteuid() != 0 {
		t.Fatal("guest initial-namespace test requires guest root")
	}
	if _, err := guestRun("systemd-detect-virt", "--vm", "--quiet"); err != nil {
		t.Fatal(err)
	}
	self, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	pid1, err := namespaceIdentity("/proc/1/ns/net")
	if err != nil || self != pid1 {
		t.Fatalf("guest initial namespace mismatch: self=%s pid1=%s err=%v", self, pid1, err)
	}
	workspace := os.Getenv("FBI_GO_VM_TEST_WORKSPACE")
	if !filepath.IsAbs(workspace) || workspace == "/" {
		t.Fatal("fresh absolute VM workspace required")
	}
	st, err := os.Lstat(workspace)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("untrusted VM workspace: %v", err)
	}
	marker, err := os.Lstat(filepath.Join(workspace, ".fbi-go-disposable-test-workspace"))
	if err != nil || !marker.Mode().IsRegular() || marker.Mode().Perm() != 0600 || marker.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("untrusted VM workspace marker: %v", err)
	}
	approval, err := os.Lstat(filepath.Join(workspace, ".fbi-go-guest-wan-approved"))
	if err != nil || !approval.Mode().IsRegular() || approval.Mode().Perm() != 0600 || approval.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatalf("guest-WAN operator approval marker missing: %v", err)
	}
	return workspace
}

func TestVMGuestInitialWANOwnership(t *testing.T) {
	workspace := requireGuestWANGate(t)
	initialNS, _ := namespaceIdentity("/proc/self/ns/net")
	var err error
	baseline, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	var token [5]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(token[:])
	// Kernel interface names have a 15-byte limit. Each name is unique for this
	// operation and still checked against live kernel identity before deletion.
	names := [4]string{"f4a" + id[:7], "f4pa" + id[:7], "f4b" + id[:7], "f4pb" + id[:7]}
	if err := guestNamesAvailable(baseline, names); err != nil {
		t.Fatal(err)
	}
	gateways := [2]*NamespaceEngine{}
	preserveGateway := [2]bool{}
	for i := range gateways {
		gateways[i], err = NewTestNamespace()
		if err != nil {
			t.Fatal(err)
		}
		index := i
		defer func() {
			if !preserveGateway[index] {
				if err := gateways[index].Close(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	intent := guestWANIntent{Version: 1, Operation: id, InitialNS: initialNS, Names: names, Phase: "intent"}
	for i, ns := range gateways {
		intent.GatewayNS[i], err = namespaceIdentity(filepath.Join("/run/netns", ns.Name()))
		if err != nil {
			t.Fatal(err)
		}
	}
	journal := filepath.Join(workspace, "guest-wan-"+id+".json")
	placeholder, err := os.OpenFile(journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatalf("duplicate operation identity: %v", err)
	}
	if err := placeholder.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	created := [2]bool{}
	defer func() {
		// A name, alias or journal entry alone is never deletion authority.
		if current, err := namespaceIdentity("/proc/self/ns/net"); err != nil || current != intent.InitialNS {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: initial namespace changed: %s %v", current, err)
			return
		}
		durable, err := readGuestIntent(journal)
		if err != nil || !reflect.DeepEqual(durable, intent) {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: journal differs from in-memory ownership: %v", err)
			for i := range created {
				if created[i] {
					preserveGateway[i] = true
				}
			}
			return
		}
		clean := true
		for i := range created {
			if !created[i] {
				continue
			}
			if nsID, nsErr := namespaceIdentity(filepath.Join("/run/netns", gateways[i].Name())); nsErr != nil || nsID != intent.GatewayNS[i] {
				t.Errorf("MANUAL_INTERVENTION_REQUIRED: gateway namespace replaced: %s %v", nsID, nsErr)
				preserveGateway[i], clean = true, false
				continue
			}
			link, readErr := guestLinkRead(names[2*i], nil)
			peer, peerErr := guestLinkRead(names[2*i+1], gateways[i])
			if readErr != nil || peerErr != nil || !guestLinkMatches(intent.Links[2*i], link) || !guestLinkMatches(intent.Links[2*i+1], peer) || link.LinkIndex != peer.IfIndex || peer.LinkIndex != link.IfIndex {
				t.Errorf("MANUAL_INTERVENTION_REQUIRED: owned link identity ambiguous: %s: %v %v", names[2*i], readErr, peerErr)
				preserveGateway[i], clean = true, false
				continue
			}
			localIPs, localErr := guestIPv4(names[2*i], nil)
			peerIPs, peerAddrErr := guestIPv4(names[2*i+1], gateways[i])
			if localErr != nil || peerAddrErr != nil || len(localIPs) > 1 || len(peerIPs) > 1 ||
				(intent.LocalIPv4[i] != "" && (len(localIPs) != 1 || localIPs[0] != intent.LocalIPv4[i])) ||
				(intent.PeerIPv4[i] != "" && (len(peerIPs) != 1 || peerIPs[0] != intent.PeerIPv4[i])) {
				t.Errorf("MANUAL_INTERVENTION_REQUIRED: unexpected WAN address: %v %v %v %v", localIPs, peerIPs, localErr, peerAddrErr)
				preserveGateway[i], clean = true, false
				continue
			}
			if intent.LocalIPv4[i] != "" {
				if routeErr := guestConnectedRoute(names[2*i], intent.LocalIPv4[i], nil); routeErr != nil {
					t.Errorf("MANUAL_INTERVENTION_REQUIRED: %v", routeErr)
					preserveGateway[i], clean = true, false
					continue
				}
			}
			if _, err := guestRun("ip", "link", "del", "dev", names[2*i]); err != nil {
				t.Errorf("owned link cleanup: %v", err)
				preserveGateway[i], clean = true, false
			}
		}
		if clean {
			intent.Phase = "clean"
			if err := writeGuestIntent(journal, intent); err != nil {
				t.Error(err)
			}
		}
	}()
	for i := 0; i < 2; i++ {
		local, peer := names[2*i], names[2*i+1]
		if _, err := guestRun("ip", "link", "add", "name", local, "type", "veth", "peer", "name", peer); err != nil {
			t.Fatal(err)
		}
		created[i] = true
		if _, err := guestRun("ip", "link", "set", "dev", peer, "netns", gateways[i].Name()); err != nil {
			t.Fatal(err)
		}
		if _, err := guestRun("ip", "link", "set", "dev", local, "alias", "fbi-go-guest-test:"+id); err != nil {
			t.Fatal(err)
		}
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", peer, "alias", "fbi-go-guest-test:"+id); err != nil {
			t.Fatal(err)
		}
		if _, err := guestRun("udevadm", "settle", "--timeout=10"); err != nil {
			t.Fatal(err)
		}
		intent.Links[2*i], err = guestLinkRead(local, nil)
		if err != nil {
			t.Fatal(err)
		}
		intent.Links[2*i+1], err = guestLinkRead(peer, gateways[i])
		if err != nil {
			t.Fatal(err)
		}
		if intent.Links[2*i].LinkIndex != intent.Links[2*i+1].IfIndex || intent.Links[2*i+1].LinkIndex != intent.Links[2*i].IfIndex {
			t.Fatal("veth peer relationship mismatch")
		}
		intent.Phase = fmt.Sprintf("created-%d", i+1)
		if err := writeGuestIntent(journal, intent); err != nil {
			t.Fatal(err)
		}
		addr, gw := "192.0.2.9/24", "192.0.2.1/24"
		if i == 1 {
			addr, gw = "198.51.100.99/24", "198.51.100.216/24"
		}
		if _, err := guestRun("ip", "addr", "add", addr, "dev", local); err != nil {
			t.Fatal(err)
		}
		if _, err := gateways[i].run("", "ip", "addr", "add", gw, "dev", peer); err != nil {
			t.Fatal(err)
		}
		if _, err := guestRun("ip", "link", "set", "dev", local, "up"); err != nil {
			t.Fatal(err)
		}
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", peer, "up"); err != nil {
			t.Fatal(err)
		}
		intent.LocalIPv4[i], intent.PeerIPv4[i] = addr, gw
		intent.Phase = fmt.Sprintf("configured-%d", i+1)
		if err := writeGuestIntent(journal, intent); err != nil {
			t.Fatal(err)
		}
	}
	// Discovery is real and read-only. A veth is deliberately not an automatic
	// production WAN candidate and has no default route in the initial netns.
	snapshot, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	var selected [2]network.Device
	for i, name := range [2]string{names[0], names[2]} {
		found := false
		for _, d := range snapshot.Devices {
			if d.Name == name {
				selected[i], found = d, true
			}
		}
		if !found || selected[i].Kind != "virtual" || selected[i].Candidate || selected[i].State != "up" {
			t.Fatalf("guest WAN scan mismatch: %+v", selected[i])
		}
		monitor := health.Monitor{State: health.Unknown, Thresholds: health.Thresholds{OfflineFailures: 2, RecoverySuccesses: 2}}
		gw := "192.0.2.1"
		if i == 1 {
			gw = "198.51.100.216"
		}
		if _, err := guestRun("ping", "-c", "1", "-W", "1", "-I", name, gw); err != nil {
			t.Fatal(err)
		}
		if monitor.Observe(true, true, 1) != health.Healthy {
			t.Fatal("gateway health not HEALTHY")
		}
		peer := names[2*i+1]
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", peer, "down"); err != nil {
			t.Fatal(err)
		}
		down, err := network.Scan()
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range down.Devices {
			if d.Name == name && (d.State != "down" || d.ID != selected[i].ID) {
				t.Fatalf("carrier or identity on down: %+v", d)
			}
		}
		if monitor.Observe(false, false, 0) != health.Offline {
			t.Fatal("link loss not OFFLINE")
		}
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", peer, "up"); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 2; j++ {
			if _, err := guestRun("ping", "-c", "1", "-W", "1", "-I", name, gw); err != nil {
				t.Fatal(err)
			}
			monitor.Observe(true, true, 1)
		}
		if monitor.State != health.Healthy {
			t.Fatal("recovery not HEALTHY")
		}
		t.Logf("guest-visible WAN %s ifindex=%d ID=%s gateway=%s health=%s", name, intent.Links[2*i].IfIndex, selected[i].ID, gw, monitor.State)
	}
	for i := range gateways {
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", names[2*i+1], "down"); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for i := range gateways {
			_, _ = gateways[i].run("", "ip", "link", "set", "dev", names[2*i+1], "up")
		}
	}()
	bothDown, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range [2]string{names[0], names[2]} {
		found := false
		for _, d := range bothDown.Devices {
			if d.Name == name {
				found = true
				if d.State != "down" || d.ID != selected[i].ID {
					t.Fatalf("both-down identity/state: %+v", d)
				}
			}
		}
		if !found {
			t.Fatalf("missing WAN after disconnect: %s", name)
		}
	}
	for i := range gateways {
		if _, err := gateways[i].run("", "ip", "link", "set", "dev", names[2*i+1], "up"); err != nil {
			t.Fatal(err)
		}
	}
	for cycle := 0; cycle < 4; cycle++ {
		for i := range gateways {
			if _, err := gateways[i].run("", "ip", "link", "set", "dev", names[2*i+1], "down"); err != nil {
				t.Fatal(err)
			}
			down, err := network.Scan()
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range down.Devices {
				if d.Name == names[2*i] && (d.State != "down" || d.ID != selected[i].ID) {
					t.Fatalf("rapid disconnect mismatch: %+v", d)
				}
			}
			if _, err := gateways[i].run("", "ip", "link", "set", "dev", names[2*i+1], "up"); err != nil {
				t.Fatal(err)
			}
			up, err := network.Scan()
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range up.Devices {
				if d.Name == names[2*i] && (d.State != "up" || d.ID != selected[i].ID) {
					t.Fatalf("rapid reconnect mismatch: %+v", d)
				}
			}
		}
	}
	t.Log("guest-visible carrier: each WAN down/up, both down, and four rapid cycles observed without identity change")
	// A carrier-up link with its gateway address removed is reachable only at
	// layer 2. Health must not call it Internet-healthy on link state alone.
	probeHealth := health.Monitor{State: health.Healthy, Thresholds: health.Thresholds{OfflineFailures: 2, RecoverySuccesses: 2}}
	if _, err := gateways[0].run("", "ip", "addr", "del", intent.PeerIPv4[0], "dev", names[1]); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = gateways[0].run("", "ip", "addr", "replace", intent.PeerIPv4[0], "dev", names[1]) }()
	carrierUp, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range carrierUp.Devices {
		if d.Name == names[0] && d.State != "up" {
			t.Fatalf("gateway outage changed carrier: %+v", d)
		}
	}
	if _, err := guestRun("ping", "-c", "1", "-W", "1", "-I", names[0], "192.0.2.1"); err == nil {
		t.Fatal("unavailable gateway unexpectedly reachable")
	}
	probeHealth.Observe(true, false, 0)
	if probeHealth.Observe(true, false, 0) != health.Offline {
		t.Fatal("probe failures did not mark carrier-up WAN OFFLINE")
	}
	if _, err := gateways[0].run("", "ip", "addr", "add", intent.PeerIPv4[0], "dev", names[1]); err != nil {
		t.Fatal(err)
	}
	// Removing the gateway address can leave a FAILED neighbor entry. Wait for
	// real probe success after restoration instead of assuming the first ARP
	// request succeeds immediately; do not alter the neighbor cache manually.
	for i := 0; i < 2; i++ {
		deadline := time.Now().Add(8 * time.Second)
		for {
			_, probeErr := guestRun("ping", "-c", "1", "-W", "1", "-I", names[0], "192.0.2.1")
			if probeErr == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("gateway did not recover after address restoration: %v", probeErr)
			}
			time.Sleep(200 * time.Millisecond)
		}
		probeHealth.Observe(true, true, 1)
	}
	if probeHealth.State != health.Healthy {
		t.Fatal("gateway probe recovery failed")
	}
	t.Log("gateway reachability: carrier stayed up while probe health became OFFLINE, then recovered")
	nm, err := guestRun("nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range [2]string{names[0], names[2]} {
		found := false
		for _, line := range strings.Split(nm, "\n") {
			if !strings.HasPrefix(line, name+":") {
				continue
			}
			found = true
			if !strings.Contains(line, ":unmanaged:") {
				t.Fatalf("NetworkManager unexpectedly manages %s: %s", name, line)
			}
			t.Logf("NetworkManager test WAN: %s", line)
		}
		if !found {
			t.Fatalf("NetworkManager device status omitted %s: %.400s", name, nm)
		}
	}
	// Compare the preserved identity before any normal cleanup. Replacing a
	// link with the same name/alias, peer or ifindex must fail this predicate.
	for i := range intent.Links {
		var ns *NamespaceEngine
		if i%2 == 1 {
			ns = gateways[i/2]
		}
		actual, err := guestLinkRead(names[i], ns)
		if err != nil || !guestLinkMatches(intent.Links[i], actual) {
			t.Fatalf("CONFLICT: link fingerprint changed: %s %v", names[i], err)
		}
	}
	// PlanM2 requires default routes, which are prohibited here. A separate
	// test-only copy models the two independently probed gateways for planning;
	// the resulting plan is never given to an executor in the initial netns.
	model := network.Snapshot{Devices: []network.Device{selected[0], selected[1]}}
	for i := range model.Devices {
		model.Devices[i].Candidate = true
	}
	model.Routes = []network.Route{{Family: "ipv4", Destination: "0.0.0.0/0", Interface: names[0], Gateway: "192.0.2.1", Table: 254}, {Family: "ipv4", Destination: "0.0.0.0/0", Interface: names[2], Gateway: "198.51.100.216", Table: 254}}
	plan := PlanM2(Inventory{Snapshot: model, RulesComplete: true, TablesComplete: true, MarksComplete: true, NFTComplete: true, WANHealth: map[string]health.State{names[0]: health.Healthy, names[2]: health.Healthy}, IPv6Policy: "system"})
	if !plan.SafeToApply || len(plan.WANs) != 2 {
		t.Fatalf("test-only plan invalid: %+v", plan)
	}
	for i := range plan.WANs {
		if plan.WANs[i].Interface != names[2*i] {
			t.Fatalf("plan WAN identity mismatch: %+v", plan.WANs)
		}
	}
	t.Logf("test-only PlanM2 allocations=%+v; initial-namespace apply forbidden", plan.WANs)
	intent.Phase = "verified"
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("FBI_GO_VM_GUEST_WAN_CRASH_AFTER_VERIFIED") == "YES" {
		// The parent test recovers this durable, exact-match state after a real
		// subprocess SIGKILL. Defers must not run in this branch.
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		t.Fatal("SIGKILL did not terminate child")
	}
	// The gate also rejects a substituted fingerprint without touching the
	// actual link. The real kernel object is checked again in deferred cleanup.
	tampered := intent.Links[0]
	tampered.IfIndex++
	if guestLinkMatches(tampered, intent.Links[0]) {
		t.Fatal("replaced ifindex accepted")
	}
	if reflect.DeepEqual(selected[0], selected[1]) {
		t.Fatal("WAN identities collapsed")
	}
}

func TestGuestLinkFingerprint(t *testing.T) {
	a := guestLink{IfIndex: 12, Name: "f4a123", LinkIndex: 13, Address: "02:00:00:00:00:01", Alias: "fbi-go-guest-test:abc"}
	a.LinkInfo.Kind = "veth"
	if !guestLinkMatches(a, a) {
		t.Fatal("exact owned link rejected")
	}
	for _, change := range []func(*guestLink){func(b *guestLink) { b.IfIndex++ }, func(b *guestLink) { b.LinkIndex++ }, func(b *guestLink) { b.LinkName = "foreign" }, func(b *guestLink) { b.Address = "02:00:00:00:00:02" }, func(b *guestLink) { b.Alias = "foreign" }, func(b *guestLink) { b.LinkInfo.Kind = "dummy" }} {
		b := a
		change(&b)
		if guestLinkMatches(a, b) {
			t.Fatal("foreign replacement accepted")
		}
	}
	if err := guestNamesAvailable(network.Snapshot{Devices: []network.Device{{Name: "foreign"}}}, [4]string{"foreign", "a", "b", "c"}); err == nil {
		t.Fatal("foreign interface name collision accepted")
	}
}

func TestGuestWANJournalIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned.json")
	intent := guestWANIntent{Version: 1, Operation: "unit", InitialNS: "4:123", Phase: "intent"}
	if err := writeGuestIntent(path, intent); err != nil {
		t.Fatal(err)
	}
	read, err := readGuestIntent(path)
	if err != nil || !reflect.DeepEqual(read, intent) {
		t.Fatalf("durable intent mismatch: %+v %v", read, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuestIntent(path); err == nil {
		t.Fatal("world-readable journal accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{bad-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuestIntent(path); err == nil {
		t.Fatal("corrupt journal accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", path); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuestIntent(path); err == nil {
		t.Fatal("symlink journal accepted")
	}
}

// TestVMGuestWANRecover is an opt-in recovery gate for a previous test run.
// It accepts only the fixed, root-owned workspace and its own journals. A
// namespace name is discovered by matching a pinned FD to the durable
// namespace identity; neither a name nor an alias alone grants cleanup.
func TestVMGuestWANRecover(t *testing.T) {
	workspace := requireGuestWANGate(t)
	recoverGuestWAN(t, workspace)
}

func recoverGuestWAN(t *testing.T, workspace string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(workspace, "guest-wan-*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected exactly one guest-WAN journal: %d %v", len(files), err)
	}
	journal := files[0]
	intent, err := readGuestIntent(journal)
	if err != nil || intent.Version != 1 || intent.Operation == "" || filepath.Base(journal) != "guest-wan-"+intent.Operation+".json" {
		t.Fatalf("invalid ownership intent: %v", err)
	}
	initialNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil || initialNS != intent.InitialNS {
		t.Fatalf("wrong initial namespace: %s expected %s: %v", initialNS, intent.InitialNS, err)
	}
	if intent.Phase == "clean" {
		t.Log("CLEAN: already reconciled")
		return
	}
	var gateways [2]*NamespaceEngine
	for i := range gateways {
		entries, err := os.ReadDir("/run/netns")
		if err != nil {
			t.Fatal(err)
		}
		var matched string
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "fbi-m2t-") {
				continue
			}
			identity, err := namespaceIdentity(filepath.Join("/run/netns", entry.Name()))
			if err == nil && identity == intent.GatewayNS[i] {
				if matched != "" {
					t.Fatal("ambiguous namespace aliases")
				}
				matched = entry.Name()
			}
		}
		if matched == "" {
			t.Fatalf("MANUAL_INTERVENTION_REQUIRED: gateway namespace %d missing", i)
		}
		path := filepath.Join("/run/netns", matched)
		fd, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		identity, err := fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		nsJournal := filepath.Join(workspace, "journal", matched+".json")
		record, err := loadJournal(nsJournal)
		if err != nil || record.Identity != intent.GatewayNS[i] || record.Phase != "created" || record.Plan != nil {
			t.Fatalf("MANUAL_INTERVENTION_REQUIRED: gateway journal mismatch: %v", err)
		}
		gateways[i] = &NamespaceEngine{name: matched, fd: fd, identity: identity, tableName: record.NFTTable, journalPath: nsJournal, journalPhase: "created"}
		if err := gateways[i].validate(); err != nil {
			t.Fatal(err)
		}
	}
	// Validate all resources before deleting any, so a conflict cannot cause
	// partial cleanup of the other link.
	for i := 0; i < 2; i++ {
		local, localErr := guestLinkRead(intent.Names[2*i], nil)
		peer, peerErr := guestLinkRead(intent.Names[2*i+1], gateways[i])
		if localErr != nil || peerErr != nil || !guestLinkMatches(intent.Links[2*i], local) || !guestLinkMatches(intent.Links[2*i+1], peer) || local.LinkIndex != peer.IfIndex || peer.LinkIndex != local.IfIndex {
			t.Fatalf("MANUAL_INTERVENTION_REQUIRED: WAN %d identity differs: %v %v", i, localErr, peerErr)
		}
		localIPs, localAddrErr := guestIPv4(local.Name, nil)
		peerIPs, peerAddrErr := guestIPv4(peer.Name, gateways[i])
		if localAddrErr != nil || peerAddrErr != nil || len(localIPs) != 1 || len(peerIPs) != 1 || localIPs[0] != intent.LocalIPv4[i] || peerIPs[0] != intent.PeerIPv4[i] {
			t.Fatalf("MANUAL_INTERVENTION_REQUIRED: WAN %d addresses differ: %v %v %v %v", i, localIPs, peerIPs, localAddrErr, peerAddrErr)
		}
		if err := guestConnectedRoute(local.Name, intent.LocalIPv4[i], nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := guestRun("ip", "link", "del", "dev", intent.Names[2*i]); err != nil {
			t.Fatal(err)
		}
		if err := gateways[i].Close(); err != nil {
			t.Fatal(err)
		}
	}
	intent.Phase = "clean"
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	t.Log("RECOVERED: exact matching owned veth pairs and gateway namespaces removed")
}

func TestVMGuestInitialWANCrashRecovery(t *testing.T) {
	workspace := requireGuestWANGate(t)
	crashWorkspace := filepath.Join(workspace, "crash-recovery")
	if err := os.Mkdir(crashWorkspace, 0700); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{".fbi-go-disposable-test-workspace", ".fbi-go-guest-wan-approved"} {
		f, err := os.OpenFile(filepath.Join(crashWorkspace, marker), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	journalDir := filepath.Join(crashWorkspace, "journal")
	if err := os.Mkdir(journalDir, 0700); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestVMGuestInitialWANOwnership$", "-test.v")
	child.Env = append(os.Environ(), "FBI_GO_VM_TEST_WORKSPACE="+crashWorkspace, "FBI_GO_JOURNAL_DIR="+journalDir, "FBI_GO_VM_GUEST_WAN_CRASH_AFTER_VERIFIED=YES")
	output, err := child.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("expected SIGKILL child, got %v: %.400s", err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("expected SIGKILL, got %v: %.400s", err, output)
	}
	recoverGuestWAN(t, crashWorkspace)
	recoverGuestWAN(t, crashWorkspace) // Idempotent second pass.
	if entries, err := os.ReadDir(journalDir); err != nil || len(entries) != 0 {
		t.Fatalf("owned namespace journals remain: %v %v", entries, err)
	}
	t.Log("SIGKILL after durable verified snapshot: RECOVERED; repeated recovery CLEAN")
}

func TestVMGuestWANForeignNameCollision(t *testing.T) {
	workspace := requireGuestWANGate(t)
	initialNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	var token [5]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(token[:])
	names := [4]string{"f4f" + id[:7], "f4fp" + id[:7]}
	baseline, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if err := guestNamesAvailable(baseline, names); err != nil {
		t.Fatal(err)
	}
	intent := guestWANIntent{Version: 1, Operation: id, InitialNS: initialNS, Names: names, Phase: "foreign-intent"}
	journal := filepath.Join(workspace, "foreign-sentinel-"+id+".json")
	f, err := os.OpenFile(journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := guestRun("ip", "link", "add", "name", names[0], "type", "veth", "peer", "name", names[1]); err != nil {
		t.Fatal(err)
	}
	created := true
	defer func() {
		if !created {
			return
		}
		current, err := namespaceIdentity("/proc/self/ns/net")
		if err != nil || current != intent.InitialNS {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: foreign sentinel namespace changed: %v", err)
			return
		}
		durable, err := readGuestIntent(journal)
		if err != nil || !reflect.DeepEqual(durable, intent) {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: foreign sentinel journal mismatch: %v", err)
			return
		}
		a, aErr := guestLinkRead(names[0], nil)
		b, bErr := guestLinkRead(names[1], nil)
		if aErr != nil || bErr != nil || !guestLinkMatches(intent.Links[0], a) || !guestLinkMatches(intent.Links[1], b) || !guestSameNSPeers(a, b) {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: foreign sentinel changed: %v %v", aErr, bErr)
			return
		}
		if _, err := guestRun("ip", "link", "del", "dev", names[0]); err != nil {
			t.Error(err)
			return
		}
		intent.Phase = "clean"
		if err := writeGuestIntent(journal, intent); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 2; i++ {
		if _, err := guestRun("ip", "link", "set", "dev", names[i], "alias", "foreign-sentinel:"+id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := guestRun("udevadm", "settle", "--timeout=10"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		intent.Links[i], err = guestLinkRead(names[i], nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	intent.Phase = "foreign-present"
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	withForeign, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if err := guestNamesAvailable(withForeign, names); err == nil || !strings.Contains(err.Error(), "CONFLICT") {
		t.Fatalf("foreign name collision not rejected: %v", err)
	}
	for i := 0; i < 2; i++ {
		actual, err := guestLinkRead(names[i], nil)
		if err != nil || !guestLinkMatches(intent.Links[i], actual) {
			t.Fatalf("foreign sentinel modified by rejection: %s %v", names[i], err)
		}
	}
	t.Log("CONFLICT: foreign interface name rejected; both kernel objects preserved until fixture-owned cleanup")
	previous := [2]guestLink{intent.Links[0], intent.Links[1]}
	if !guestSameNSPeers(previous[0], previous[1]) {
		t.Fatal("foreign fixture peer relation invalid before replacement")
	}
	if _, err := guestRun("ip", "link", "del", "dev", names[0]); err != nil {
		t.Fatal(err)
	}
	created = false
	if _, err := guestRun("ip", "link", "add", "name", names[0], "type", "veth", "peer", "name", names[1]); err != nil {
		t.Fatal(err)
	}
	created = true
	for i := 0; i < 2; i++ {
		if _, err := guestRun("ip", "link", "set", "dev", names[i], "alias", "foreign-sentinel:"+id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := guestRun("udevadm", "settle", "--timeout=10"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		intent.Links[i], err = guestLinkRead(names[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		if guestLinkMatches(previous[i], intent.Links[i]) {
			t.Fatal("recreated interface retained old ownership fingerprint")
		}
	}
	if !guestSameNSPeers(intent.Links[0], intent.Links[1]) {
		t.Fatal("replacement fixture peer relation invalid")
	}
	intent.Phase = "foreign-replacement"
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	t.Log("CONFLICT: replacement with reused names and alias rejected by original fingerprint; replacement preserved until fixture-owned cleanup")
}
