//go:build integration

package routing

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVMGuestVisibleWANDataPlane(t *testing.T) {
	_ = requireGuestWANGate(t)
	verifyVMExecutorTestGate(t)
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	traffic := make(chan appTrafficInterval, 2)
	outage := make(chan guestOutage, 2)
	trafficRelease := make(chan struct{})
	outageFailure := make(chan struct{})
	outageDone := make(chan error, 1)
	go func() {
		links := make(map[string]guestOutage, 2)
		for len(links) < 2 {
			select {
			case link := <-outage:
				links[link.wan] = link
			case <-time.After(20 * time.Second):
				outageDone <- fmt.Errorf("managed applications did not reach WAN outage barrier")
				close(outageFailure)
				return
			}
		}
		err := exerciseGuestWANOutages(links["wan-a"], links["wan-b"])
		outageDone <- err
		if err != nil {
			close(outageFailure)
		} else {
			close(trafficRelease)
		}
	}()
	startWorkerBarrier(ready, release)
	t.Run("applications", func(t *testing.T) {
		for _, wan := range []string{"wan-a", "wan-b"} {
			wan := wan
			t.Run(wan, func(t *testing.T) {
				t.Parallel()
				runExecutorProcessBoundary(t, NewTestNamespace, false, wan, &workerBarrier{ready: ready, release: release, traffic: traffic, outage: outage, trafficRelease: trafficRelease, outageFailure: outageFailure}, true)
			})
		}
	})
	if err := <-outageDone; err != nil {
		t.Fatal(err)
	}
	t.Log("guest WAN live outage: each selected peer and both peers down/up while both managed apps remained alive; unaffected and restored WANs delivered new TCP flows; STRICT leak marker absent at both gateways")
	spans := map[string]appTrafficInterval{}
	for i := 0; i < 2; i++ {
		select {
		case span := <-traffic:
			spans[span.wan] = span
		case <-time.After(time.Second):
			t.Fatal("managed traffic timing evidence missing")
		}
	}
	a, b := spans["wan-a"], spans["wan-b"]
	start, end := max(a.startNS, b.startNS), min(a.endNS, b.endNS)
	if end <= start {
		t.Fatalf("managed packet intervals did not overlap: A=%+v B=%+v", a, b)
	}
	t.Logf("guest-visible managed TCP traffic overlap: %d ms", (end-start)/int64(time.Millisecond))
}

func exerciseGuestWANOutages(a, b guestOutage) error {
	if a.app == nil || b.app == nil || a.gateway == nil || b.gateway == nil || a.guestWAN == "" || b.guestWAN == "" {
		return fmt.Errorf("owned guest WAN outage identities missing")
	}
	for _, pair := range [][2]guestOutage{{a, b}, {b, a}} {
		disabled, surviving := pair[0], pair[1]
		peer := "fbi_aa"
		if disabled.wan == "wan-b" {
			peer = "fbi_bb"
		}
		if _, err := disabled.gateway.run("", "ip", "link", "set", "dev", peer, "down"); err != nil {
			return fmt.Errorf("disconnect %s owned gateway peer: %w", disabled.wan, err)
		}
		if err := guestWANCarrier(disabled.guestWAN, "down"); err != nil {
			return err
		}
		if err := guestCaptureCarrier(disabled, "carrier_down"); err != nil {
			return err
		}
		strict, err := filepath.Abs("testdata/managed_strict_probe.py")
		if err != nil {
			return err
		}
		if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: disabled.app.fd, NamespaceName: disabled.app.Name(), WAN: disabled.wan,
			Command: []string{disabled.python, strict}, GuestVMTest: true}); err != nil {
			return fmt.Errorf("STRICT %s during gateway disconnect: %w", disabled.wan, err)
		}
		if err := guestFlowProbe(surviving, "unaffected-"+disabled.wan); err != nil {
			return err
		}
		if err := guestNoStrictLeak(a.flowLog, b.flowLog); err != nil {
			return err
		}
		if _, err := disabled.gateway.run("", "ip", "link", "set", "dev", peer, "up"); err != nil {
			return fmt.Errorf("restore %s owned gateway peer: %w", disabled.wan, err)
		}
		if err := guestWANCarrier(disabled.guestWAN, "up"); err != nil {
			return err
		}
		if err := guestCaptureCarrier(disabled, "carrier_up"); err != nil {
			return err
		}
		if err := guestFlowProbe(disabled, "restored-"+disabled.wan); err != nil {
			return err
		}
	}
	// Test simultaneous loss while both managed applications remain alive.
	for _, link := range []guestOutage{a, b} {
		peer := "fbi_aa"
		if link.wan == "wan-b" {
			peer = "fbi_bb"
		}
		if _, err := link.gateway.run("", "ip", "link", "set", "dev", peer, "down"); err != nil {
			return fmt.Errorf("disconnect both WANs at %s: %w", link.wan, err)
		}
	}
	for _, link := range []guestOutage{a, b} {
		if err := guestWANCarrier(link.guestWAN, "down"); err != nil {
			return err
		}
		strict, err := filepath.Abs("testdata/managed_strict_probe.py")
		if err != nil {
			return err
		}
		if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: link.app.fd, NamespaceName: link.app.Name(), WAN: link.wan,
			Command: []string{link.python, strict}, GuestVMTest: true}); err != nil {
			return fmt.Errorf("STRICT %s while both WANs disconnected: %w", link.wan, err)
		}
	}
	if err := guestNoStrictLeak(a.flowLog, b.flowLog); err != nil {
		return err
	}
	for _, link := range []guestOutage{a, b} {
		peer := "fbi_aa"
		if link.wan == "wan-b" {
			peer = "fbi_bb"
		}
		if _, err := link.gateway.run("", "ip", "link", "set", "dev", peer, "up"); err != nil {
			return fmt.Errorf("restore both WANs at %s: %w", link.wan, err)
		}
		if err := guestWANCarrier(link.guestWAN, "up"); err != nil {
			return err
		}
		if err := guestFlowProbe(link, "both-restored-"+link.wan); err != nil {
			return err
		}
	}
	return nil
}

func guestCaptureCarrier(link guestOutage, event string) error {
	deadline := time.Now().Add(3 * time.Second)
	for _, path := range []string{link.captureGuest, link.captureGateway} {
		if path == "" {
			return fmt.Errorf("capture path missing for %s", link.wan)
		}
		for {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			found, err := guestCaptureEvent(data, event)
			if err != nil {
				return fmt.Errorf("parse %s carrier evidence: %w", path, err)
			}
			if found {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s %s capture did not observe %s", link.wan, path, event)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

func guestCaptureEvent(data []byte, event string) (bool, error) {
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var row struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return false, err
		}
		if row.Event == event {
			return true, nil
		}
	}
	return false, nil
}

func TestGuestCaptureEventParsing(t *testing.T) {
	for _, input := range []string{`{"event": "carrier_down"}`, `{"event":"carrier_down"}`} {
		found, err := guestCaptureEvent([]byte(input), "carrier_down")
		if err != nil || !found {
			t.Fatalf("JSONL event %q: found=%v err=%v", input, found, err)
		}
	}
	if found, err := guestCaptureEvent([]byte(`{"event":"carrier_up"}`), "carrier_down"); err != nil || found {
		t.Fatalf("wrong event: found=%v err=%v", found, err)
	}
	if _, err := guestCaptureEvent([]byte(`{"event":`), "carrier_down"); err == nil {
		t.Fatal("malformed JSONL event accepted")
	}
}

func guestWANCarrier(name, want string) error {
	deadline := time.Now().Add(3 * time.Second)
	for {
		inventory, err := network.Scan()
		if err != nil {
			return err
		}
		for _, device := range inventory.Devices {
			if device.Name == name && device.State == want {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("guest-visible WAN %s carrier did not become %s", name, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func guestFlowProbe(link guestOutage, marker string) error {
	flow, err := filepath.Abs("testdata/flow_client.py")
	if err != nil {
		return err
	}
	if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: link.app.fd, NamespaceName: link.app.Name(), WAN: link.wan,
		Command: []string{link.python, flow, "tcp_affinity", marker, "4"}, GuestVMTest: true}); err != nil {
		return fmt.Errorf("%s flow through %s: %w", marker, link.wan, err)
	}
	log, err := os.ReadFile(link.flowLog)
	if err != nil {
		return err
	}
	if !strings.Contains(string(log), marker) || !strings.Contains(string(log), link.source) {
		return fmt.Errorf("%s missing observed gateway flow from %s", marker, link.source)
	}
	return nil
}

func guestNoStrictLeak(logs ...string) error {
	for _, path := range logs {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "managed-strict-leak") {
			return fmt.Errorf("STRICT probe reached synthetic gateway: %s", path)
		}
	}
	return nil
}

// TestVMGuestDataPlaneStaleRecovery is a separate opt-in recovery step for a
// failed guest data-plane experiment. It accepts only app namespace identities
// cross-linked from the durable bridge journals and preserves every conflict.
func TestVMGuestDataPlaneStaleRecovery(t *testing.T) {
	if os.Getenv("FBI_GO_VM_RECOVER_STALE") != "YES" {
		t.Skip("explicit stale guest data-plane recovery not requested")
	}
	workspace := requireGuestWANGate(t)
	paths, err := filepath.Glob(filepath.Join(workspace, "guest-data-*.json"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("two durable guest-data journals required: %d %v", len(paths), err)
	}
	identities := map[string]bool{}
	for _, path := range paths {
		intent, err := readGuestIntent(path)
		if err != nil || intent.Version != 2 || intent.Phase != "clean" || filepath.Base(path) != "guest-data-"+intent.Operation+".json" {
			t.Fatalf("guest bridge journal not clean: %s %v", path, err)
		}
		identities[intent.GatewayNS[1]] = true
	}
	if len(identities) != 2 {
		t.Fatal("application namespace identities overlap")
	}
	journalDir := filepath.Join(workspace, "journal")
	entries, err := os.ReadDir(journalDir)
	if err != nil || len(entries) > 2 {
		t.Fatalf("unexpected stale application journal count: %d %v", len(entries), err)
	}
	if len(entries) == 0 {
		t.Log("CLEAN: no stale application journals remain")
		return
	}
	for _, entry := range entries {
		path := filepath.Join(journalDir, entry.Name())
		j, err := loadJournal(path)
		if err != nil || !identities[j.Identity] || j.Phase != "active" || j.Plan == nil || entry.Name() != j.Name+".json" {
			t.Fatalf("stale journal ownership mismatch: %s %v", path, err)
		}
		if output, err := guestRun("ip", "netns", "pids", j.Name); err != nil || strings.TrimSpace(output) != "" {
			t.Fatalf("application still runs in stale namespace %s: %.200s %v", j.Name, output, err)
		}
		nsPath := filepath.Join("/run/netns", j.Name)
		identity, err := namespaceIdentity(nsPath)
		if err != nil || identity != j.Identity {
			t.Fatalf("stale namespace identity changed: %s %v", identity, err)
		}
		fd, err := os.Open(nsPath)
		if err != nil {
			t.Fatal(err)
		}
		info, err := fd.Stat()
		if err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		e := &NamespaceEngine{name: j.Name, tableName: j.NFTTable, fd: fd, identity: info, journalPath: path, journalPhase: j.Phase, nftState: j.NFTState, operationID: j.OperationID, nftScriptHash: j.NFTScriptHash, ipv6GuardIntent: j.IPv6GuardIntent, ipv6GuardState: j.IPv6GuardState, ipv6GuardHash: j.IPv6GuardHash, applied: j.Plan}
		if err := e.validate(); err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		// The fixture created this empty sentinel after the authorized apply.
		// Verify it has no chain, rule or ownership comment before fixture cleanup.
		foreign, err := e.run("", "nft", "-j", "list", "table", "ip", "fbi_foreign_process")
		if err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		var doc struct {
			NFTables []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(foreign), &doc); err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		tables := 0
		for _, item := range doc.NFTables {
			for kind, raw := range item {
				if kind == "metainfo" {
					continue
				}
				if kind != "table" {
					_ = fd.Close()
					t.Fatal("foreign sentinel contains unexpected object")
				}
				var table struct{ Family, Name, Comment string }
				if json.Unmarshal(raw, &table) != nil || table.Family != "ip" || table.Name != "fbi_foreign_process" || table.Comment != "" {
					_ = fd.Close()
					t.Fatal("foreign sentinel identity changed")
				}
				tables++
			}
		}
		if tables != 1 {
			_ = fd.Close()
			t.Fatal("foreign sentinel table count differs")
		}
		if _, err := e.run("", "nft", "delete", "table", "ip", "fbi_foreign_process"); err != nil {
			_ = fd.Close()
			t.Fatal(err)
		}
		if err := e.Close(); err != nil {
			t.Fatalf("stale executor recovery preserved on conflict: %s: %v", j.Name, err)
		}
		t.Logf("RECOVERED: stale application namespace %s exact journal and kernel resources", j.Name)
	}
}

// recoverPrecommittedBridge handles only the narrow bridge-only crash window.
// The random MAC and requested ifindex are installed atomically with link
// creation and were persisted before that mutation. A bridge with ports, addresses, routes or foreign
// references is never inferred to be ours from its name alone.
func recoverPrecommittedBridge(path string) (string, error) {
	intent, err := readGuestIntent(path)
	if err != nil {
		return "", err
	}
	if intent.Version != 2 || intent.Phase != "intent" && intent.Phase != "clean" ||
		len(intent.Operation) != 10 || intent.BridgeName != "f4br"+intent.Operation[:6] ||
		intent.Bridge.Address != bridgeMACFromOperation(intent.Operation) ||
		intent.Bridge.IfIndex != bridgeIndexFromOperation(intent.Operation) || intent.Bridge.LinkInfo.Kind != "bridge" ||
		intent.Bridge.Name != "" || intent.Bridge.Alias != "" || intent.Bridge.Master != "" ||
		intent.Names != [4]string{} || intent.Links != [4]guestLink{} ||
		intent.GatewayNS != [2]string{} || intent.LocalIPv4 != [2]string{} || intent.PeerIPv4 != [2]string{} {
		return "MANUAL_INTERVENTION_REQUIRED", fmt.Errorf("incomplete or incompatible bridge recovery intent")
	}
	if _, err := hex.DecodeString(intent.Operation); err != nil {
		return "MANUAL_INTERVENTION_REQUIRED", fmt.Errorf("invalid precommitted operation ID: %w", err)
	}
	currentNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil || currentNS != intent.InitialNS {
		return "CONFLICT", fmt.Errorf("initial namespace differs: expected=%s actual=%s: %v", intent.InitialNS, currentNS, err)
	}
	raw, err := guestRun("ip", "-j", "-d", "link", "show")
	if err != nil {
		return "CONFLICT", err
	}
	var links []guestLink
	if err := json.Unmarshal([]byte(raw), &links); err != nil {
		return "CONFLICT", err
	}
	var match *guestLink
	for i := range links {
		if links[i].Name == intent.BridgeName || links[i].Address == intent.Bridge.Address || links[i].IfIndex == intent.Bridge.IfIndex {
			if links[i].Name != intent.BridgeName || links[i].Address != intent.Bridge.Address || links[i].IfIndex != intent.Bridge.IfIndex || match != nil {
				return "CONFLICT", fmt.Errorf("precommitted bridge identity was replaced or duplicated")
			}
			match = &links[i]
		}
	}
	if match == nil {
		if intent.Phase != "clean" {
			intent.Phase = "clean"
			if err := writeGuestIntent(path, intent); err != nil {
				return "", err
			}
		}
		return "CLEAN", nil
	}
	if intent.Phase == "clean" || match.IfIndex <= 0 || match.LinkInfo.Kind != "bridge" ||
		match.Master != "" || match.LinkIndex != 0 || match.LinkName != "" || match.Alias != "" {
		return "CONFLICT", fmt.Errorf("precommitted bridge attributes differ")
	}
	for _, args := range [][]string{
		{"ip", "-j", "link", "show", "master", intent.BridgeName},
		{"ip", "-j", "-4", "route", "show", "dev", intent.BridgeName},
		{"ip", "-j", "-6", "route", "show", "dev", intent.BridgeName},
	} {
		raw, err := guestRun(args...)
		if err != nil {
			return "CONFLICT", err
		}
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(raw), &entries); err != nil || len(entries) != 0 {
			return "CONFLICT", fmt.Errorf("bridge has members or routes: %s: %v", intent.BridgeName, err)
		}
	}
	for _, family := range []string{"-4", "-6"} {
		raw, err := guestRun("ip", "-j", family, "addr", "show", "dev", intent.BridgeName)
		if err != nil {
			return "CONFLICT", err
		}
		var devices []struct {
			Addresses []json.RawMessage `json:"addr_info"`
		}
		if err := json.Unmarshal([]byte(raw), &devices); err != nil || len(devices) > 1 || len(devices) == 1 && len(devices[0].Addresses) != 0 {
			return "CONFLICT", fmt.Errorf("bridge has unexpected %s address: %v", family, err)
		}
		raw, err = guestRun("ip", "-j", family, "rule", "show")
		if err != nil || strings.Contains(raw, intent.BridgeName) {
			return "CONFLICT", fmt.Errorf("bridge is referenced by %s policy rule: %v", family, err)
		}
	}
	raw, err = guestRun("nft", "-j", "-s", "list", "ruleset")
	if err != nil || strings.Contains(raw, intent.BridgeName) {
		return "CONFLICT", fmt.Errorf("bridge is referenced by nftables or ruleset is unreadable: %v", err)
	}
	if _, err := guestRun("ip", "link", "del", "dev", intent.BridgeName); err != nil {
		return "", err
	}
	intent.Phase = "clean"
	if err := writeGuestIntent(path, intent); err != nil {
		return "", err
	}
	return "RECOVERED", nil
}

func bridgeMACFromOperation(operation string) string {
	if len(operation) != 10 {
		return ""
	}
	return fmt.Sprintf("02:%s:%s:%s:%s:%s", operation[0:2], operation[2:4], operation[4:6], operation[6:8], operation[8:10])
}

func bridgeIndexFromOperation(operation string) int {
	decoded, err := hex.DecodeString(operation)
	if err != nil || len(decoded) != 5 {
		return 0
	}
	return 1<<20 + int(decoded[0])<<16 + int(decoded[1])<<8 + int(decoded[2])
}

func TestBridgePrecommittedIdentity(t *testing.T) {
	operation := "0123456789"
	if got := bridgeMACFromOperation(operation); got != "02:01:23:45:67:89" {
		t.Fatalf("unexpected bridge MAC: %s", got)
	}
	if got := bridgeIndexFromOperation(operation); got != 1<<20+0x012345 {
		t.Fatalf("unexpected bridge index: %d", got)
	}
	if bridgeIndexFromOperation("not-hex-id") != 0 {
		t.Fatal("invalid operation ID produced an ifindex")
	}
}

func TestVMGuestBridgePartialCrashRecovery(t *testing.T) {
	workspace := requireGuestWANGate(t)
	if os.Getenv("FBI_GO_VM_BRIDGE_RECOVER_STALE") == "YES" {
		paths, err := filepath.Glob(filepath.Join(workspace, "guest-data-*.json"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("one stale bridge intent required: %v", err)
		}
		result, err := recoverPrecommittedBridge(paths[0])
		if err != nil {
			t.Fatalf("stale bridge recovery: %s %v", result, err)
		}
		t.Logf("stale bridge recovery: %s", result)
		return
	}
	if point := os.Getenv("FBI_GO_VM_BRIDGE_CRASH_POINT"); point != "" {
		paths, err := filepath.Glob(filepath.Join(workspace, "guest-data-*.json"))
		if err != nil || len(paths) != 1 {
			t.Fatalf("one precommitted bridge journal required: %v", err)
		}
		intent, err := readGuestIntent(paths[0])
		if err != nil || intent.Phase != "intent" || intent.Bridge.Address != bridgeMACFromOperation(intent.Operation) {
			t.Fatalf("invalid durable bridge intent: %v", err)
		}
		if point == "after-create" {
			if _, err := guestRun("ip", "link", "add", "name", intent.BridgeName, "index", fmt.Sprint(intent.Bridge.IfIndex), "address", intent.Bridge.Address, "type", "bridge", "stp_state", "0"); err != nil {
				t.Fatal(err)
			}
		} else if point != "before-create" {
			t.Fatal("unknown bridge crash point")
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		t.Fatal("SIGKILL did not terminate child")
	}
	for _, point := range []string{"before-create", "after-create"} {
		t.Run(point, func(t *testing.T) {
			caseWorkspace := filepath.Join(workspace, "bridge-crash-"+point)
			if err := os.Mkdir(caseWorkspace, 0700); err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{".fbi-go-disposable-test-workspace", ".fbi-go-guest-wan-approved"} {
				f, err := os.OpenFile(filepath.Join(caseWorkspace, marker), os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var token [5]byte
			if _, err := rand.Read(token[:]); err != nil {
				t.Fatal(err)
			}
			id := hex.EncodeToString(token[:])
			bridge := "f4br" + id[:6]
			if _, err := guestLinkRead(bridge, nil); err == nil {
				t.Fatal("foreign bridge name collision")
			}
			initialNS, err := namespaceIdentity("/proc/self/ns/net")
			if err != nil {
				t.Fatal(err)
			}
			intent := guestWANIntent{Version: 2, Operation: id, InitialNS: initialNS, BridgeName: bridge, Phase: "intent"}
			intent.Bridge.Address = bridgeMACFromOperation(id)
			intent.Bridge.IfIndex = bridgeIndexFromOperation(id)
			intent.Bridge.LinkInfo.Kind = "bridge"
			journal := filepath.Join(caseWorkspace, "guest-data-"+id+".json")
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
			child := exec.Command(os.Args[0], "-test.run=^TestVMGuestBridgePartialCrashRecovery$", "-test.v")
			child.Env = append(os.Environ(), "FBI_GO_VM_TEST_WORKSPACE="+caseWorkspace, "FBI_GO_VM_BRIDGE_CRASH_POINT="+point)
			output, err := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("expected child SIGKILL: %v %.400s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("expected SIGKILL: %v %.400s", err, output)
			}
			persisted, err := readGuestIntent(journal)
			if err != nil || persisted.Phase != "intent" || persisted.Bridge.IfIndex != intent.Bridge.IfIndex {
				t.Fatalf("pre-mutation intent was not durable: %v", err)
			}
			if point == "after-create" {
				original, err := guestLinkRead(bridge, nil)
				if err != nil || original.Address != intent.Bridge.Address {
					t.Fatalf("created bridge identity differs: %v", err)
				}
				foreignMAC := "02:ff:ee:dd:cc:bb"
				if _, err := guestRun("ip", "link", "set", "dev", bridge, "address", foreignMAC); err != nil {
					t.Fatal(err)
				}
				if result, err := recoverPrecommittedBridge(journal); result != "CONFLICT" || err == nil {
					t.Fatalf("foreign bridge change was not rejected: %s %v", result, err)
				}
				changed, err := guestLinkRead(bridge, nil)
				if err != nil || changed.IfIndex != original.IfIndex || changed.Address != foreignMAC {
					t.Fatalf("conflict modified foreign bridge: %v", err)
				}
				// This test process knows the original ifindex and restores only its
				// own fixture before the exact-match recovery attempt.
				if _, err := guestRun("ip", "link", "set", "dev", bridge, "address", intent.Bridge.Address); err != nil {
					t.Fatal(err)
				}
				restored, err := guestLinkRead(bridge, nil)
				if err != nil || restored.IfIndex != original.IfIndex {
					t.Fatalf("test bridge changed identity during conflict check: %v", err)
				}
			}
			result, err := recoverPrecommittedBridge(journal)
			if err != nil {
				t.Fatalf("partial bridge recovery %s: %s %v", point, result, err)
			}
			if point == "after-create" && result != "RECOVERED" || point == "before-create" && result != "CLEAN" {
				t.Fatalf("unexpected first recovery: %s", result)
			}
			if result, err := recoverPrecommittedBridge(journal); err != nil || result != "CLEAN" {
				t.Fatalf("repeated recovery: %s %v", result, err)
			}
			if _, err := guestLinkRead(bridge, nil); err == nil {
				t.Fatal("owned bridge survived recovery")
			}
			t.Logf("SIGKILL %s: durable intent, %s, repeated CLEAN", point, result)
		})
	}
}

// setupGuestVisibleDataPlane connects one selected application WAN to a
// gateway through a test-owned bridge in the disposable guest's initial netns.
// The other application WAN remains a direct private test link. No L3 route,
// forwarding setting, NAT rule or default gateway is added to the initial ns.
func setupGuestVisibleDataPlane(t *testing.T, app, gateway *NamespaceEngine, appIf, gatewayIf, appCIDR, gatewayCIDR, wan string, preserve *bool) (string, func()) {
	t.Helper()
	workspace := requireGuestWANGate(t)
	initialNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	appNS, err := namespaceIdentity(filepath.Join("/run/netns", app.Name()))
	if err != nil {
		t.Fatal(err)
	}
	gwNS, err := namespaceIdentity(filepath.Join("/run/netns", gateway.Name()))
	if err != nil {
		t.Fatal(err)
	}
	var token [5]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(token[:])
	names := [4]string{"f4w" + id[:7], gatewayIf, "f4p" + id[:7], appIf}
	bridge := "f4br" + id[:6]
	base, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if err := guestNamesAvailable(base, [4]string{names[0], names[2], bridge}); err != nil {
		t.Fatal(err)
	}
	if _, err := guestLinkRead(bridge, nil); err == nil {
		t.Fatal("CONFLICT: bridge name already exists")
	}
	intent := guestWANIntent{Version: 2, Operation: id, InitialNS: initialNS, GatewayNS: [2]string{gwNS, appNS}, Names: names, BridgeName: bridge, Phase: "intent"}
	journal := filepath.Join(workspace, "guest-data-"+id+".json")
	f, err := os.OpenFile(journal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	*preserve = true // only complete exact-match cleanup may clear this flag
	createdBridge, createdWAN, createdPort := false, false, false
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		if !createdBridge && !createdWAN && !createdPort {
			*preserve = false
			return
		}
		if current, err := namespaceIdentity("/proc/self/ns/net"); err != nil || current != intent.InitialNS {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: data-plane initial namespace changed: %v", err)
			return
		}
		durable, err := readGuestIntent(journal)
		if err != nil || !reflect.DeepEqual(durable, intent) || durable.Version != 2 {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: data-plane journal mismatch: %v", err)
			return
		}
		if !createdBridge || !createdWAN || !createdPort || intent.Phase != "verified" {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: incomplete bridge creation at %s", intent.Phase)
			return
		}
		for i, ns := range []*NamespaceEngine{gateway, app} {
			actualNS, err := namespaceIdentity(filepath.Join("/run/netns", ns.Name()))
			if err != nil || actualNS != intent.GatewayNS[i] {
				t.Errorf("MANUAL_INTERVENTION_REQUIRED: data-plane namespace changed: %s %v", actualNS, err)
				return
			}
		}
		br, brErr := guestLinkRead(bridge, nil)
		wanPort, wanErr := guestLinkRead(names[0], nil)
		gwPeer, gwErr := guestLinkRead(names[1], gateway)
		appPort, portErr := guestLinkRead(names[2], nil)
		appPeer, appErr := guestLinkRead(names[3], app)
		if brErr != nil || wanErr != nil || gwErr != nil || portErr != nil || appErr != nil || !guestBridgeMatches(intent.Bridge, br) ||
			!guestLinkMatches(intent.Links[0], wanPort) || !guestLinkMatches(intent.Links[1], gwPeer) ||
			!guestLinkMatches(intent.Links[2], appPort) || !guestLinkMatches(intent.Links[3], appPeer) ||
			wanPort.LinkIndex != gwPeer.IfIndex || gwPeer.LinkIndex != wanPort.IfIndex ||
			appPort.LinkIndex != appPeer.IfIndex || appPeer.LinkIndex != appPort.IfIndex ||
			wanPort.Master != bridge || appPort.Master != bridge {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: bridge or peer fingerprint differs: %v %v %v %v %v", brErr, wanErr, gwErr, portErr, appErr)
			return
		}
		if actual, err := guestIPv4(names[0], nil); err != nil || len(actual) != 0 {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: guest WAN has an unexpected IP: %v %v", actual, err)
			return
		}
		if actual, err := guestIPv4(names[2], nil); err != nil || len(actual) != 0 {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: bridge port has an unexpected IP: %v %v", actual, err)
			return
		}
		if actual, err := guestIPv4(names[1], gateway); err != nil || len(actual) != 1 || actual[0] != gatewayCIDR {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: gateway address differs: %v %v", actual, err)
			return
		}
		if actual, err := guestIPv4(names[3], app); err != nil || len(actual) != 1 || actual[0] != appCIDR {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: app address differs: %v %v", actual, err)
			return
		}
		if err := guestExactBridgeMembers(bridge, names[0], names[2]); err != nil {
			t.Errorf("MANUAL_INTERVENTION_REQUIRED: %v", err)
			return
		}
		for _, link := range []string{bridge, names[0], names[2]} {
			if err := guestNoIPv4Routes(link); err != nil {
				t.Errorf("MANUAL_INTERVENTION_REQUIRED: %v", err)
				return
			}
		}
		if _, err := guestRun("ip", "link", "del", "dev", names[2]); err != nil {
			t.Error(err)
			return
		}
		if _, err := guestRun("ip", "link", "del", "dev", names[0]); err != nil {
			t.Error(err)
			return
		}
		if _, err := guestRun("ip", "link", "del", "dev", bridge); err != nil {
			t.Error(err)
			return
		}
		intent.Phase = "clean"
		if err := writeGuestIntent(journal, intent); err != nil {
			t.Error(err)
			return
		}
		*preserve = false
		cleaned = true
	}
	t.Cleanup(cleanup)
	alias := "fbi-go-guest-data:" + id
	if _, err := guestRun("ip", "link", "add", "name", bridge, "type", "bridge", "stp_state", "0"); err != nil {
		t.Fatal(err)
	}
	createdBridge = true
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := guestRun("ip", "link", "add", "name", names[0], "type", "veth", "peer", "name", names[1]); err != nil {
		t.Fatal(err)
	}
	createdWAN = true
	if _, err := guestRun("ip", "link", "set", "dev", names[1], "netns", gateway.Name()); err != nil {
		t.Fatal(err)
	}
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	if _, err := guestRun("ip", "link", "add", "name", names[2], "type", "veth", "peer", "name", names[3]); err != nil {
		t.Fatal(err)
	}
	createdPort = true
	if _, err := guestRun("ip", "link", "set", "dev", names[3], "netns", app.Name()); err != nil {
		t.Fatal(err)
	}
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{bridge, names[0], names[2]} {
		if _, err := guestRun("ip", "link", "set", "dev", name, "alias", alias); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := gateway.run("", "ip", "link", "set", "dev", names[1], "alias", alias); err != nil {
		t.Fatal(err)
	}
	if _, err := app.run("", "ip", "link", "set", "dev", names[3], "alias", alias); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{names[0], names[2]} {
		if _, err := guestRun("ip", "link", "set", "dev", name, "master", bridge); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := gateway.run("", "ip", "addr", "add", gatewayCIDR, "dev", names[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := app.run("", "ip", "addr", "add", appCIDR, "dev", names[3]); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{bridge, names[0], names[2]} {
		if _, err := guestRun("ip", "link", "set", "dev", name, "up"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := gateway.run("", "ip", "link", "set", "dev", names[1], "up"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.run("", "ip", "link", "set", "dev", names[3], "up"); err != nil {
		t.Fatal(err)
	}
	if _, err := guestRun("udevadm", "settle", "--timeout=10"); err != nil {
		t.Fatal(err)
	}
	intent.Bridge, err = guestLinkRead(bridge, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, owner := range []*NamespaceEngine{nil, gateway, nil, app} {
		intent.Links[i], err = guestLinkRead(names[i], owner)
		if err != nil {
			t.Fatal(err)
		}
	}
	if intent.Bridge.LinkInfo.Kind != "bridge" || intent.Links[0].Master != bridge || intent.Links[2].Master != bridge ||
		intent.Links[0].LinkIndex != intent.Links[1].IfIndex || intent.Links[2].LinkIndex != intent.Links[3].IfIndex {
		t.Fatalf("bridge topology does not match intended peer ownership: %+v", intent)
	}
	if err := guestExactBridgeMembers(bridge, names[0], names[2]); err != nil {
		t.Fatal(err)
	}
	intent.PeerIPv4 = [2]string{gatewayCIDR, appCIDR}
	intent.Phase = "verified"
	if err := writeGuestIntent(journal, intent); err != nil {
		t.Fatal(err)
	}
	if current, err := network.Scan(); err != nil || guestNamesAvailable(current, [4]string{names[0]}) == nil {
		t.Fatalf("guest-visible WAN not discovered: %v", err)
	}
	if nm, err := guestRun("nmcli", "-t", "-f", "DEVICE,STATE,CONNECTION", "device", "status"); err != nil || !strings.Contains(nm, names[0]+":unmanaged:") {
		t.Fatalf("NetworkManager owns test WAN or device missing: %v %.400s", err, nm)
	}
	if _, err := app.run("", "ping", "-c", "1", "-W", "1", "-I", appIf, strings.Split(gatewayCIDR, "/")[0]); err != nil {
		t.Fatalf("guest-visible bridge gateway unreachable: %v", err)
	}
	t.Logf("guest-visible %s bridge=%s WAN=%s ifindex=%d app=%s gateway=%s journal=%s", wan, bridge, names[0], intent.Links[0].IfIndex, app.Name(), gateway.Name(), journal)
	return names[0], cleanup
}

func guestBridgeMatches(expected, actual guestLink) bool {
	return expected.IfIndex > 0 && expected.IfIndex == actual.IfIndex && expected.Name == actual.Name && expected.Address == actual.Address && expected.Alias == actual.Alias && expected.Master == "" && actual.Master == "" && expected.LinkInfo.Kind == "bridge" && actual.LinkInfo.Kind == "bridge"
}

func guestNSSwitchFile(t *testing.T, evidence string) *os.File {
	t.Helper()
	f, err := os.CreateTemp(evidence, "nsswitch-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("passwd: files\ngroup: files\nhosts: files dns\n"); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Chown(1000, 1000); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := validateGuestNSSwitch(f); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func guestExactBridgeMembers(bridge string, first, second string) error {
	raw, err := guestRun("ip", "-j", "link", "show", "master", bridge)
	if err != nil {
		return err
	}
	var members []struct {
		Name string `json:"ifname"`
	}
	if err := json.Unmarshal([]byte(raw), &members); err != nil {
		return err
	}
	if len(members) != 2 || !(members[0].Name == first && members[1].Name == second || members[0].Name == second && members[1].Name == first) {
		return fmt.Errorf("CONFLICT: bridge %s membership differs: %.400s", bridge, raw)
	}
	return nil
}

func guestNoIPv4Routes(link string) error {
	raw, err := guestRun("ip", "-j", "-4", "route", "show", "dev", link)
	if err != nil {
		return err
	}
	var routes []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &routes); err != nil {
		return err
	}
	if len(routes) != 0 {
		return fmt.Errorf("CONFLICT: unexpected route on %s: %.400s", link, raw)
	}
	return nil
}

func TestGuestBridgeFingerprint(t *testing.T) {
	a := guestLink{IfIndex: 7, Name: "f4br123", Address: "02:00:00:00:00:07", Alias: "fbi-go-guest-data:123"}
	a.LinkInfo.Kind = "bridge"
	if !guestBridgeMatches(a, a) {
		t.Fatal("exact bridge rejected")
	}
	b := a
	b.IfIndex++
	if guestBridgeMatches(a, b) {
		t.Fatal("replaced bridge accepted")
	}
	b = a
	b.LinkInfo.Kind = "veth"
	if guestBridgeMatches(a, b) {
		t.Fatal("foreign link type accepted")
	}
}

type guestPacket struct {
	Stage, Interface, Event, Family, Protocol, Source, Destination string
	SourcePort                                                     int   `json:"source_port"`
	DestinationPort                                                int   `json:"destination_port"`
	TimeNS                                                         int64 `json:"time_ns"`
}

func startGuestWANPacketCaptures(t *testing.T, app, gateway *NamespaceEngine, wanInterface, wan, evidence string) [3]string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("testdata/guest_wan_capture.py")
	if err != nil {
		t.Fatal(err)
	}
	appIf, gatewayIf := "fbi_ca", "fbi_aa"
	if wan == "wan-b" {
		appIf, gatewayIf = "fbi_cb", "fbi_bb"
	}
	specs := []struct {
		stage, iface string
		ns           *NamespaceEngine
	}{{"app", appIf, app}, {"guest_wan", wanInterface, nil}, {"gateway", gatewayIf, gateway}}
	var paths [3]string
	for i, spec := range specs {
		paths[i] = filepath.Join(evidence, fmt.Sprintf("capture-%s-%s.jsonl", wan, spec.stage))
		ready := paths[i] + ".ready"
		args := []string{script, spec.iface, paths[i], ready, spec.stage}
		cmd := exec.Command(python, args...)
		if spec.ns != nil {
			cmd = exec.Command("nsenter", append([]string{"--net=/proc/self/fd/3", "--", python}, args...)...)
			cmd.ExtraFiles = []*os.File{spec.ns.fd}
		}
		var stderr boundedTestOutput
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s capture did not become ready: %s", spec.stage, stderr.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return paths
}

func verifyGuestWANPacketEvidence(t *testing.T, paths [3]string, source, wan string) {
	t.Helper()
	flows := [3]map[string]bool{}
	protocols := [3]map[string]bool{}
	appTimes := map[string][]int64{}
	var downPeriods [][2]int64
	var downStart int64
	for stage, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		flows[stage], protocols[stage] = map[string]bool{}, map[string]bool{}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var row guestPacket
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatalf("packet evidence parse %s: %v", path, err)
			}
			// The gateway peer is lowered first. The guest WAN carrier event is
			// observed later, after netlink propagation and polling. Use the
			// gateway's packet-capture clock for the outage interval so an
			// app-side probe in that gap is correctly recognized as blocked.
			if stage == 2 {
				switch row.Event {
				case "carrier_down":
					if downStart != 0 {
						t.Fatalf("duplicate carrier_down in %s", path)
					}
					downStart = row.TimeNS
				case "carrier_up":
					if downStart == 0 || row.TimeNS <= downStart {
						t.Fatalf("unpaired carrier_up in %s", path)
					}
					downPeriods = append(downPeriods, [2]int64{downStart, row.TimeNS})
					downStart = 0
				}
			}
			if row.Family != "ipv4" || row.Destination != "203.0.113.7" {
				continue
			}
			if row.Source != source {
				t.Fatalf("cross-WAN egress at %s: source=%s expected=%s", row.Stage, row.Source, source)
			}
			if stage == 2 && guestFlowOnlyDuringOutage([]int64{row.TimeNS}, downPeriods) {
				t.Fatalf("gateway received %s packet during selected WAN carrier outage: %s", row.Protocol, path)
			}
			key := fmt.Sprintf("%s/%s/%d/%d", row.Protocol, row.Source, row.SourcePort, row.DestinationPort)
			flows[stage][key] = true
			if stage == 0 {
				appTimes[key] = append(appTimes[key], row.TimeNS)
			}
			if row.DestinationPort == 49494 {
				protocols[stage][row.Protocol] = true
			}
			if row.DestinationPort == 53 {
				protocols[stage]["dns_"+row.Protocol] = true
			}
			if row.DestinationPort == 8080 {
				protocols[stage]["http_"+row.Protocol] = true
			}
		}
		for _, required := range []string{"tcp", "udp", "dns_tcp", "dns_udp", "http_tcp"} {
			if !protocols[stage][required] {
				t.Fatalf("%s missing %s packets on %s", wan, required, path)
			}
		}
	}
	if downStart != 0 {
		t.Fatalf("unpaired carrier_down in %s", paths[2])
	}
	for key := range flows[0] {
		if flows[1][key] && flows[2][key] {
			continue
		}
		// The STRICT probe intentionally creates an app-side packet while its
		// selected WAN is down. All packets of such a flow must fall within an
		// observed carrier-down interval; any missing post-recovery flow fails.
		if guestFlowOnlyDuringOutage(appTimes[key], downPeriods) && !flows[1][key] && !flows[2][key] {
			continue
		}
		// Some application packets can be local control probes; only external
		// selected-WAN flows must be present at all three observation points.
		if strings.HasSuffix(key, "/49494") || strings.HasSuffix(key, "/53") || strings.HasSuffix(key, "/8080") {
			t.Fatalf("flow did not traverse all interfaces: %s app=%t guest=%t gateway=%t", key, flows[0][key], flows[1][key], flows[2][key])
		}
	}
	t.Logf("guest-visible packet proof %s source=%s: TCP, UDP, DNS UDP/TCP and HTTP tuples present at app, initial-netns WAN and gateway", wan, source)
}

func guestFlowOnlyDuringOutage(times []int64, periods [][2]int64) bool {
	if len(times) == 0 {
		return false
	}
	for _, observed := range times {
		within := false
		for _, period := range periods {
			if observed >= period[0] && observed <= period[1] {
				within = true
				break
			}
		}
		if !within {
			return false
		}
	}
	return true
}

func TestGuestWANPacketEvidenceGatewayOutageBoundary(t *testing.T) {
	// Gateway carrier falls before the guest WAN's asynchronously observed
	// carrier event. A STRICT app-side SYN in that gap must not be mistaken
	// for a packet that should have reached the disconnected gateway.
	dir := t.TempDir()
	var paths [3]string
	for stage, label := range []string{"app", "guest_wan", "gateway"} {
		paths[stage] = filepath.Join(dir, label+".jsonl")
		var rows []guestPacket
		for _, flow := range []struct {
			proto string
			port  int
		}{
			{"tcp", 49494}, {"udp", 49494}, {"tcp", 53}, {"udp", 53}, {"tcp", 8080},
		} {
			rows = append(rows, guestPacket{Stage: label, Family: "ipv4", Protocol: flow.proto,
				Source: "192.0.2.9", Destination: "203.0.113.7", SourcePort: 40000 + flow.port,
				DestinationPort: flow.port, TimeNS: 50})
		}
		if stage == 0 {
			rows = append(rows, guestPacket{Stage: label, Family: "ipv4", Protocol: "tcp",
				Source: "192.0.2.9", Destination: "203.0.113.7", SourcePort: 45908,
				DestinationPort: 49494, TimeNS: 120})
		} else {
			down, up := int64(130), int64(190)
			if stage == 2 {
				down, up = 100, 200
			}
			rows = append(rows, guestPacket{Stage: label, Event: "carrier_down", TimeNS: down},
				guestPacket{Stage: label, Event: "carrier_up", TimeNS: up})
		}
		var data []byte
		for _, row := range rows {
			line, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, append(line, '\n')...)
		}
		if err := os.WriteFile(paths[stage], data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	verifyGuestWANPacketEvidence(t, paths, "192.0.2.9", "wan-a")
}

func TestGuestFlowOnlyDuringOutage(t *testing.T) {
	periods := [][2]int64{{100, 200}, {300, 400}}
	for _, tc := range []struct {
		name  string
		times []int64
		want  bool
	}{
		{"inside", []int64{110, 150}, true},
		{"two-outages", []int64{110, 310}, true},
		{"after-recovery", []int64{110, 201}, false},
		{"before-outage", []int64{99}, false},
		{"no-packets", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := guestFlowOnlyDuringOutage(tc.times, periods); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}
