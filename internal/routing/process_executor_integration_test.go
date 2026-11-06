//go:build integration

package routing

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type testExecutorWire struct {
	Name             string
	SocketDir        string
	ControllerPID    int
	ControllerUID    uint32
	ControllerGID    uint32
	ControllerStart  string
	ControllerUserNS string
	ControllerNetNS  string
	SessionID        string
	Plan             M2Plan
	Rootless         bool
	PinnedWorker     bool
}

type boundedTestOutput struct{ bytes.Buffer }

func (b *boundedTestOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 4096 {
		_, _ = b.Buffer.Write(p[:min(n, 4096-b.Len())])
	}
	return n, nil
}

func safeTestFileInfo(st os.FileInfo, err error) string {
	if err != nil {
		return err.Error()
	}
	if st == nil {
		return "unavailable"
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("mode=%s", st.Mode())
	}
	return fmt.Sprintf("mode=%s uid=%d gid=%d dev=%d ino=%d", st.Mode(), sys.Uid, sys.Gid, sys.Dev, sys.Ino)
}

func testProcessIdentity(pid int) string {
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return fmt.Sprintf("pid=%d status=%v", pid, err)
	}
	var uid, gid string
	var security []string
	for _, line := range strings.Split(string(status), "\n") {
		switch {
		case strings.HasPrefix(line, "Uid:"):
			uid = strings.TrimSpace(line)
		case strings.HasPrefix(line, "Gid:"):
			gid = strings.TrimSpace(line)
		case strings.HasPrefix(line, "CapInh:"), strings.HasPrefix(line, "CapPrm:"), strings.HasPrefix(line, "CapEff:"), strings.HasPrefix(line, "CapBnd:"), strings.HasPrefix(line, "CapAmb:"), strings.HasPrefix(line, "NoNewPrivs:"), strings.HasPrefix(line, "Seccomp:"), strings.HasPrefix(line, "Seccomp_filters:"):
			security = append(security, strings.TrimSpace(line))
		}
	}
	userNS, userErr := namespaceIdentity(filepath.Join("/proc", strconv.Itoa(pid), "ns/user"))
	netNS, netErr := namespaceIdentity(filepath.Join("/proc", strconv.Itoa(pid), "ns/net"))
	mountNS, mountErr := namespaceIdentity(filepath.Join("/proc", strconv.Itoa(pid), "ns/mnt"))
	return fmt.Sprintf("pid=%d %s %s %s userns=%s(%v) netns=%s(%v) mntns=%s(%v)", pid, uid, gid, strings.Join(security, " "), userNS, userErr, netNS, netErr, mountNS, mountErr)
}

func TestProcessExecutorChild(t *testing.T) {
	if os.Getenv("FBI_GO_PROCESS_EXECUTOR_CHILD") != "1" {
		t.Skip("test helper")
	}
	var w testExecutorWire
	if err := json.Unmarshal([]byte(os.Getenv("FBI_GO_PROCESS_EXECUTOR_CONFIG")), &w); err != nil {
		t.Fatal(err)
	}
	fd := os.NewFile(3, "owned-netns")
	defer fd.Close()
	var pid1FD *os.File
	if !w.Rootless {
		pid1FD = os.NewFile(5, "pinned-pid1-netns")
		defer pid1FD.Close()
	}
	var controlFD, listenerFD *os.File
	if w.PinnedWorker {
		controlFD = os.NewFile(6, "pinned-control-netns")
		listenerFD = os.NewFile(7, "prepared-executor-socket")
		defer controlFD.Close()
		defer listenerFD.Close()
	}
	ready := os.NewFile(4, "executor-readiness")
	defer ready.Close()
	fail := func(stage string, err error) {
		_, _ = fmt.Fprintf(ready, "ERROR %s: %.400s\n", stage, err)
		t.Fatalf("executor startup %s: %v", stage, err)
	}
	c := TestExecutorConfig{NamespaceFD: fd, PID1NetNSFD: pid1FD, ControlNetNSFD: controlFD, ListenerFD: listenerFD, PinnedWorker: w.PinnedWorker, Name: w.Name, SocketDir: w.SocketDir, ControllerPID: w.ControllerPID, ControllerUID: w.ControllerUID, ControllerGID: w.ControllerGID, ControllerStart: w.ControllerStart, ControllerUserNS: w.ControllerUserNS, ControllerNetNS: w.ControllerNetNS, SessionID: w.SessionID, Plan: w.Plan, Rootless: w.Rootless}
	if w.PinnedWorker {
		caps, err := effectiveCapabilities()
		if err != nil || caps != 1<<12 {
			fail("capabilities", fmt.Errorf("pinned worker CapEff=%#x want CAP_NET_ADMIN only: %v", caps, err))
		}
		if err := verifyRestrictedWorkerStatus(); err != nil {
			fail("kernel confinement", err)
		}
		childStatus, childErr := exec.Command("cat", "/proc/self/status").Output()
		if childErr != nil {
			fail("exec child", childErr)
		}
		if err := verifyRestrictedStatusBytes(childStatus); err != nil {
			fail("exec child privilege regain", err)
		}
		if err := exec.Command("setpriv", "--bounding-set=+sys_admin", "true").Run(); err == nil {
			fail("bounding set regain", errors.New("child restored CAP_SYS_ADMIN"))
		}
		for _, fdNum := range []uintptr{5, 6, 8} {
			_, _, errno := syscall.RawSyscall(308, fdNum, uintptr(syscall.CLONE_NEWNET), 0)
			if errno != syscall.EPERM {
				fail("setns denial", fmt.Errorf("setns fd %d: got %v, want EPERM", fdNum, errno))
			}
		}
		for _, flags := range []uintptr{syscall.CLONE_NEWNET, syscall.CLONE_NEWUSER} {
			_, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, flags, 0, 0)
			if errno != syscall.EPERM {
				fail("unshare denial", fmt.Errorf("unshare flags %#x: got %v, want EPERM", flags, errno))
			}
		}
		_, _, clone3Err := syscall.RawSyscall(435, 0, 0, 0)
		if clone3Err != syscall.ENOSYS {
			fail("clone3 denial", fmt.Errorf("clone3 returned %v, expected ENOSYS for libc fallback", clone3Err))
		}
		foreignFD := os.NewFile(8, "foreign-test-netns")
		_ = foreignFD.Close()
	} else if !w.Rootless {
		caps, err := effectiveCapabilities()
		const allowed = uint64(1<<0 | 1<<12 | 1<<21) // CAP_CHOWN, CAP_NET_ADMIN, CAP_SYS_ADMIN
		if err != nil || caps != allowed {
			fail("capabilities", fmt.Errorf("VM executor CapEff=%#x want %#x: %v", caps, allowed, err))
		}
	}
	if err := serveIsolatedTestExecutor(context.Background(), c, func() error {
		_, err := io.WriteString(ready, "READY kernel-denials=pass child-exec=pass inherited-sockets=audited\n")
		return err
	}); err != nil {
		fail("socket or namespace setup", err)
	}
}

func verifyRestrictedWorkerStatus() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	return verifyRestrictedStatusBytes(b)
}

func verifyRestrictedStatusBytes(b []byte) error {
	wantCaps := map[string]uint64{"CapInh:": 0, "CapPrm:": 1 << 12, "CapEff:": 1 << 12, "CapBnd:": 1 << 12, "CapAmb:": 0}
	seen := make(map[string]bool)
	var noNewPrivs, seccomp, filters bool
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if want, ok := wantCaps[fields[0]]; ok {
			got, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil || got != want {
				return fmt.Errorf("%s got %s, expected %#x: %v", fields[0], fields[1], want, err)
			}
			seen[fields[0]] = true
		}
		if fields[0] == "NoNewPrivs:" && fields[1] != "1" {
			return fmt.Errorf("NoNewPrivs=%s, expected 1", fields[1])
		}
		if fields[0] == "NoNewPrivs:" {
			noNewPrivs = true
		}
		if fields[0] == "Seccomp:" && fields[1] != "2" {
			return fmt.Errorf("Seccomp=%s, expected filter mode 2", fields[1])
		}
		if fields[0] == "Seccomp:" {
			seccomp = true
		}
		if fields[0] == "Seccomp_filters:" {
			n, err := strconv.Atoi(fields[1])
			if err != nil || n < 1 {
				return fmt.Errorf("Seccomp_filters=%s: %v", fields[1], err)
			}
			filters = true
		}
	}
	if len(seen) != len(wantCaps) || !noNewPrivs || !seccomp || !filters {
		return errors.New("restricted worker capability or seccomp status incomplete")
	}
	return nil
}

func TestProcessControllerChild(t *testing.T) {
	if os.Getenv("FBI_GO_PROCESS_CONTROLLER_CHILD") != "1" {
		t.Skip("test helper")
	}
	if caps, err := effectiveCapabilities(); err != nil || caps != 0 || os.Geteuid() == 0 {
		t.Fatalf("controller must be nonroot with CapEff=0: uid=%d caps=%#x err=%v", os.Geteuid(), caps, err)
	}
	reader := bufio.NewScanner(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	socket := os.Getenv("FBI_GO_PROCESS_SOCKET")
	send := func(method string, seq uint64, session string, extra bool) string {
		conn, err := net.DialTimeout("unix", socket, 2*time.Second)
		if err != nil {
			return "DIAL_ERROR|" + err.Error()
		}
		defer conn.Close()
		if method == "TOO_LARGE" {
			_, err = conn.Write(append(bytes.Repeat([]byte("x"), testExecutorRequestLimit+1), '\n'))
		} else if method == "MALFORMED" {
			_, err = conn.Write([]byte("{bad-json}\n"))
		} else if extra {
			_, err = fmt.Fprintf(conn, "{\"version\":1,\"method\":\"APPLY\",\"session_id\":%q,\"sequence\":%d,\"plan\":{}}\n", session, seq)
		} else {
			err = json.NewEncoder(conn).Encode(testExecutorRequest{Version: 1, Method: method, Sequence: seq, SessionID: session})
		}
		if err != nil {
			return "WRITE_ERROR|" + err.Error()
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		var resp testExecutorResponse
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			return "READ_ERROR|" + err.Error()
		}
		return resp.Code + "|" + resp.Message
	}
	fmt.Fprintf(writer, "READY %d\n", os.Geteuid())
	writer.Flush()
	for reader.Scan() {
		fields := strings.Fields(reader.Text())
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "DIRECT" {
			name := os.Getenv("FBI_GO_PROCESS_TARGET_NAME")
			err := exec.Command("ip", "-n", name, "route", "add", "table", "30098", "203.0.113.0/24", "dev", "lo").Run()
			if err == nil {
				fmt.Fprintln(writer, "DIRECT_ALLOWED")
			} else {
				fmt.Fprintln(writer, "DIRECT_DENIED")
			}
			writer.Flush()
			continue
		}
		if fields[0] == "SOCKET" && len(fields) == 2 {
			socket = fields[1]
			fmt.Fprintln(writer, "SOCKET_SET")
			writer.Flush()
			continue
		}
		if len(fields) != 3 {
			fmt.Fprintln(writer, "BAD_COMMAND")
			writer.Flush()
			continue
		}
		seq, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			fmt.Fprintln(writer, "BAD_SEQUENCE")
			writer.Flush()
			continue
		}
		if fields[0] == "DISCONNECT" {
			conn, err := net.DialTimeout("unix", socket, 2*time.Second)
			if err != nil {
				fmt.Fprintf(writer, "DIAL_ERROR|%v\n", err)
			} else {
				conn.Close()
				fmt.Fprintln(writer, "DISCONNECTED")
			}
			writer.Flush()
			continue
		}
		if fields[0] == "CONCURRENT_APPLY" {
			codes := make([]string, 2)
			var wg sync.WaitGroup
			for i := range codes {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					codes[i] = strings.SplitN(send("APPLY", seq, fields[2], false), "|", 2)[0]
				}(i)
			}
			wg.Wait()
			sort.Strings(codes)
			fmt.Fprintln(writer, strings.Join(codes, ","))
			writer.Flush()
			continue
		}
		fmt.Fprintln(writer, send(fields[0], seq, fields[2], fields[0] == "EXTRA"))
		writer.Flush()
	}
	if err := reader.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestRootlessExecutorProcessBoundary(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatal(err)
	}
	runExecutorProcessBoundary(t, NewRootlessTestNamespace, true, "wan-a", nil, false)
}

func TestVMExecutorProcessBoundary(t *testing.T) {
	verifyVMExecutorTestGate(t)
	runExecutorProcessBoundary(t, NewTestNamespace, false, "wan-a", nil, false)
}

func TestVMConcurrentExecutorWorkers(t *testing.T) {
	verifyVMExecutorTestGate(t)
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	go func() {
		for i := 0; i < 2; i++ {
			select {
			case <-ready:
			case <-time.After(20 * time.Second):
				close(release)
				return
			}
		}
		close(release)
	}()
	t.Run("workers", func(t *testing.T) {
		for _, wan := range []string{"wan-a", "wan-b"} {
			wan := wan
			t.Run(wan, func(t *testing.T) {
				t.Parallel()
				runExecutorProcessBoundary(t, NewTestNamespace, false, wan, &workerBarrier{ready: ready, release: release}, false)
			})
		}
	})
}

func verifyVMExecutorTestGate(t *testing.T) {
	t.Helper()
	if os.Getenv("FBI_GO_VM_PROCESS_TEST") != "YES" {
		t.Skip("requires disposable-VM launcher")
	}
	if os.Getenv("FBI_GO_RUN_NETNS") != "1" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" {
		t.Fatal("VM opt-in missing")
	}
	if out, err := exec.Command("systemd-detect-virt", "--vm", "--quiet").CombinedOutput(); err != nil {
		t.Fatalf("VM not detected: %v %s", err, out)
	}
}

func TestOwnedWANScanChild(t *testing.T) {
	if os.Getenv("FBI_GO_OWNED_WAN_SCAN_CHILD") != "1" {
		t.Skip("test-only owned namespace scanner")
	}
	snapshot, err := network.Scan()
	if err != nil {
		t.Fatal(err)
	}
	id, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(struct {
		Namespace string           `json:"namespace"`
		Snapshot  network.Snapshot `json:"snapshot"`
	}{id, snapshot})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("FBI_OWNED_SCAN:%s\n", data)
}

func scanOwnedWANs(t *testing.T, ns *NamespaceEngine) network.Snapshot {
	t.Helper()
	cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", os.Args[0], "-test.run=^TestOwnedWANScanChild$")
	cmd.ExtraFiles = []*os.File{ns.fd}
	cmd.Env = append(os.Environ(), "FBI_GO_OWNED_WAN_SCAN_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("read-only scan in owned namespace failed: %v %.2048s", err, output)
	}
	for _, line := range bytes.Split(output, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("FBI_OWNED_SCAN:")) {
			continue
		}
		var result struct {
			Namespace string           `json:"namespace"`
			Snapshot  network.Snapshot `json:"snapshot"`
		}
		if err := json.Unmarshal(bytes.TrimPrefix(line, []byte("FBI_OWNED_SCAN:")), &result); err != nil {
			t.Fatal(err)
		}
		want, err := namespaceIdentity(filepath.Join("/run/netns", ns.Name()))
		if err != nil || result.Namespace != want {
			t.Fatalf("scanner escaped owned namespace: got=%s want=%s err=%v", result.Namespace, want, err)
		}
		return result.Snapshot
	}
	t.Fatalf("owned scanner omitted structured snapshot: %.2048s", output)
	return network.Snapshot{}
}

func verifiedGuestWANPlan(t *testing.T, client, gatewayA, gatewayB *NamespaceEngine, selectedWAN string, guestVisible bool) M2Plan {
	t.Helper()
	if _, err := client.run("", "nft", "list", "tables"); err != nil {
		t.Fatalf("test namespace nft inventory: %v", err)
	}
	rules := labRun(t, client, "ip", "-4", "-j", "rule", "show")
	var existing []struct {
		Priority int `json:"priority"`
	}
	if err := json.Unmarshal([]byte(rules), &existing); err != nil {
		t.Fatal(err)
	}
	for _, rule := range existing {
		if rule.Priority != 0 && rule.Priority != 32766 && rule.Priority != 32767 {
			t.Fatalf("unexpected foreign rule in fresh test namespace: %s", rules)
		}
	}
	snapshot := scanOwnedWANs(t, client)
	if len(snapshot.Warnings) != 0 {
		t.Fatalf("incomplete WAN discovery: %v", snapshot.Warnings)
	}
	if len(snapshot.Devices) != 3 {
		t.Fatalf("unexpected devices in owned namespace: %+v", snapshot.Devices)
	}
	byName := make(map[string]network.Device, len(snapshot.Devices))
	for _, d := range snapshot.Devices {
		byName[d.Name] = d
	}
	if _, exists := byName["enp1s0"]; exists {
		t.Fatal("guest management interface appeared in owned test namespace")
	}
	var wans []policy.WAN
	for _, spec := range []struct {
		iface, addr, gw string
		peer            *NamespaceEngine
		peerIf          string
	}{
		{"fbi_ca", "192.0.2.9/24", "192.0.2.1", gatewayA, "fbi_aa"},
		{"fbi_cb", "198.51.100.99/24", "198.51.100.216", gatewayB, "fbi_bb"},
	} {
		viaBridge := guestVisible && (selectedWAN == "wan-a" && spec.iface == "fbi_ca" || selectedWAN == "wan-b" && spec.iface == "fbi_cb")
		d := byName[spec.iface]
		if d.ID == "" || !strings.HasPrefix(d.ID, "mac:") || d.Kind != "virtual" || d.Candidate || d.State != "up" || !d.AdminUp {
			t.Fatalf("unexpected unregistered synthetic WAN classification: %+v", d)
		}
		if !containsString(d.Addresses, spec.addr) || !containsString(d.Gateways, spec.gw) {
			t.Fatalf("WAN address/gateway discovery mismatch: %+v", d)
		}
		probe := func() bool {
			_, err := client.run("", "ping", "-c", "1", "-W", "1", "-I", spec.iface, spec.gw)
			return err == nil
		}
		monitor := health.Monitor{State: health.Unknown, Thresholds: health.Thresholds{OfflineFailures: 2, RecoverySuccesses: 2}}
		if !probe() || monitor.Observe(true, true, 1) != health.Healthy {
			t.Fatalf("initial %s gateway probe failed", spec.iface)
		}
		labRun(t, spec.peer, "ip", "link", "set", spec.peerIf, "down")
		down := scanOwnedWANs(t, client)
		if got := deviceNamed(down, spec.iface); got.ID != d.ID || !viaBridge && got.State != "down" {
			t.Fatalf("WAN link loss or stable identity missed: before=%+v after=%+v", d, got)
		}
		if viaBridge && probe() {
			t.Fatalf("gateway %s reachable after peer shutdown", spec.gw)
		}
		monitor.Observe(viaBridge, false, 0)
		if monitor.Observe(viaBridge, false, 0) != health.Offline {
			t.Fatal("link loss did not transition health OFFLINE")
		}
		labRun(t, spec.peer, "ip", "link", "set", spec.peerIf, "up")
		up := scanOwnedWANs(t, client)
		if got := deviceNamed(up, spec.iface); got.ID != d.ID || got.State != "up" {
			t.Fatalf("WAN recovery changed identity/state: before=%+v after=%+v", d, got)
		}
		for i := 0; i < 2; i++ {
			if !probe() {
				t.Fatalf("%s gateway unreachable after restoration", spec.iface)
			}
			state := monitor.Observe(true, true, 1)
			if i == 0 && state != health.Offline || i == 1 && state != health.Healthy {
				t.Fatalf("%s recovery hysteresis step %d: %s", spec.iface, i, state)
			}
		}
		wans = append(wans, policy.WAN{ID: d.ID, Interface: d.Name, Gateway: spec.gw, SourceAddresses: d.Addresses, Enabled: true, Health: monitor.State, Weight: 1})
		t.Logf("owned guest WAN discovered: interface=%s stable_id=%s gateway=%s state=%s health=%s", d.Name, d.ID, spec.gw, d.State, monitor.State)
	}
	if wans[0].ID == wans[1].ID {
		t.Fatal("synthetic WAN identities collide")
	}
	// The scanner intentionally excludes veth from automatic physical-WAN
	// classification. Only this FD-verified test fixture explicitly opts in.
	ready := scanOwnedWANs(t, client)
	for i := range ready.Devices {
		if ready.Devices[i].Name == "fbi_ca" || ready.Devices[i].Name == "fbi_cb" {
			ready.Devices[i].Candidate = true
		}
	}
	inventory := Inventory{Snapshot: ready, WANHealth: map[string]health.State{"fbi_ca": health.Healthy, "fbi_cb": health.Healthy},
		RulesComplete: true, TablesComplete: true, MarksComplete: true, NFTComplete: true, IPv6Policy: "system"}
	plan := PlanM2(inventory)
	if !plan.SafeToApply || len(plan.WANs) != 2 {
		t.Fatalf("discovered guest WAN routing plan unsafe: %+v", plan)
	}
	plan.NFTTable = client.TableName()
	preferred := wans[0].ID
	if selectedWAN == "wan-b" {
		preferred = wans[1].ID
	}
	app := policy.ApplicationPolicy{ID: "owned-guest-" + selectedWAN, Mode: policy.PinnedWAN, PreferredWAN: preferred, FailureBehavior: policy.Strict, Enabled: true}
	decision, err := policy.Decide(&app, policy.GlobalPolicy{Mode: policy.Auto}, wans, 0)
	if err != nil || decision.SelectedWAN != preferred {
		t.Fatalf("discovered WAN policy resolution: %+v %v", decision, err)
	}
	weights, system, err := ManagedWeights(app, policy.GlobalPolicy{Mode: policy.Auto}, wans)
	if err != nil || system {
		t.Fatalf("managed weights from discovered IDs: %v", err)
	}
	for i := range plan.WANs {
		plan.WANs[i].Weight = weights[plan.WANs[i].Interface]
	}
	return plan
}

func deviceNamed(s network.Snapshot, name string) network.Device {
	for _, d := range s.Devices {
		if d.Name == name {
			return d
		}
	}
	return network.Device{}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestRootlessConcurrentExecutorWorkers(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatal(err)
	}
	for _, crashWAN := range []string{"wan-a", "wan-b"} {
		t.Run("crash-"+crashWAN, func(t *testing.T) {
			ready := make(chan struct{}, 2)
			release := make(chan struct{})
			traffic := make(chan appTrafficInterval, 2)
			startWorkerBarrier(ready, release)
			t.Run("workers", func(t *testing.T) {
				for _, wan := range []string{"wan-a", "wan-b"} {
					wan := wan
					t.Run(wan, func(t *testing.T) {
						t.Parallel()
						runExecutorProcessBoundary(t, NewRootlessTestNamespace, true, wan, &workerBarrier{ready: ready, release: release, crashWAN: crashWAN, traffic: traffic}, false)
					})
				}
			})
			spans := map[string]appTrafficInterval{}
			for i := 0; i < 2; i++ {
				select {
				case span := <-traffic:
					spans[span.wan] = span
				case <-time.After(time.Second):
					t.Fatal("a managed application did not provide TCP timing evidence")
				}
			}
			a, b := spans["wan-a"], spans["wan-b"]
			start := max(a.startNS, b.startNS)
			end := min(a.endNS, b.endNS)
			if end <= start {
				t.Fatalf("managed TCP traffic did not overlap: A=%+v B=%+v", a, b)
			}
			t.Logf("managed TCP traffic overlap: %d ms (A=%d..%d B=%d..%d)", (end-start)/int64(time.Millisecond), a.startNS, a.endNS, b.startNS, b.endNS)
			if err := ReconcileIsolatedJournals(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type workerBarrier struct {
	ready          chan<- struct{}
	release        <-chan struct{}
	crashWAN       string
	traffic        chan<- appTrafficInterval
	outage         chan<- guestOutage
	trafficRelease <-chan struct{}
	outageFailure  <-chan struct{}
}

type guestOutage struct {
	wan, source, guestWAN, python, flowLog string
	captureGuest, captureGateway           string
	app, gateway                           *NamespaceEngine
}

type appTrafficInterval struct {
	wan            string
	startNS, endNS int64
}

func startWorkerBarrier(ready <-chan struct{}, release chan struct{}) {
	go func() {
		for i := 0; i < 2; i++ {
			select {
			case <-ready:
			case <-time.After(20 * time.Second):
				close(release)
				return
			}
		}
		close(release)
	}()
}

func verifyConcurrentManagedRuntime(t *testing.T, app, gateway *NamespaceEngine, worker *exec.Cmd, wan, source, python, evidence, guestWAN string, captures [3]string, barrier *workerBarrier, guestVM bool) bool {
	t.Helper()
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatalf("real curl application required for concurrent runtime: %v", err)
	}
	serverPath, err := filepath.Abs("testdata/dns_http_server.py")
	if err != nil {
		t.Fatal(err)
	}
	dnsLog := filepath.Join(evidence, "concurrent-dns-http.jsonl")
	server := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, serverPath, "203.0.113.7", dnsLog, wan)
	server.ExtraFiles = []*os.File{gateway.fd}
	var serverErr boundedTestOutput
	server.Stderr = &serverErr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(dnsLog); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("concurrent DNS/HTTP server not ready: %s", serverErr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	resolver, err := os.CreateTemp(evidence, "concurrent-resolv-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if _, err := resolver.WriteString("nameserver 203.0.113.7\noptions timeout:1 attempts:1\n"); err != nil {
		t.Fatal(err)
	}
	if guestVM {
		if err := resolver.Chown(1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	var nss *os.File
	if guestVM {
		nss = guestNSSwitchFile(t, evidence)
	}
	clientPath, err := filepath.Abs("testdata/concurrent_runtime_client.py")
	if err != nil {
		t.Fatal(err)
	}
	flowPath, err := filepath.Abs("testdata/flow_client.py")
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(evidence, "concurrent-app.ready.json")
	signal := filepath.Join(evidence, "concurrent-app.signal")
	appContext, cancelApp := context.WithCancel(context.Background())
	defer cancelApp()
	done := make(chan error, 1)
	go func() {
		done <- RunManaged(appContext, ManagedLaunch{NamespaceFD: app.fd, ResolverFD: resolver, NSSwitchFD: nss, NamespaceName: app.Name(), WAN: wan,
			Command: []string{python, clientPath, ready, signal, flowPath, curl}, GuestVMTest: guestVM})
	}()
	deadline = time.Now().Add(8 * time.Second)
	for {
		if data, err := os.ReadFile(ready); err == nil {
			var identity struct {
				PID, UID int
				Netns    string
			}
			if err := json.Unmarshal(data, &identity); err != nil {
				t.Fatal(err)
			}
			if identity.PID <= 0 || identity.UID == 0 || identity.Netns == "" {
				t.Fatalf("managed application identity invalid: %s", data)
			}
			if current, err := os.Stat(filepath.Join("/proc", strconv.Itoa(identity.PID), "ns/net")); err != nil || !os.SameFile(current, app.identity) {
				t.Fatalf("managed app outside owned namespace: got=%v expected=%v err=%v", current, app.identity, err)
			}
			t.Logf("managed application READY: WAN=%s PID=%d UID=%d namespace=%s", wan, identity.PID, identity.UID, identity.Netns)
			break
		}
		select {
		case err := <-done:
			t.Fatalf("managed app exited before concurrency barrier: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("managed app did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	barrier.ready <- struct{}{}
	select {
	case <-barrier.release:
	case <-time.After(20 * time.Second):
		t.Fatal("concurrent worker barrier timed out")
	}
	if barrier.outage != nil {
		barrier.outage <- guestOutage{wan: wan, source: source, guestWAN: guestWAN, python: python,
			flowLog: filepath.Join(evidence, "worker-managed-packets.jsonl"), captureGuest: captures[1], captureGateway: captures[2], app: app, gateway: gateway}
		select {
		case <-barrier.trafficRelease:
		case <-barrier.outageFailure:
			cancelApp()
			<-done
			t.Fatal("guest WAN outage verification failed; managed application terminated")
		case <-time.After(30 * time.Second):
			cancelApp()
			<-done
			t.Fatal("guest WAN outage phase did not release managed applications")
		}
	}
	killed := wan == barrier.crashWAN
	if killed {
		if err := worker.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		_ = worker.Wait()
		t.Logf("restricted worker SIGKILL while managed app was alive: WAN=%s PID=%d", wan, worker.Process.Pid)
	}
	if err := os.WriteFile(signal, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("concurrent managed application: %v", err)
	}
	if barrier.traffic != nil {
		packetData, err := os.ReadFile(filepath.Join(evidence, "worker-managed-packets.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		interval := appTrafficInterval{wan: wan}
		for _, line := range bytes.Split(bytes.TrimSpace(packetData), []byte{'\n'}) {
			var row packetRecord
			if json.Unmarshal(line, &row) != nil || row.Proto != "tcp" || !strings.HasPrefix(row.Flow, "concurrent-tcp_affinity-") {
				continue
			}
			if interval.startNS == 0 || row.StartNS < interval.startNS {
				interval.startNS = row.StartNS
			}
			if row.EndNS > interval.endNS {
				interval.endNS = row.EndNS
			}
		}
		if interval.startNS == 0 || interval.endNS <= interval.startNS {
			t.Fatalf("missing timed TCP packet observations for %s", wan)
		}
		barrier.traffic <- interval
	}
	data, err := os.ReadFile(dnsLog)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var row struct{ Protocol, Source string }
		if json.Unmarshal(line, &row) == nil && row.Source == source {
			seen[row.Protocol] = true
		}
	}
	if !seen["dns_udp"] || !seen["http_tcp"] {
		t.Fatalf("concurrent curl missing selected-WAN DNS/HTTP observations: %s", data)
	}
	t.Logf("concurrent curl child: WAN=%s DNS/HTTP source=%s", wan, source)
	_ = server.Process.Kill()
	_ = server.Wait()
	return killed
}

func verifyConcurrentStrictRecovery(t *testing.T, app, alternate *NamespaceEngine, selected Allocation, wan, python, evidence, selectedLog string, guestVM bool) {
	t.Helper()
	labRun(t, alternate, "ip", "link", "set", "lo", "up")
	labRun(t, alternate, "ip", "addr", "add", "203.0.113.7/32", "dev", "lo")
	serverPath, err := filepath.Abs("testdata/flow_server.py")
	if err != nil {
		t.Fatal(err)
	}
	otherLog := filepath.Join(evidence, "strict-alternate-gateway.jsonl")
	server := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", python, serverPath, "203.0.113.7", "49494", otherLog)
	server.ExtraFiles = []*os.File{alternate.fd}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(otherLog); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("alternate gateway capture not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	table := strconv.Itoa(selected.Table)
	labRun(t, app, "ip", "-4", "route", "del", "table", table, "default", "via", selected.Gateway, "dev", selected.Interface)
	strictPath, err := filepath.Abs("testdata/managed_strict_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: app.fd, NamespaceName: app.Name(), WAN: wan,
		Command: []string{python, strictPath}, GuestVMTest: guestVM}); err != nil {
		t.Fatalf("STRICT route-removal probe: %v", err)
	}
	for _, logPath := range []string{selectedLog, otherLog} {
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("managed-strict-leak")) {
			t.Fatalf("STRICT traffic escaped to gateway %s: %s", logPath, data)
		}
	}
	labRun(t, app, "ip", "-4", "route", "add", "table", table, "default", "via", selected.Gateway, "dev", selected.Interface, "src", selected.SourceIP)
	flowPath, err := filepath.Abs("testdata/flow_client.py")
	if err != nil {
		t.Fatal(err)
	}
	if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: app.fd, NamespaceName: app.Name(), WAN: wan,
		Command: []string{python, flowPath, "tcp_affinity", "strict-recovered", "4"}, GuestVMTest: guestVM}); err != nil {
		t.Fatalf("recovered WAN probe: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(selectedLog)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Count(data, []byte("strict-recovered")) >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("restored WAN did not receive new flows: %s", data)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("restricted-worker STRICT route removal and recovery: WAN=%s alternate gateway leak=0 recovered TCP flows>=4", wan)
}

func runExecutorProcessBoundary(t *testing.T, create func() (*NamespaceEngine, error), rootless bool, wan string, barrier *workerBarrier, guestVisible bool) {
	t.Helper()
	if wan != "wan-a" && wan != "wan-b" {
		t.Fatalf("unsupported test WAN %q", wan)
	}
	client, err := create()
	if err != nil {
		t.Fatal(err)
	}
	a, err := create()
	if err != nil {
		t.Fatal(err)
	}
	b, err := create()
	if err != nil {
		t.Fatal(err)
	}
	preserveGuestTopology := false
	guestWANInterface := ""
	var cleanupGuestDataPlane func()
	if !rootless {
		t.Cleanup(func() {
			if preserveGuestTopology {
				t.Error("MANUAL_INTERVENTION_REQUIRED: preserving application and gateway namespaces after ambiguous guest-visible topology cleanup")
				return
			}
			for _, e := range []*NamespaceEngine{client, a, b} {
				if e.closed {
					continue
				}
				j, err := loadJournal(e.journalPath)
				if err != nil || j.Phase != "created" {
					t.Errorf("preserving %s after failed VM test: journal phase requires explicit recovery: %v", e.name, err)
					continue
				}
				if err := e.Close(); err != nil {
					t.Errorf("cleanup of created VM test namespace %s: %v", e.name, err)
				}
			}
		})
	}
	for _, peer := range []struct {
		ns                                 *NamespaceEngine
		clientIf, peerIf, clientIP, peerIP string
	}{
		{a, "fbi_ca", "fbi_aa", "192.0.2.9/24", "192.0.2.1/24"},
		{b, "fbi_cb", "fbi_bb", "198.51.100.99/24", "198.51.100.216/24"},
	} {
		if guestVisible && (wan == "wan-a" && peer.clientIf == "fbi_ca" || wan == "wan-b" && peer.clientIf == "fbi_cb") {
			guestWANInterface, cleanupGuestDataPlane = setupGuestVisibleDataPlane(t, client, peer.ns, peer.clientIf, peer.peerIf, peer.clientIP, peer.peerIP, wan, &preserveGuestTopology)
		} else {
			labRun(t, client, "ip", "link", "add", peer.clientIf, "type", "veth", "peer", "name", peer.peerIf)
			labRun(t, client, "ip", "link", "set", peer.peerIf, "netns", peer.ns.Name())
			labRun(t, client, "ip", "addr", "add", peer.clientIP, "dev", peer.clientIf)
			labRun(t, peer.ns, "ip", "addr", "add", peer.peerIP, "dev", peer.peerIf)
			labRun(t, client, "ip", "link", "set", peer.clientIf, "up")
			labRun(t, peer.ns, "ip", "link", "set", peer.peerIf, "up")
		}
	}
	// Local OUTPUT starts with the main-table lookup. The M2 route chain can
	// then change its mark and trigger a second lookup into the owned table.
	labRun(t, client, "ip", "route", "add", "default", "via", "192.0.2.1", "dev", "fbi_ca", "metric", "100")
	labRun(t, client, "ip", "route", "add", "default", "via", "198.51.100.216", "dev", "fbi_cb", "metric", "101")
	p := verifiedGuestWANPlan(t, client, a, b, wan, guestVisible)
	selectedGateway, selectedSource := a, "192.0.2.9"
	if wan == "wan-b" {
		selectedGateway, selectedSource = b, "198.51.100.99"
	}
	controllerBinary := os.Args[0]
	var controllerArgs []string
	if rootless {
		uid := os.Getenv("FBI_GO_CALLER_UID")
		gid := os.Getenv("FBI_GO_CALLER_GID")
		if gid == "0" {
			gid = uid
		}
		controllerArgs = []string{"--user", "--map-user=" + uid, "--map-group=" + gid, "--", controllerBinary, "-test.run=^TestProcessControllerChild$"}
	} else {
		controllerBinary = os.Getenv("FBI_GO_VM_TEST_BINARY")
		if controllerBinary == "" {
			t.Fatal("VM test binary must be precompiled into an accessible test-only directory")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	var controller *exec.Cmd
	if rootless {
		controller = exec.CommandContext(ctx, "unshare", controllerArgs...)
	} else {
		user := os.Getenv("FBI_GO_VM_TEST_USER")
		uid, err := exec.Command("id", "-u", user).Output()
		if err != nil {
			t.Fatal(err)
		}
		gid, err := exec.Command("id", "-g", user).Output()
		if err != nil {
			t.Fatal(err)
		}
		controller = exec.CommandContext(ctx, "setpriv", "--reuid="+strings.TrimSpace(string(uid)), "--regid="+strings.TrimSpace(string(gid)), "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", controllerBinary, "-test.run=^TestProcessControllerChild$")
	}
	controller.Env = append(os.Environ(), "FBI_GO_PROCESS_CONTROLLER_CHILD=1", "FBI_GO_PROCESS_TARGET_NAME="+client.Name())
	stdin, err := controller.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := controller.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var controllerErr bytes.Buffer
	controller.Stderr = &controllerErr
	if err := controller.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = controller.Process.Kill(); _ = controller.Wait() }()
	reader := bufio.NewReader(stdout)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "READY ") {
		t.Fatalf("controller did not start unprivileged: %q %v %s", line, err, controllerErr.String())
	}
	controllerPID := controller.Process.Pid
	start, err := processStartTime(controllerPID)
	if err != nil {
		t.Fatal(err)
	}
	userNS, err := namespaceIdentity(filepath.Join("/proc", strconv.Itoa(controllerPID), "ns/user"))
	if err != nil {
		t.Fatal(err)
	}
	netNS, err := namespaceIdentity(filepath.Join("/proc", strconv.Itoa(controllerPID), "ns/net"))
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if !rootless {
		rawUID, err := exec.Command("id", "-u", os.Getenv("FBI_GO_VM_TEST_USER")).Output()
		if err != nil {
			t.Fatal(err)
		}
		rawGID, err := exec.Command("id", "-g", os.Getenv("FBI_GO_VM_TEST_USER")).Output()
		if err != nil {
			t.Fatal(err)
		}
		u, _ := strconv.ParseUint(strings.TrimSpace(string(rawUID)), 10, 32)
		g, _ := strconv.ParseUint(strings.TrimSpace(string(rawGID)), 10, 32)
		uid, gid = uint32(u), uint32(g)
	}
	base := TestExecutorConfig{NamespaceFD: client.fd, Name: client.Name(), ControllerPID: controllerPID, ControllerUID: uid, ControllerGID: gid, ControllerStart: start, ControllerUserNS: userNS, ControllerNetNS: netNS, SessionID: strings.Repeat("a", 32), Plan: p, Rootless: rootless}
	if !rootless {
		pid1FD, err := os.Open("/proc/1/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer pid1FD.Close()
		selfFD, err := os.Open("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer selfFD.Close()
		pid1Info, err := pid1FD.Stat()
		if err != nil {
			t.Fatal(err)
		}
		selfInfo, err := selfFD.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(pid1Info, selfInfo) {
			t.Fatal("VM test parent does not share PID 1 network namespace")
		}
		base.PID1NetNSFD = pid1FD
	}
	wrongIdentity := base
	wrongIdentity.ControllerUserNS = "0:0"
	if _, err := loadTestExecutorEngine(wrongIdentity); err == nil {
		t.Fatal("wrong controller user namespace identity accepted")
	}
	wrongIdentity = base
	wrongIdentity.ControllerNetNS = "0:0"
	if _, err := loadTestExecutorEngine(wrongIdentity); err == nil {
		t.Fatal("wrong controller network namespace identity accepted")
	}
	wrongFD := base
	wrongFD.NamespaceFD = a.fd
	if _, err := loadTestExecutorEngine(wrongFD); err == nil {
		t.Fatal("foreign namespace FD accepted")
	}
	staleFD, err := os.Open(filepath.Join("/run/netns", client.Name()))
	if err != nil {
		t.Fatal(err)
	}
	if err := staleFD.Close(); err != nil {
		t.Fatal(err)
	}
	wrongFD.NamespaceFD = staleFD
	if _, err := loadTestExecutorEngine(wrongFD); err == nil {
		t.Fatal("closed stale namespace FD accepted")
	}
	if !rootless {
		wrongPID1 := base
		wrongPID1.PID1NetNSFD = a.fd
		if _, err := loadTestExecutorEngine(wrongPID1); err == nil {
			t.Fatal("foreign namespace FD accepted as pinned PID 1 namespace")
		}
	}
	selfFD, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer selfFD.Close()
	wrongFD.NamespaceFD = selfFD
	if _, err := loadTestExecutorEngine(wrongFD); err == nil {
		t.Fatal("executor current network namespace FD accepted")
	}
	if pidOne, err := os.Open("/proc/1/ns/net"); err == nil {
		defer pidOne.Close()
		wrongFD.NamespaceFD = pidOne
		if _, err := loadTestExecutorEngine(wrongFD); err == nil {
			t.Fatal("PID 1 network namespace FD accepted")
		}
	} else {
		t.Logf("PID 1 namespace FD is inaccessible in this rootless environment: %v", err)
	}
	badPlan := base
	badPlan.Plan = p
	badPlan.Plan.WANs = append([]Allocation(nil), p.WANs...)
	badPlan.Plan.WANs[0].Table = 254
	if _, err := loadTestExecutorEngine(badPlan); err == nil {
		t.Fatal("unsupported routing table accepted")
	}
	badPlan.Plan.WANs[0].Table = p.WANs[0].Table
	badPlan.Plan.WANs[0].Mark = 0x2023
	if _, err := loadTestExecutorEngine(badPlan); err == nil {
		t.Fatal("foreign fwmark accepted")
	}
	command := func(method string, seq uint64, session string) string {
		t.Helper()
		if _, err := fmt.Fprintf(stdin, "%s %d %s\n", method, seq, session); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("controller response %s: %v %s", method, err, controllerErr.String())
		}
		line = strings.TrimSpace(line)
		t.Logf("internal executor %s: %s", method, line)
		return strings.SplitN(line, "|", 2)[0]
	}
	if got := command("DIRECT", 0, "x"); got != "DIRECT_DENIED" {
		t.Fatalf("controller directly mutated target: %s", got)
	}
	launch := func(session string) (*exec.Cmd, string) {
		t.Helper()
		socketDir, err := os.MkdirTemp("/tmp", "fbi-go-exec-")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(socketDir, 0711); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
		w := testExecutorWire{Name: client.Name(), SocketDir: socketDir, ControllerPID: controllerPID, ControllerUID: uid, ControllerGID: gid, ControllerStart: start, ControllerUserNS: userNS, ControllerNetNS: netNS, SessionID: session, Plan: p, Rootless: rootless, PinnedWorker: true}
		config, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		setup := base
		setup.SocketDir = socketDir
		if _, err := loadTestExecutorEngine(setup); err != nil {
			t.Fatalf("trusted executor setup validation: %v", err)
		}
		listener, _, err := prepareTestExecutorListener(setup)
		if err != nil {
			t.Fatalf("trusted executor socket setup: %v", err)
		}
		defer listener.Close()
		listenerFile, err := listener.File()
		if err != nil {
			t.Fatal(err)
		}
		defer listenerFile.Close()
		controlFD, err := os.Open("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		defer controlFD.Close()
		filterPath, err := writeExecutorSeccompFilter(socketDir)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "nsenter", "--net=/proc/self/fd/3", "--", "setpriv", "--bounding-set=-all,+net_admin", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--seccomp-filter="+filterPath, os.Args[0], "-test.run=^TestProcessExecutorChild$")
		cmd.Env = append(os.Environ(), "FBI_GO_PROCESS_EXECUTOR_CHILD=1", "FBI_GO_PROCESS_EXECUTOR_CONFIG="+string(config))
		readiness, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer readiness.Close()
		pid1Child := base.PID1NetNSFD
		if rootless {
			pid1Child = controlFD
		}
		cmd.ExtraFiles = []*os.File{client.fd, writer, pid1Child, controlFD, listenerFile, a.fd}
		var stderr, stdout boundedTestOutput
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			_ = writer.Close()
			t.Fatal(err)
		}
		_ = writer.Close()
		_ = listener.Close()
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		socket := filepath.Join(socketDir, "control.sock")
		type startup struct {
			line string
			err  error
		}
		result := make(chan startup, 1)
		go func() {
			line, err := bufio.NewReader(io.LimitReader(readiness, 1024)).ReadString('\n')
			result <- startup{line, err}
		}()
		var status startup
		select {
		case status = <-result:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			status = <-result
			status.err = fmt.Errorf("executor readiness timed out: %v", status.err)
		}
		if status.err != nil || !strings.HasPrefix(status.line, "READY kernel-denials=pass ") {
			executorIdentity := testProcessIdentity(cmd.Process.Pid)
			controllerIdentity := testProcessIdentity(controllerPID)
			parentIdentity := testProcessIdentity(os.Getpid())
			waited := make(chan error, 1)
			go func() { waited <- cmd.Wait() }()
			var waitErr error
			select {
			case waitErr = <-waited:
			case <-time.After(2 * time.Second):
				_ = cmd.Process.Kill()
				waitErr = <-waited
			}
			dirInfo, dirErr := os.Lstat(socketDir)
			socketInfo, socketErr := os.Lstat(socket)
			t.Fatalf("executor startup failed: exit=%v readiness=%q read=%v dir=%s socket=%s executor={%s} controller={%s} parent={%s} stdout=%.4096s stderr=%.4096s", waitErr, status.line, status.err, safeTestFileInfo(dirInfo, dirErr), safeTestFileInfo(socketInfo, socketErr), executorIdentity, controllerIdentity, parentIdentity, stdout.String(), stderr.String())
		}
		st, err := os.Lstat(socket)
		if err != nil || st.Mode()&os.ModeSocket == 0 {
			t.Fatalf("executor reported ready without a socket: pid=%d path=%s: %v", cmd.Process.Pid, socket, err)
		}
		owner := st.Sys().(*syscall.Stat_t)
		if st.Mode().Perm() != 0600 || owner.Uid != uid || owner.Gid != gid {
			t.Fatalf("executor reported ready with wrong socket metadata: got %s want uid/gid=%d/%d mode=0600", safeTestFileInfo(st, nil), uid, gid)
		}
		t.Logf("executor %s: %s controller={%s} socket=%s", strings.TrimSpace(status.line), testProcessIdentity(cmd.Process.Pid), testProcessIdentity(controllerPID), safeTestFileInfo(st, nil))
		return cmd, socket
	}
	session, err := NewTestSessionID()
	if err != nil {
		t.Fatal(err)
	}
	executor, socket := launch(session)
	// The already-running controller receives the socket through a fixed command.
	if _, err := fmt.Fprintf(stdin, "SOCKET %s\n", socket); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "SOCKET_SET" {
		t.Fatalf("controller socket update: %s %v", line, err)
	}
	other, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewEncoder(other).Encode(testExecutorRequest{Version: 1, Method: "APPLY", Sequence: 1, SessionID: session})
	var otherResp testExecutorResponse
	_ = other.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewDecoder(other).Decode(&otherResp); err != nil || otherResp.Code != "UNAUTHORIZED" {
		t.Fatalf("wrong peer accepted: %+v %v", otherResp, err)
	}
	_ = other.Close()
	if got := command("APPLY", 1, strings.Repeat("0", 32)); got != "UNAUTHORIZED" {
		t.Fatalf("wrong session accepted: %s", got)
	}
	if got := command("EXTRA", 1, session); got != "INVALID_REQUEST" {
		t.Fatalf("client plan accepted: %s", got)
	}
	if got := command("MALFORMED", 1, session); got != "INVALID_REQUEST" {
		t.Fatalf("malformed request accepted: %s", got)
	}
	if got := command("TOO_LARGE", 1, session); got != "TOO_LARGE" {
		t.Fatalf("oversized request accepted: %s", got)
	}
	if got := command("HOST_APPLY", 1, session); got != "UNSUPPORTED" {
		t.Fatalf("host apply accepted: %s", got)
	}
	if got := command("DISCONNECT", 1, session); got != "DISCONNECTED" {
		t.Fatalf("disconnect probe failed: %s", got)
	}
	if got := command("INSTALL_IPV6_GUARD", 1, session); got != "FAILED" {
		t.Fatalf("guard installed before owned IPv4 plan: %s", got)
	}
	if got := command("CONCURRENT_APPLY", 1, session); got != "OK,REPLAY" {
		t.Fatalf("concurrent approved apply was not serialized: %s", got)
	}
	labRun(t, client, "nft", "add", "table", "ip", "fbi_foreign_process")
	if got := command("APPLY", 1, session); got != "REPLAY" {
		t.Fatalf("replayed request accepted: %s", got)
	}
	if rootless {
		marker := filepath.Join(t.TempDir(), "must-not-launch")
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Fatal(err)
		}
		python, err = filepath.Abs(python)
		if err != nil {
			t.Fatal(err)
		}
		attempt := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: client.fd, NamespaceName: client.Name(), WAN: wan, Command: []string{python, "-c", "open(" + strconv.Quote(marker) + ", 'w').close()"}})
		if attempt == nil || !strings.Contains(attempt.Error(), "kernel IPv6 guard") {
			t.Fatalf("managed launch was not blocked before worker guard: %v", attempt)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("unprotected application executed: %v", err)
		}
	}
	labRun(t, client, "nft", "add", "table", "ip6", ipv6GuardTable(p.NFTTable))
	if got := command("INSTALL_IPV6_GUARD", 2, session); got != "FAILED" {
		t.Fatalf("foreign guard-name conflict was not rejected: %s", got)
	}
	if _, err := client.run("", "nft", "list", "table", "ip6", ipv6GuardTable(p.NFTTable)); err != nil {
		t.Fatalf("failed guard installation removed foreign table: %v", err)
	}
	// Only the test setup removes the exact table it just created.
	labRun(t, client, "nft", "delete", "table", "ip6", ipv6GuardTable(p.NFTTable))
	if got := command("INSTALL_IPV6_GUARD", 2, session); got != "OK" {
		t.Fatalf("restricted worker guard installation failed: %s", got)
	}
	if got := command("INSTALL_IPV6_GUARD", 3, session); got != "OK" {
		t.Fatalf("duplicate exact guard installation failed: %s", got)
	}
	guardJournal, err := loadJournal(client.journalPath)
	if err != nil || !guardJournal.IPv6GuardIntent || guardJournal.IPv6GuardState == "" {
		t.Fatalf("restricted worker did not durably snapshot IPv6 guard: %+v %v", guardJournal, err)
	}
	if got := command("VERIFY", 4, session); got != "OK" {
		t.Fatalf("verify failed: %s", got)
	}
	if barrier != nil && !rootless && !guestVisible {
		barrier.ready <- struct{}{}
		select {
		case <-barrier.release:
		case <-time.After(20 * time.Second):
			t.Fatal("concurrent VM workers did not become ready")
		}
	}
	if rootless || guestVisible {
		// The application launcher must see the worker's durable guard before
		// it is allowed to create any socket in the owned namespace.
		labRun(t, client, "ip", "link", "set", "lo", "up")
		labRun(t, selectedGateway, "ip", "link", "set", "lo", "up")
		labRun(t, selectedGateway, "ip", "addr", "add", "203.0.113.7/32", "dev", "lo")
		packetDir := os.Getenv("FBI_GO_EVIDENCE_DIR")
		if packetDir == "" {
			packetDir = t.TempDir()
		}
		if guestVisible {
			packetDir, err = os.MkdirTemp("/tmp", "fbi-go-guest-app-")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(packetDir, 1000, 1000); err != nil {
				t.Fatal(err)
			}
			t.Logf("guest application packet evidence: %s", packetDir)
		} else {
			packetDir = filepath.Join(packetDir, client.Name())
			if err := os.MkdirAll(packetDir, 0700); err != nil {
				t.Fatal(err)
			}
		}
		var guestCaptures [3]string
		if guestVisible {
			captureDir := filepath.Join(requireGuestWANGate(t), "guest-captures", client.Name())
			if err := os.MkdirAll(captureDir, 0700); err != nil {
				t.Fatal(err)
			}
			guestCaptures = startGuestWANPacketCaptures(t, client, selectedGateway, guestWANInterface, wan, captureDir)
		}
		packetPath := filepath.Join(packetDir, "worker-managed-packets.jsonl")
		serverPath, err := filepath.Abs("testdata/flow_server.py")
		if err != nil {
			t.Fatal(err)
		}
		server := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "python3", serverPath, "203.0.113.7", "49494", packetPath)
		server.ExtraFiles = []*os.File{selectedGateway.fd}
		var serverErr boundedTestOutput
		server.Stderr = &serverErr
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(packetPath); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("packet server not ready: %s", serverErr.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Fatal(err)
		}
		python, err = filepath.Abs(python)
		if err != nil {
			t.Fatal(err)
		}
		flowPath, err := filepath.Abs("testdata/flow_client.py")
		if err != nil {
			t.Fatal(err)
		}
		if barrier != nil {
			killed := verifyConcurrentManagedRuntime(t, client, selectedGateway, executor, wan, selectedSource, python, packetDir, guestWANInterface, guestCaptures, barrier, guestVisible)
			if killed {
				restartedSession, err := NewTestSessionID()
				if err != nil {
					t.Fatal(err)
				}
				executor, socket = launch(restartedSession)
				if _, err := fmt.Fprintf(stdin, "SOCKET %s\n", socket); err != nil {
					t.Fatal(err)
				}
				if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "SOCKET_SET" {
					t.Fatalf("crash restart socket update: %s %v", line, err)
				}
				session = restartedSession
				if got := command("VERIFY", 1, session); got != "OK" {
					t.Fatalf("worker crash lost kernel policy or IPv6 guard: %s", got)
				}
			}
		}
		for _, proto := range []string{"tcp_affinity", "udp"} {
			if err := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: client.fd, NamespaceName: client.Name(), WAN: wan, Command: []string{python, flowPath, proto, "worker-" + proto, "4"}, GuestVMTest: guestVisible}); err != nil {
				t.Fatalf("managed launch after restricted worker guard (%s): %v", proto, err)
			}
		}
		deadline = time.Now().Add(3 * time.Second)
		for {
			b, err := os.ReadFile(packetPath)
			if err != nil {
				t.Fatal(err)
			}
			tcp, udp := 0, 0
			for _, line := range bytes.Split(bytes.TrimSpace(b), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				var observation struct{ Proto, Source string }
				if err := json.Unmarshal(line, &observation); err != nil {
					t.Fatal(err)
				}
				if observation.Source != selectedSource {
					t.Fatalf("wrong managed source %q", observation.Source)
				}
				if observation.Proto == "tcp" {
					tcp++
				} else if observation.Proto == "udp" {
					udp++
				}
			}
			if tcp >= 4 && udp >= 4 {
				t.Logf("restricted-worker guard then managed packet evidence: WAN=%s TCP=%d UDP=%d source=%s", wan, tcp, udp, selectedSource)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("missing managed packets: TCP=%d UDP=%d", tcp, udp)
			}
			time.Sleep(20 * time.Millisecond)
		}
		verifyWorkerDNS(t, client, selectedGateway, wan, selectedSource, packetDir, guestVisible)
		if barrier != nil {
			alternate := b
			selected := p.WANs[0]
			if wan == "wan-b" {
				alternate, selected = a, p.WANs[1]
			}
			verifyConcurrentStrictRecovery(t, client, alternate, selected, wan, python, packetDir, packetPath, guestVisible)
		}
		verifyWorkerIPv6PacketGuard(t, client, a, b, wan, packetDir, guestVisible)
		if guestVisible {
			verifyGuestWANPacketEvidence(t, guestCaptures, selectedSource, wan)
		}
	}
	// A privileged test actor can remove the guard in this owned namespace.
	// Readiness and the managed launcher must then refuse until exact state is
	// restored; this does not claim protection from privileged live tampering.
	labRun(t, client, "nft", "delete", "table", "ip6", ipv6GuardTable(p.NFTTable))
	verifySeq := uint64(5)
	if barrier != nil && rootless && wan == barrier.crashWAN {
		verifySeq = 2
	}
	if got := command("VERIFY", verifySeq, session); got != "FAILED" {
		t.Fatalf("missing guard passed worker verification: %s", got)
	}
	if rootless {
		python, err := exec.LookPath("python3")
		if err != nil {
			t.Fatal(err)
		}
		python, err = filepath.Abs(python)
		if err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(t.TempDir(), "must-not-launch-without-guard")
		attempt := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: client.fd, NamespaceName: client.Name(), WAN: wan, Command: []string{python, "-c", "open(" + strconv.Quote(marker) + ", 'w').close()"}})
		if attempt == nil || !strings.Contains(attempt.Error(), "kernel IPv6 guard") {
			t.Fatalf("managed launch after guard removal was not blocked: %v", attempt)
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("unprotected application executed after guard removal: %v", err)
		}
	}
	// A replacement with the same name and comment has a different kernel
	// table identity. The worker must refuse ownership and leave it untouched.
	if _, err := client.run(ipv6GuardScript(p.NFTTable, guardJournal.OperationID), "nft", "-f", "-"); err != nil {
		t.Fatalf("create test-owned replacement guard: %v", err)
	}
	if got := command("VERIFY", verifySeq, session); got != "FAILED" {
		t.Fatalf("replacement table was accepted as original guard: %s", got)
	}
	if got := command("ROLLBACK", verifySeq, session); got != "FAILED" {
		t.Fatalf("replacement table was deleted by worker: %s", got)
	}
	if _, err := client.run("", "nft", "list", "table", "ip6", ipv6GuardTable(p.NFTTable)); err != nil {
		t.Fatalf("worker removed foreign replacement: %v", err)
	}
	// The trusted test setup removes only the replacement it just created.
	labRun(t, client, "nft", "delete", "table", "ip6", ipv6GuardTable(p.NFTTable))
	if err := executor.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = executor.Wait()
	j, err := loadJournal(client.journalPath)
	if err != nil || j.Phase != "active" {
		t.Fatalf("executor crash lost active journal: %+v %v", j, err)
	}
	nextSession, err := NewTestSessionID()
	if err != nil {
		t.Fatal(err)
	}
	executor, socket = launch(nextSession)
	if _, err := fmt.Fprintf(stdin, "SOCKET %s\n", socket); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || strings.TrimSpace(line) != "SOCKET_SET" {
		t.Fatalf("restart socket update: %s %v", line, err)
	}
	if got := command("ROLLBACK", 1, session); got != "UNAUTHORIZED" {
		t.Fatalf("old session accepted after restart: %s", got)
	}
	if got := command("ROLLBACK", 1, nextSession); got != "OK" {
		t.Fatalf("post-crash rollback failed: %s", got)
	}
	if got := command("SHUTDOWN", 2, nextSession); got != "OK" {
		t.Fatalf("shutdown failed: %s", got)
	}
	if err := executor.Wait(); err != nil {
		t.Fatalf("executor shutdown: %v", err)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatalf("executor did not remove its owned socket on shutdown: %v", err)
	}
	out, err := client.run("", "nft", "list", "tables")
	_, guardErr := client.run("", "nft", "list", "table", "ip6", ipv6GuardTable(p.NFTTable))
	if err != nil || !hasNFTTable(out, "fbi_foreign_process") || hasNFTTable(out, p.NFTTable) || guardErr == nil {
		t.Fatalf("foreign preservation or owned cleanup failed: %v %s", err, out)
	}
	labRun(t, client, "nft", "delete", "table", "ip", "fbi_foreign_process")
	if rootless && barrier == nil {
		if err := ReconcileIsolatedJournals(); err != nil {
			t.Fatal(err)
		}
	} else if !rootless {
		if cleanupGuestDataPlane != nil {
			cleanupGuestDataPlane()
			if preserveGuestTopology {
				t.Fatal("guest-visible topology cleanup requires manual intervention")
			}
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
	}
	_ = stdin.Close()
	if err := controller.Wait(); err != nil {
		t.Fatalf("controller exit: %v %s", err, controllerErr.String())
	}
}
