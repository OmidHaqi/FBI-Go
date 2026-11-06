//go:build integration

package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/applications"
	"github.com/omidhaqi/FBI-Go/internal/health"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type boundedCapture struct {
	data      []byte
	truncated bool
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	const limit = 16 << 10
	length := len(p)
	if len(b.data) >= limit && length > 0 {
		b.truncated = true
	}
	if len(b.data) < limit {
		remaining := limit - len(b.data)
		if len(p) > remaining {
			p = p[:remaining]
		}
		b.data = append(b.data, p...)
	}
	if length > len(p) {
		b.truncated = true
	}
	return length, nil
}

func (b *boundedCapture) String() string {
	if b.truncated {
		return string(b.data) + " [truncated]"
	}
	return string(b.data)
}

// This test runs only through the rootless launcher. Each application gets its
// own M2-managed local OUTPUT path; no host or shared-client rule is touched.
func TestRootlessManagedApps(t *testing.T) {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" {
		t.Skip("requires dedicated rootless launcher")
	}
	if err := verifyRootlessIsolation(); err != nil {
		t.Fatalf("rootless isolation BLOCKED: %v", err)
	}
	create := func() *NamespaceEngine {
		ns, err := NewRootlessTestNamespace()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := ns.Close(); err != nil {
				t.Errorf("owned namespace cleanup: %v", err)
			}
		})
		return ns
	}
	apps := [2]*NamespaceEngine{create(), create()}
	for _, app := range apps {
		if err := validateNetworkNamespaceFD(app.fd); err != nil {
			t.Fatalf("named owned network namespace FD rejected: %v", err)
		}
		if link, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", app.fd.Fd())); err == nil {
			t.Logf("owned namespace %s FD link: %s", app.Name(), link)
		}
	}
	gateways := [2][2]*NamespaceEngine{{create(), create()}, {create(), create()}}
	for appIndex, app := range apps {
		labRun(t, app, "ip", "link", "set", "lo", "up")
		labRun(t, app, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
		labRun(t, app, "sysctl", "-q", "-w", "net.ipv4.conf.default.rp_filter=0")
		for wanIndex, peer := range []struct{ iface, peer, clientIP, gatewayIP string }{
			{"fbi_ca", "fbi_ga", "192.0.2.9/24", "192.0.2.1/24"},
			{"fbi_cb", "fbi_gb", "198.51.100.99/24", "198.51.100.216/24"},
		} {
			gateway := gateways[appIndex][wanIndex]
			labRun(t, app, "ip", "link", "add", peer.iface, "type", "veth", "peer", "name", peer.peer)
			labRun(t, app, "ip", "link", "set", peer.peer, "netns", gateway.Name())
			labRun(t, app, "ip", "addr", "add", peer.clientIP, "dev", peer.iface)
			labRun(t, gateway, "ip", "addr", "add", peer.gatewayIP, "dev", peer.peer)
			labRun(t, app, "ip", "link", "set", peer.iface, "up")
			labRun(t, gateway, "ip", "link", "set", peer.peer, "up")
			labRun(t, gateway, "ip", "link", "set", "lo", "up")
			labRun(t, gateway, "ip", "addr", "add", "203.0.113.7/32", "dev", "lo")
			checkLabLink(t, app, peer.iface, peer.clientIP)
			checkLabLink(t, gateway, peer.peer, peer.gatewayIP)
			gatewayAddress := strings.Split(peer.gatewayIP, "/")[0]
			connected := labRun(t, app, "ip", "-4", "route", "get", gatewayAddress)
			if !strings.Contains(connected, "dev "+peer.iface) {
				t.Fatalf("gateway %s not connected through %s: %s", gatewayAddress, peer.iface, connected)
			}
			labRun(t, app, "ping", "-I", peer.iface, "-c", "1", "-W", "1", gatewayAddress)
		}
		labRun(t, app, "ip", "route", "add", "default", "via", "192.0.2.1", "dev", "fbi_ca")
		inv := Inventory{RulesComplete: true, TablesComplete: true, MarksComplete: true, NFTComplete: true, IPv6Policy: "system", WANHealth: map[string]health.State{"fbi_ca": health.Healthy, "fbi_cb": health.Healthy}, Snapshot: network.Snapshot{Devices: []network.Device{{Name: "fbi_ca", State: "up", Candidate: true, Addresses: []string{"192.0.2.9/24"}}, {Name: "fbi_cb", State: "up", Candidate: true, Addresses: []string{"198.51.100.99/24"}}}, Routes: []network.Route{{Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "192.0.2.1", Interface: "fbi_ca", Table: 254}, {Family: "ipv4", Destination: "0.0.0.0/0", Gateway: "198.51.100.216", Interface: "fbi_cb", Table: 254}}}}
		plan := PlanM2(inv)
		if !plan.SafeToApply {
			t.Fatal(plan.Reasons)
		}
		plan.NFTTable = app.TableName()
		if err := app.Apply(plan); err != nil {
			t.Fatal(err)
		}
		preferred := "wan-a"
		if appIndex == 1 {
			preferred = "wan-b"
		}
		weights, _, err := ManagedWeights(policy.ApplicationPolicy{ID: fmt.Sprintf("managed-%d", appIndex), Mode: policy.PinnedWAN, PreferredWAN: preferred, FailureBehavior: policy.Strict, Enabled: true}, policy.GlobalPolicy{Mode: policy.Auto, EligibleWANs: []string{"wan-a", "wan-b"}}, []policy.WAN{{ID: "wan-a", Interface: "fbi_ca", Enabled: true, Health: health.Healthy, Weight: 3}, {ID: "wan-b", Interface: "fbi_cb", Enabled: true, Health: health.Healthy, Weight: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if err := app.UpdateWeights(weights); err != nil {
			t.Fatal(err)
		}
		if err := app.InstallIPv6Guard(); err != nil {
			t.Fatal(err)
		}
		if err := app.InstallIPv6Guard(); err != nil {
			t.Fatalf("idempotent IPv6 guard install: %v", err)
		}
	}
	evidence := os.Getenv("FBI_GO_EVIDENCE_DIR")
	if evidence == "" {
		evidence = t.TempDir()
	}
	serverPath, err := filepath.Abs("testdata/flow_server.py")
	if err != nil {
		t.Fatal(err)
	}
	var paths [2][2]string
	var servers []*exec.Cmd
	for i := range apps {
		for j := range gateways[i] {
			path := filepath.Join(evidence, fmt.Sprintf("managed-%d-%d.jsonl", i, j))
			paths[i][j] = path
			cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "python3", serverPath, "203.0.113.7", "49494", path)
			cmd.ExtraFiles = []*os.File{gateways[i][j].fd}
			output, err := os.Create(path + ".stderr")
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdout, cmd.Stderr = output, output
			if err := cmd.Start(); err != nil {
				_ = output.Close()
				t.Fatal(err)
			}
			_ = output.Close()
			servers = append(servers, cmd)
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		ready := true
		for i := range paths {
			for _, path := range paths[i] {
				if _, err := os.Stat(path); err != nil {
					ready = false
				}
			}
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("managed receiver startup timeout")
		}
		time.Sleep(25 * time.Millisecond)
	}
	clientPath, err := filepath.Abs("testdata/managed_client.py")
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	python, err = filepath.Abs(python)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "fbi")
	build := exec.Command("go", "build", "-o", binary, "./cmd/fbi")
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build managed CLI: %v: %s", err, out)
	}
	configHome := filepath.Join(evidence, "config")
	if err := os.Mkdir(configHome, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", configHome)
	dataHome := filepath.Join(evidence, "data")
	if err := os.MkdirAll(filepath.Join(dataHome, "applications"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_DATA_DIRS", filepath.Join(evidence, "empty-data"))
	for _, id := range []string{"fbi-test-a.desktop", "fbi-test-b.desktop"} {
		entry := []byte("[Desktop Entry]\nType=Application\nName=" + id + "\nExec=/bin/true\n")
		if err := os.WriteFile(filepath.Join(dataHome, "applications", id), entry, 0600); err != nil {
			t.Fatal(err)
		}
	}
	discovered, err := applications.Discover(applications.DataDirs())
	if err != nil || len(discovered) != 2 || discovered[0].ID != "fbi-test-a.desktop" || discovered[1].ID != "fbi-test-b.desktop" {
		t.Fatalf("synthetic desktop discovery: %+v %v", discovered, err)
	}
	policyPath, err := policy.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	runPolicyCLI := func(args ...string) {
		cmd := exec.Command(binary, append([]string{"app", "policy"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("policy CLI %v: %v: %s", args, err, out)
		}
	}
	for _, pair := range [][2]string{{"fbi-test-a.desktop", "wan-a"}, {"fbi-test-b.desktop", "wan-b"}} {
		runPolicyCLI("set", pair[0], "--wan", pair[1], "--mode", "strict")
	}
	reloaded, err := policy.Read(policyPath)
	if err != nil || len(reloaded.Policies) != 2 {
		t.Fatalf("persisted policy reload: %+v %v", reloaded, err)
	}
	identitySnapshot := network.Snapshot{Devices: []network.Device{{ID: "wan-a", Name: "fbi_ca", Candidate: true}, {ID: "wan-b", Name: "fbi_cb", Candidate: true}}}
	for i, saved := range reloaded.Policies {
		resolved := policy.Resolve(saved, identitySnapshot)
		want := "fbi_ca"
		if i == 1 {
			want = "fbi_cb"
		}
		if resolved.Status != "RESOLVED" || resolved.PreferredInterface != want {
			t.Fatalf("saved policy resolution %s: %+v", saved.ID, resolved)
		}
	}
	runCLISelected := func(app *NamespaceEngine, selector, value, wan, label string, command ...string) (int, string, error) {
		args := []string{"app", "run", selector, value, "--"}
		args = append(args, command...)
		cmd := exec.Command(binary, args...)
		cmd.ExtraFiles = []*os.File{app.fd}
		cmd.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_NETNS_NAME="+app.Name(), "FBI_GO_APP_WAN="+wan, "FBI_GO_APP_LOG_LABEL="+label)
		var stdout, stderr boundedCapture
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Start(); err != nil {
			return 0, "", fmt.Errorf("start fbi CLI: %w", err)
		}
		pid := cmd.Process.Pid
		err := cmd.Wait()
		if err != nil {
			var exit *exec.ExitError
			exitCode := -1
			if errors.As(err, &exit) {
				exitCode = exit.ExitCode()
			}
			nsIdentity, identityErr := namespaceIdentity(filepath.Join("/run/netns", app.Name()))
			if identityErr != nil {
				nsIdentity = "unavailable: " + identityErr.Error()
			}
			readApp := func(kind string) string {
				b, readErr := os.ReadFile(filepath.Join(evidence, "managed-"+label+".app."+kind))
				if readErr != nil {
					return "unavailable: " + readErr.Error()
				}
				if len(b) > 16<<10 {
					b = b[:16<<10]
				}
				return string(b)
			}
			return pid, stdout.String(), fmt.Errorf("fbi CLI pid %d exited %d in owned namespace %s (%s; WAN %s, controller UID/GID %d/%d, policy weights %v): %w; CLI stdout=%q; CLI stderr=%q; application stdout=%q; application stderr=%q", pid, exitCode, app.Name(), nsIdentity, wan, os.Geteuid(), os.Getegid(), app.applied.WANs, err, stdout.String(), stderr.String(), readApp("stdout"), readApp("stderr"))
		}
		return pid, stdout.String(), nil
	}
	runCLI := func(app *NamespaceEngine, wan, label string, command ...string) (int, string, error) {
		return runCLISelected(app, "--wan", wan, wan, label, command...)
	}
	runSavedCLI := func(app *NamespaceEngine, id, wan, label string, command ...string) (int, string, error) {
		return runCLISelected(app, "--app", id, wan, label, command...)
	}
	idPath, err := exec.LookPath("id")
	if err != nil {
		t.Fatal(err)
	}
	idPath, err = filepath.Abs(idPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runSavedCLI(apps[0], "missing.desktop", "wan-a", "missing-pol", idPath, "-u"); err == nil || !strings.Contains(err.Error(), "no managed policy") {
		t.Fatalf("missing saved policy did not fail before execution: %v", err)
	}
	if _, _, err := runSavedCLI(apps[1], "fbi-test-a.desktop", "wan-b", "wrong-pol", idPath, "-u"); err == nil || !strings.Contains(err.Error(), "launch refused") {
		t.Fatalf("mismatched saved policy did not fail before execution: %v", err)
	}
	_, smokeOutput, err := runCLI(apps[0], "wan-a", "smoke-a", idPath, "-u")
	if err != nil {
		t.Fatalf("minimal nonroot launch: %v", err)
	}
	if strings.TrimSpace(smokeOutput) != os.Getenv("FBI_GO_CALLER_UID") {
		t.Fatalf("minimal managed target UID %q, want %s", strings.TrimSpace(smokeOutput), os.Getenv("FBI_GO_CALLER_UID"))
	}
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	nftPath, err = filepath.Abs(nftPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(apps[0], "wan-a", "ipv6-delete-denied", nftPath, "delete", "table", "ip6", ipv6GuardTable(apps[0].TableName())); err == nil {
		t.Fatal("unprivileged managed application removed IPv6 guard")
	}
	if drops := guardDropCount(t, apps[0]); drops < 0 {
		t.Fatal("IPv6 guard disappeared")
	}
	resolverPath := filepath.Join(evidence, "managed-resolv.conf")
	if err := os.WriteFile(resolverPath, []byte("nameserver 203.0.113.7\nsearch lab.test\noptions timeout:1 attempts:1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolver, err := os.Open(resolverPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	catPath, err = filepath.Abs(catPath)
	if err != nil {
		t.Fatal(err)
	}
	resolverCmd := exec.Command(binary, "app", "run", "--wan", "wan-a", "--", catPath, "/etc/resolv.conf")
	resolverCmd.ExtraFiles = []*os.File{apps[0].fd, resolver}
	resolverCmd.Env = append(os.Environ(), "FBI_GO_APP_NETNS_FD=3", "FBI_GO_APP_RESOLVER_FD=4", "FBI_GO_APP_NETNS_NAME="+apps[0].Name(), "FBI_GO_APP_WAN=wan-a")
	resolverOut, resolverErr := resolverCmd.CombinedOutput()
	if resolverErr != nil || !strings.Contains(string(resolverOut), "nameserver 203.0.113.7") || !strings.Contains(string(resolverOut), "search lab.test") {
		t.Fatalf("isolated resolver bind: %v: %s", resolverErr, resolverOut)
	}
	if _, _, err := runCLI(apps[0], "wan-a", "missing-exe", filepath.Join(evidence, "not-an-executable")); err == nil || !strings.Contains(err.Error(), "resolve managed executable") {
		t.Fatalf("missing executable did not fail at validation stage: %v", err)
	}
	deniedPath := filepath.Join(evidence, "non-executable")
	if err := os.WriteFile(deniedPath, []byte("#!/bin/sh\nexit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(apps[0], "wan-a", "no-exec", deniedPath); err == nil || !strings.Contains(err.Error(), "executable is not a regular executable file") {
		t.Fatalf("non-executable path was accepted: %v", err)
	}
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	shPath, err = filepath.Abs(shPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(apps[0], "wan-a", "exit-42", shPath, "-c", "exit 42"); err == nil {
		t.Fatal("nonzero target exit was swallowed")
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 42 {
			t.Fatalf("target exit code not preserved: %v", err)
		}
	}
	// Both launches start before either is waited on. RunManaged enforces a
	// nonzero target UID and closes the namespace FD before target exec.
	type launchResult struct {
		index, pid int
		err        error
	}
	results := make(chan launchResult, 2)
	for i, app := range apps {
		wan := "wan-a"
		if i == 1 {
			wan = "wan-b"
		}
		go func(i int, app *NamespaceEngine, wan string) {
			id := "fbi-test-a.desktop"
			if i == 1 {
				id = "fbi-test-b.desktop"
			}
			pid, _, err := runSavedCLI(app, id, wan, fmt.Sprintf("client-%d", i), python, clientPath, fmt.Sprintf("managed-%d", i), filepath.Join(evidence, fmt.Sprintf("managed-%d-process.json", i)))
			results <- launchResult{i, pid, err}
		}(i, app, wan)
	}
	var launchPIDs [2]int
	for range apps {
		result := <-results
		if result.err != nil {
			t.Fatalf("managed launch: %v", result.err)
		}
		launchPIDs[result.index] = result.pid
	}
	type processIdentity struct {
		ID               string `json:"id"`
		PID              int    `json:"pid"`
		StartTicks       uint64 `json:"start_ticks"`
		UID              int    `json:"uid"`
		GID              int    `json:"gid"`
		CapEff           uint64 `json:"cap_eff"`
		UIDMap           string `json:"uid_map"`
		GIDMap           string `json:"gid_map"`
		Setgroups        string `json:"setgroups"`
		NetworkNamespace uint64 `json:"network_namespace"`
		UserNamespace    uint64 `json:"user_namespace"`
	}
	var processIDs [2]processIdentity
	var childIDs [2]processIdentity
	callerUID, err := strconv.Atoi(os.Getenv("FBI_GO_CALLER_UID"))
	if err != nil || callerUID <= 0 {
		t.Fatal("invalid caller UID")
	}
	callerGID, err := strconv.Atoi(os.Getenv("FBI_GO_CALLER_GID"))
	if err != nil || callerGID < 0 {
		t.Fatal("invalid caller GID")
	}
	if callerGID == 0 {
		callerGID = callerUID
	}
	parentUserNS, err := os.Stat("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	for i, app := range apps {
		readIdentity := func(path string) processIdentity {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var result processIdentity
			if err := json.Unmarshal(b, &result); err != nil {
				t.Fatal(err)
			}
			return result
		}
		processIDs[i] = readIdentity(filepath.Join(evidence, fmt.Sprintf("managed-%d-process.json", i)))
		child := readIdentity(filepath.Join(evidence, fmt.Sprintf("managed-%d-process.json.child", i)))
		childIDs[i] = child
		if processIDs[i].ID != fmt.Sprintf("managed-%d", i) || child.ID != fmt.Sprintf("managed-%d-child", i) {
			t.Errorf("managed policy identifier mismatch: parent=%s child=%s", processIDs[i].ID, child.ID)
		}
		st, err := app.fd.Stat()
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []processIdentity{processIDs[i], child} {
			if identity.PID <= 0 || identity.StartTicks == 0 || identity.UID != callerUID || identity.GID != callerGID || identity.CapEff != 0 || identity.Setgroups != "deny" ||
				identity.NetworkNamespace != st.Sys().(*syscall.Stat_t).Ino || identity.UserNamespace == parentUserNS.Sys().(*syscall.Stat_t).Ino ||
				strings.Join(strings.Fields(identity.UIDMap), " ") != fmt.Sprintf("%d 0 1", callerUID) || strings.Join(strings.Fields(identity.GIDMap), " ") != fmt.Sprintf("%d 0 1", callerGID) {
				t.Errorf("invalid managed process identity: %+v", identity)
			}
		}
		if child.PID == processIDs[i].PID || child.UserNamespace != processIDs[i].UserNamespace || child.NetworkNamespace != processIDs[i].NetworkNamespace {
			t.Errorf("managed child did not inherit identity: parent=%+v child=%+v", processIDs[i], child)
		}
	}
	badLaunchFile := filepath.Join(evidence, "invalid-map-target-started")
	previousUID := os.Getenv("FBI_GO_CALLER_UID")
	if err := os.Setenv("FBI_GO_CALLER_UID", "0"); err != nil {
		t.Fatal(err)
	}
	badLaunchErr := RunManaged(context.Background(), ManagedLaunch{NamespaceFD: apps[0].fd, NamespaceName: apps[0].Name(), WAN: "wan-a", Command: []string{python, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()", badLaunchFile}})
	if err := os.Setenv("FBI_GO_CALLER_UID", previousUID); err != nil {
		t.Fatal(err)
	}
	if badLaunchErr == nil {
		t.Error("invalid caller mapping accepted")
	}
	if _, err := os.Stat(badLaunchFile); !os.IsNotExist(err) {
		t.Errorf("target started after mapping rejection: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		complete := true
		for i := range apps {
			logs := labRecords(t, paths[i])
			count := 0
			for _, records := range logs {
				for _, r := range records {
					if strings.HasPrefix(r.Flow, fmt.Sprintf("managed-%d-", i)) {
						count++
					}
				}
			}
			if count < 49 { // parent + 8 TCP * 3 + 8 UDP * 3
				complete = false
			}
		}
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("managed packet observations incomplete")
		}
		time.Sleep(25 * time.Millisecond)
	}
	for i := range apps {
		logs := labRecords(t, paths[i])
		for _, stage := range []struct {
			prefix         string
			flows, packets int
		}{
			{fmt.Sprintf("managed-%d-tcp_affinity", i), 8, 3},
			{fmt.Sprintf("managed-%d-udp", i), 8, 3},
		} {
			counts, selected := verifyStage(t, logs, stage.prefix, stage.flows, stage.packets)
			if counts[i] != stage.flows || counts[1-i] != 0 {
				t.Errorf("managed app %d escaped selected WAN: %v", i, counts)
			}
			if strings.HasSuffix(stage.prefix, "tcp_affinity") {
				ports := map[string]int{}
				for _, r := range selected[i] {
					if old, ok := ports[r.Flow]; ok && old != r.Port {
						t.Errorf("managed TCP flow %s changed source port", r.Flow)
					}
					ports[r.Flow] = r.Port
				}
			}
		}
		parent := 0
		for j, records := range logs {
			for _, r := range records {
				if r.Flow == fmt.Sprintf("managed-%d-parent", i) {
					if j != i {
						t.Errorf("managed parent %d used WAN %d", i, j)
					}
					parent++
				}
			}
		}
		if parent != 1 {
			t.Errorf("managed parent %d observed %d times", i, parent)
		}
	}
	var concurrentTCP [2][]packetRecord
	for i := range apps {
		for _, records := range labRecords(t, paths[i]) {
			for _, r := range records {
				if r.Proto == "tcp" && strings.HasPrefix(r.Flow, fmt.Sprintf("managed-%d-tcp_affinity-", i)) {
					concurrentTCP[i] = append(concurrentTCP[i], r)
				}
			}
		}
	}
	overlap := false
	for _, a := range concurrentTCP[0] {
		for _, b := range concurrentTCP[1] {
			if a.StartNS < b.EndNS && b.StartNS < a.EndNS {
				overlap = true
				break
			}
		}
	}
	if !overlap {
		t.Error("no concurrent managed TCP flows observed across WANs")
	}
	verifyManagedDNSHTTP(t, apps, gateways, binary, resolver, evidence)
	verifyManagedIPv6Guard(t, apps, gateways, binary, resolver, evidence)
	runPolicyCLI("remove", "fbi-test-a.desktop")
	afterRemoval, err := policy.Read(policyPath)
	if err != nil || len(afterRemoval.Policies) != 1 || afterRemoval.Policies[0].ID != "fbi-test-b.desktop" {
		t.Fatalf("policy removal did not persist: %+v %v", afterRemoval, err)
	}
	if _, _, err := runSavedCLI(apps[0], "fbi-test-a.desktop", "wan-a", "removed-pol", idPath, "-u"); err == nil || !strings.Contains(err.Error(), "no managed policy") {
		t.Fatalf("removed policy still launched: %v", err)
	}
	// An ordinary process in a third, unconfigured namespace must retain its
	// own default route. The B-pinned application's nftables table is private.
	unmanaged := create()
	labRun(t, unmanaged, "ip", "link", "set", "lo", "up")
	labRun(t, unmanaged, "ip", "link", "add", "fbi_un", "type", "veth", "peer", "name", "fbi_gu")
	labRun(t, unmanaged, "ip", "link", "set", "fbi_gu", "netns", gateways[0][0].Name())
	labRun(t, unmanaged, "ip", "addr", "add", "198.18.0.9/24", "dev", "fbi_un")
	labRun(t, gateways[0][0], "ip", "addr", "add", "198.18.0.1/24", "dev", "fbi_gu")
	labRun(t, unmanaged, "ip", "link", "set", "fbi_un", "up")
	labRun(t, gateways[0][0], "ip", "link", "set", "fbi_gu", "up")
	checkLabLink(t, unmanaged, "fbi_un", "198.18.0.9/24")
	checkLabLink(t, gateways[0][0], "fbi_gu", "198.18.0.1/24")
	labRun(t, unmanaged, "ip", "route", "add", "default", "via", "198.18.0.1", "dev", "fbi_un")
	flowClient, err := filepath.Abs("testdata/flow_client.py")
	if err != nil {
		t.Fatal(err)
	}
	labRun(t, unmanaged, python, flowClient, "tcp", "unmanaged", "1")
	deadline = time.Now().Add(3 * time.Second)
	for {
		found := false
		for _, r := range labRecords(t, paths[0])[0] {
			if r.Flow == "unmanaged-0000" {
				if r.Source != "198.18.0.9" {
					t.Errorf("unmanaged source %s", r.Source)
				}
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unmanaged flow not observed on its own route")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Remove the pinned B gateway route. Its high-metric unreachable route
	// must prevent a fallback through A for unmarked managed traffic.
	app := apps[1]
	labRun(t, app, "ip", "-4", "route", "del", "table", "30001", "default", "via", "198.51.100.216", "dev", "fbi_cb")
	strictPath, err := filepath.Abs("testdata/managed_strict_probe.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(app, "wan-b", "strict-b", python, strictPath); err != nil {
		t.Fatalf("STRICT managed probe: %v", err)
	}
	for _, records := range labRecords(t, paths[1]) {
		for _, r := range records {
			if r.Flow == "managed-strict-leak" {
				t.Fatal("STRICT managed flow reached a gateway")
			}
		}
	}
	// Cancellation must terminate the managed process group and reap its
	// direct child before routing resources are removed.
	pidFile := filepath.Join(evidence, "managed-cancel.pid")
	ctx, cancel := context.WithCancel(context.Background())
	terminated := make(chan error, 1)
	go func() {
		terminated <- RunManaged(ctx, ManagedLaunch{NamespaceFD: apps[0].fd, NamespaceName: apps[0].Name(), WAN: "wan-a", Command: []string{python, "-c", "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)", pidFile}})
	}()
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-terminated
			t.Fatal("managed cancellation target never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-terminated; !errors.Is(err, context.Canceled) {
		t.Fatalf("managed cancellation: %v", err)
	}
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Errorf("managed process %d survived cancellation: %v", pid, err)
	}
	labRun(t, apps[0], "nft", "add", "table", "ip6", "fbi_foreign_probe")
	for i, app := range apps {
		if err := app.Disable(); err != nil {
			t.Fatal(err)
		}
		if err := app.Disable(); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if out := labRun(t, app, "nft", "list", "tables"); !strings.Contains(out, "table ip6 fbi_foreign_probe") {
				t.Errorf("foreign IPv6 nftables table was removed by owned cleanup: %s", out)
			}
			labRun(t, app, "nft", "delete", "table", "ip6", "fbi_foreign_probe")
		}
		if out := labRun(t, app, "nft", "list", "tables"); strings.TrimSpace(out) != "" {
			t.Errorf("managed cleanup left nftables objects: %s", out)
		}
		for _, table := range []int{30000, 30001} {
			if routes := labRouteTable(t, app, "managed cleanup", 4, table, true); strings.TrimSpace(routes) != "" {
				t.Errorf("managed cleanup left table %d: %s", table, routes)
			}
		}
		if rules := labRun(t, app, "ip", "-4", "rule", "show"); strings.Contains(rules, strconv.Itoa(15000)+":") || strings.Contains(rules, strconv.Itoa(15001)+":") {
			t.Errorf("managed cleanup left policy rule: %s", rules)
		}
	}
	for _, server := range servers {
		_ = server.Process.Kill()
		_ = server.Wait()
	}
	if err := unmanaged.Close(); err != nil {
		t.Fatalf("unmanaged namespace cleanup: %v", err)
	}
	for _, pair := range gateways {
		for _, gateway := range pair {
			if err := gateway.Close(); err != nil {
				t.Fatalf("gateway namespace cleanup: %v", err)
			}
		}
	}
	for _, app := range apps {
		if err := app.Close(); err != nil {
			t.Fatalf("managed namespace cleanup: %v", err)
		}
	}
	if names := labRegistryNames(); len(names) != 0 {
		t.Errorf("owned namespace registry not empty after cleanup: %v", names)
	}
	state := "VERIFIED"
	if t.Failed() {
		state = "FAILED"
	}
	summary := map[string]any{"state": state, "mechanism": "owned_app_network_namespace", "policy_source": "reloaded_toml_via_app_run_app", "apps": []map[string]any{{"id": "managed-0", "desktop_id": "fbi-test-a.desktop", "mode": "PINNED_WAN", "wan": "wan-a", "launcher_pid": launchPIDs[0], "process": processIDs[0], "child_process": childIDs[0], "namespace": apps[0].Name(), "observed_interface": "fbi_ca", "observed_source": "192.0.2.9", "tcp_flows": 8, "udp_flows": 8}, {"id": "managed-1", "desktop_id": "fbi-test-b.desktop", "mode": "PINNED_WAN", "wan": "wan-b", "launcher_pid": launchPIDs[1], "process": processIDs[1], "child_process": childIDs[1], "namespace": apps[1].Name(), "observed_interface": "fbi_cb", "observed_source": "198.51.100.99", "tcp_flows": 8, "udp_flows": 8}}, "strict": "PASS", "cleanup": "PASS"}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "managed-summary.json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
