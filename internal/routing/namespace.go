package routing

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var interfaceName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)

// NamespaceEngine owns a namespace created by NewTestNamespace. It cannot
// attach to an arbitrary pre-existing namespace. The open netns FD is used
// for every command, so replacing a name cannot redirect an apply operation.
type NamespaceEngine struct {
	mu              sync.Mutex
	name            string
	tableName       string
	fd              *os.File
	identity        os.FileInfo
	pid1FD          *os.File // trusted VM test parent pins PID 1 netns before capability drop
	pinnedWorker    bool     // isolated test worker already entered its owned netns
	pid1Identity    os.FileInfo
	closed          bool
	rootless        bool
	applied         *M2Plan
	journalPath     string
	journalPhase    string
	completed       bool
	ownJournalDir   bool
	nftState        string
	operationID     string
	nftScriptHash   string
	ipv6GuardIntent bool
	ipv6GuardState  string
	ipv6GuardHash   string
	// failAfter is a package-private integration-test fault injection point.
	failAfter int
	// failCommand injects one test-only command failure; never set by CLI/IPC.
	failCommand string
	// afterStage is a test-only crash hook; no public API or IPC sets it.
	afterStage func(string)
}

// NewTestNamespace creates a fresh, uniquely named namespace. It never moves
// physical interfaces or modifies routes in the current namespace.
func NewTestNamespace() (*NamespaceEngine, error) {
	if os.Getenv("FBI_GO_RUN_NETNS") != "1" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" {
		return nil, errors.New("test namespace creation requires explicit disposable-VM opt-in")
	}
	if out, err := exec.Command("systemd-detect-virt", "--vm", "--quiet").CombinedOutput(); err != nil {
		return nil, fmt.Errorf("test namespace creation requires a detected VM: %w: %s", err, out)
	}
	return newOwnedNamespace(false)
}

// NewRootlessTestNamespace accepts only the private user/net/mount namespace
// established by scripts/test-rootless-netns.sh. It never joins a supplied
// namespace path and leaves the VM-only constructor's guard intact.
func NewRootlessTestNamespace() (*NamespaceEngine, error) {
	if err := verifyRootlessIsolation(); err != nil {
		return nil, err
	}
	return newOwnedNamespace(true)
}

func newOwnedNamespace(rootless bool) (*NamespaceEngine, error) {
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(random)
	name := fmt.Sprintf("fbi-m2t-%d-%s", os.Getpid(), id)
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("create test namespace: %w: %s", err, out)
	}
	path := filepath.Join("/run/netns", name)
	fd, err := os.Open(path)
	if err != nil {
		_ = exec.Command("ip", "netns", "del", name).Run()
		return nil, err
	}
	identity, err := fd.Stat()
	if err != nil {
		_ = fd.Close()
		_ = exec.Command("ip", "netns", "del", name).Run()
		return nil, err
	}
	e := &NamespaceEngine{name: name, tableName: "fbi_m2t_" + id, fd: fd, identity: identity, rootless: rootless}
	if err := e.validate(); err != nil {
		if target, statErr := os.Stat(path); statErr == nil && os.SameFile(target, identity) {
			_ = exec.Command("ip", "netns", "del", name).Run()
		}
		_ = fd.Close()
		return nil, err
	}
	if err := e.initJournal(); err != nil {
		_ = exec.Command("ip", "netns", "del", name).Run()
		_ = fd.Close()
		return nil, err
	}
	return e, nil
}

func verifyRootlessIsolation() error {
	return verifyRootlessIsolationMode(true)
}

func verifyRootlessIsolationMode(setup bool) error {
	if os.Getenv("FBI_GO_ROOTLESS_TEST") != "1" || os.Getenv("FBI_GO_PARENT_NETNS") == "" || os.Getenv("FBI_GO_PARENT_USERNS") == "" {
		return errors.New("rootless test launcher environment missing")
	}
	callerUID, err := strconv.Atoi(os.Getenv("FBI_GO_CALLER_UID"))
	if err != nil || callerUID <= 0 {
		return errors.New("rootless launcher must originate from a non-root caller")
	}
	callerGID, err := strconv.Atoi(os.Getenv("FBI_GO_CALLER_GID"))
	if err != nil || callerGID < 0 {
		return errors.New("rootless launcher caller GID missing")
	}
	if os.Geteuid() != 0 {
		return errors.New("rootless child is not mapped to UID 0")
	}
	for _, pair := range []struct{ path, parent string }{{"/proc/self/ns/net", os.Getenv("FBI_GO_PARENT_NETNS")}, {"/proc/self/ns/user", os.Getenv("FBI_GO_PARENT_USERNS")}} {
		id, err := namespaceIdentity(pair.path)
		if err != nil || id == pair.parent {
			return fmt.Errorf("namespace isolation not proven for %s: %v", pair.path, err)
		}
	}
	selfNet, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	initNet, err := os.Stat("/proc/1/ns/net")
	if err == nil && os.SameFile(selfNet, initNet) {
		return errors.New("rootless network namespace matches PID 1")
	}
	mapBytes, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(mapBytes))
	if len(fields) < 3 || fields[0] != "0" || fields[1] != os.Getenv("FBI_GO_CALLER_UID") || fields[2] != "1" {
		return errors.New("unexpected rootless UID mapping")
	}
	groupMap, err := os.ReadFile("/proc/self/gid_map")
	if err != nil {
		return err
	}
	groupFields := strings.Fields(string(groupMap))
	if len(groupFields) != 3 || groupFields[0] != "0" || groupFields[1] != strconv.Itoa(callerGID) || groupFields[2] != "1" {
		return errors.New("unexpected rootless GID mapping")
	}
	setgroups, err := os.ReadFile("/proc/self/setgroups")
	if err != nil || strings.TrimSpace(string(setgroups)) != "deny" {
		return errors.New("rootless setgroups=deny inheritance not proven")
	}
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	privateRun := false
	for _, line := range strings.Split(string(mounts), "\n") {
		if strings.Contains(line, " /run ") && strings.Contains(line, " - tmpfs ") {
			privateRun = true
			break
		}
	}
	if !privateRun {
		return errors.New("private tmpfs /run mount not proven")
	}
	if st, err := os.Stat("/run/netns"); err != nil || !st.IsDir() {
		return errors.New("private namespace registry missing")
	}
	caps, err := effectiveCapabilities()
	if err != nil {
		return err
	}
	bits := []uint{12}
	if setup {
		bits = append(bits, 13, 21)
	} else if caps != 1<<12 {
		return fmt.Errorf("restricted rootless worker CapEff=%#x; expected CAP_NET_ADMIN only", caps)
	}
	for _, bit := range bits {
		if caps&(uint64(1)<<bit) == 0 {
			return fmt.Errorf("missing rootless effective capability bit %d", bit)
		}
	}
	return nil
}

func namespaceIdentity(path string) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d:%d", st.Sys().(*syscall.Stat_t).Dev, st.Sys().(*syscall.Stat_t).Ino), nil
}

func effectiveCapabilities() (uint64, error) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	return 0, errors.New("CapEff unavailable")
}

func (e *NamespaceEngine) Name() string {
	if e == nil {
		return ""
	}
	return e.name
}
func (e *NamespaceEngine) TableName() string {
	if e == nil {
		return ""
	}
	return e.tableName
}

func (e *NamespaceEngine) validate() error {
	if e == nil || e.closed || e.fd == nil || e.identity == nil || !strings.HasPrefix(e.name, "fbi-m2t-") {
		return errors.New("namespace is not owned by this engine")
	}
	target, err := os.Stat(filepath.Join("/run/netns", e.name))
	if err != nil {
		return err
	}
	opened, err := e.fd.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(opened, e.identity) || !os.SameFile(target, e.identity) {
		return errors.New("owned namespace name was replaced")
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	if e.pinnedWorker {
		if e.pid1Identity == nil || os.SameFile(opened, e.pid1Identity) || !os.SameFile(opened, self) {
			return errors.New("pinned worker left owned namespace or targets control namespace")
		}
		return nil
	}
	host, hostErr := os.Stat("/proc/1/ns/net")
	if hostErr != nil && !e.rootless {
		if !errors.Is(hostErr, os.ErrPermission) || e.pid1FD == nil || e.pid1Identity == nil {
			return fmt.Errorf("inspect PID 1 network namespace: %w", hostErr)
		}
		host, hostErr = e.pid1FD.Stat()
		if hostErr != nil || !os.SameFile(host, e.pid1Identity) {
			return errors.New("pinned PID 1 namespace FD changed")
		}
	}
	if os.SameFile(opened, self) || hostErr == nil && os.SameFile(opened, host) {
		return errors.New("refusing current or PID 1 network namespace")
	}
	return nil
}

func (e *NamespaceEngine) run(input string, args ...string) (string, error) {
	if err := e.validate(); err != nil {
		return "", err
	}
	if e.failCommand != "" && strings.Contains(strings.Join(args, " "), e.failCommand) {
		e.failCommand = ""
		return "", errors.New("injected kernel command failure")
	}
	var cmd *exec.Cmd
	if e.pinnedWorker {
		cmd = exec.Command(args[0], args[1:]...)
	} else {
		cmd = exec.Command("nsenter", append([]string{"--net=/proc/self/fd/3", "--"}, args...)...)
		cmd.ExtraFiles = []*os.File{e.fd}
	}
	cmd.Stdin = strings.NewReader(input)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%v: %w: %s", args, err, out.String())
	}
	return out.String(), nil
}

// A not-yet-created FIB table is empty only for callers explicitly inspecting
// unused tables or completed rollback. Applied-state checks remain strict.
func (e *NamespaceEngine) readRouteTable(family, table int, allowMissing bool) (string, error) {
	if family != 4 && family != 6 || table < 30000 || table > 30999 {
		return "", errors.New("invalid owned routing table query")
	}
	out, err := e.run("", "ip", fmt.Sprintf("-%d", family), "route", "show", "table", strconv.Itoa(table))
	return normalizeRouteTableRead(family, out, err, allowMissing)
}

func normalizeRouteTableRead(family int, output string, err error, allowMissing bool) (string, error) {
	if err == nil {
		return output, nil
	}
	var exit interface{ ExitCode() int }
	if allowMissing && (family == 4 || family == 6) && errors.As(err, &exit) && exit.ExitCode() == 2 {
		want := fmt.Sprintf("Error: ipv%d: FIB table does not exist.\nDump terminated", family)
		if strings.TrimSpace(output) == want {
			return "", nil
		}
	}
	return "", err
}

func verifyRequiredRoutes(w Allocation, output string) error {
	_, subnet, err := net.ParseCIDR(w.SourceCIDR)
	if err != nil {
		return err
	}
	connected, gateway := false, false
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == subnet.String() && hasFieldPair(fields, "dev", w.Interface) && hasFieldPair(fields, "src", w.SourceIP) {
			connected = true
		}
		if fields[0] == "default" && hasFieldPair(fields, "via", w.Gateway) && hasFieldPair(fields, "dev", w.Interface) && hasFieldPair(fields, "src", w.SourceIP) {
			gateway = true
		}
	}
	if !connected || !gateway {
		return fmt.Errorf("owned table %d missing required connected/default route (connected=%t default=%t)", w.Table, connected, gateway)
	}
	return nil
}

func requireUnoccupiedTable(table int, routes string) error {
	if strings.TrimSpace(routes) != "" {
		return fmt.Errorf("routing table %d occupied", table)
	}
	return nil
}

func validateNamespacePlan(p M2Plan, tableName string) error {
	if !p.SafeToApply || p.NFTTable != tableName || len(p.WANs) < 2 || p.IPv6Policy != "system" {
		return errors.New("unsafe or foreign namespace plan")
	}
	tables := map[int]bool{}
	priorities := map[int]bool{}
	marks := map[uint32]bool{}
	for _, w := range p.WANs {
		ip, subnet, err := net.ParseCIDR(w.SourceCIDR)
		gw := net.ParseIP(w.Gateway)
		if err != nil || ip.To4() == nil || gw.To4() == nil || !subnet.Contains(gw) || w.SourceIP != ip.String() || !interfaceName.MatchString(w.Interface) || w.Table < 30000 || w.Table > 30999 || w.Priority < 15000 || w.Priority > 15999 || w.Mark < 0x40000001 || w.Mark >= 0x40001000 || tables[w.Table] || priorities[w.Priority] || marks[w.Mark] {
			return errors.New("invalid or duplicate namespace allocation")
		}
		tables[w.Table] = true
		priorities[w.Priority] = true
		marks[w.Mark] = true
	}
	return nil
}

// Apply modifies only the newly created namespace. An error rolls back every
// successfully added route/rule; nft -f is submitted as one transaction.
func (e *NamespaceEngine) Apply(p M2Plan) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validate(); err != nil {
		return err
	}
	if e.applied != nil || e.journalPhase != "created" {
		return errors.New("namespace already has an applied or incomplete transaction")
	}
	if err := validateNamespacePlan(p, e.tableName); err != nil {
		return err
	}
	script, err := NFTScript(p)
	if err != nil {
		return err
	}
	if err = e.preflight(p); err != nil {
		return err
	}
	if e.afterStage != nil {
		e.afterStage("before-intent")
	}
	operation := make([]byte, 16)
	if _, err = rand.Read(operation); err != nil {
		return err
	}
	e.operationID = hex.EncodeToString(operation)
	script = strings.Replace(script, "add table ip "+p.NFTTable+"\n", "add table ip "+p.NFTTable+" { comment \"fbi-go:"+e.operationID+"\"; }\n", 1)
	e.nftScriptHash = scriptFingerprint(script)
	if err = e.writeJournal("preparing", &p, ""); err != nil {
		return err
	}
	if err = e.writeJournal("applying", &p, ""); err != nil {
		return errors.Join(err, e.writeJournal("created", nil, ""))
	}
	if e.afterStage != nil {
		e.afterStage("after-intent")
	}
	copyPlan := p
	e.applied = &copyPlan // Durable intent names every permissible resource.
	e.completed = false
	if e.afterStage != nil {
		e.afterStage("before-first")
	}
	stepsDone := 0
	rollback := func(cause error) error {
		return errors.Join(cause, e.disableLocked())
	}
	for _, w := range p.WANs {
		for _, s := range wanSteps(w) {
			if _, err = e.run("", s.add...); err != nil {
				return rollback(err)
			}
			stepsDone++
			if e.afterStage != nil {
				if stepsDone == 1 {
					e.afterStage("after-route")
				}
				if stepsDone == 4 {
					e.afterStage("after-rule")
				}
			}
			if e.failAfter == stepsDone {
				return rollback(errors.New("injected partial apply failure"))
			}
		}
	}
	if e.afterStage != nil {
		e.afterStage("before-nft-batch")
	}
	if _, err = e.run(script, "nft", "-f", "-"); err != nil {
		return rollback(err)
	}
	if e.afterStage != nil {
		e.afterStage("after-nft-batch")
		e.afterStage("after-nft-modified")
		e.afterStage("before-snapshot")
	}
	e.nftState, err = e.run("", "nft", "-j", "list", "table", "ip", p.NFTTable)
	if err != nil {
		// The nft batch may be installed, but its exact state is unknown.
		// Keep the journal and refuse ambiguous deletion.
		return fmt.Errorf("nft batch installed but ownership snapshot unavailable; recovery required: %w", err)
	}
	if err = e.writeJournal("verifying", &copyPlan, e.nftState); err != nil {
		return rollback(err)
	}
	if e.afterStage != nil {
		e.afterStage("after-snapshot")
		e.afterStage("after-nft")
	}
	stepsDone++
	if e.failAfter == stepsDone {
		return rollback(errors.New("injected failure after nft installation"))
	}
	if e.afterStage != nil {
		e.afterStage("during-verification")
	}
	if err = e.verifyAppliedLocked(p); err != nil {
		return rollback(err)
	}
	if e.afterStage != nil {
		e.afterStage("after-verification")
	}
	stepsDone++
	if e.failAfter == stepsDone {
		return rollback(errors.New("injected failure during verification"))
	}
	if err = e.writeJournal("active", &copyPlan, e.nftState); err != nil {
		return rollback(err)
	}
	if e.afterStage != nil {
		e.afterStage("after-commit")
		e.afterStage("active")
	}
	return nil
}

// verifyAppliedLocked checks exact installed resources. Packet-level delivery
// remains a separate integration gate and is never inferred from this scan.
func (e *NamespaceEngine) verifyAppliedLocked(p M2Plan) error {
	if err := e.validate(); err != nil {
		return err
	}
	currentNFT, err := e.run("", "nft", "-j", "list", "table", "ip", p.NFTTable)
	if err != nil {
		return err
	}
	if e.nftState == "" || currentNFT != e.nftState {
		return errors.New("owned nftables table changed during verification")
	}
	rules, err := e.run("", "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	for _, w := range p.WANs {
		routes, err := e.readRouteTable(4, w.Table, false)
		if err != nil {
			return err
		}
		if err := verifyRequiredRoutes(w, routes); err != nil {
			return err
		}
		found := false
		for _, line := range strings.Split(rules, "\n") {
			fields := strings.Fields(line)
			if strings.HasPrefix(strings.TrimSpace(line), strconv.Itoa(w.Priority)+":") && hasFWMark(fields, w.Mark) && hasFieldPair(fields, "lookup", strconv.Itoa(w.Table)) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("owned policy rule priority %d missing after apply", w.Priority)
		}
	}
	return nil
}

type commandStep struct{ add, del []string }

func wanSteps(w Allocation) []commandStep {
	t, pr := strconv.Itoa(w.Table), strconv.Itoa(w.Priority)
	mark := fmt.Sprintf("%#x/0xffffffff", w.Mark)
	_, subnet, _ := net.ParseCIDR(w.SourceCIDR)
	return []commandStep{
		{[]string{"ip", "-4", "route", "add", "table", t, subnet.String(), "dev", w.Interface, "src", w.SourceIP}, []string{"ip", "-4", "route", "del", "table", t, subnet.String(), "dev", w.Interface}},
		{[]string{"ip", "-4", "route", "add", "table", t, "unreachable", "default", "metric", "4278198272"}, []string{"ip", "-4", "route", "del", "table", t, "unreachable", "default", "metric", "4278198272"}},
		{[]string{"ip", "-4", "route", "add", "table", t, "default", "via", w.Gateway, "dev", w.Interface, "src", w.SourceIP}, []string{"ip", "-4", "route", "del", "table", t, "default", "via", w.Gateway, "dev", w.Interface}},
		{[]string{"ip", "-4", "rule", "add", "priority", pr, "fwmark", mark, "lookup", t}, []string{"ip", "-4", "rule", "del", "priority", pr, "fwmark", mark, "lookup", t}},
	}
}

func (e *NamespaceEngine) preflight(p M2Plan) error {
	rules, err := e.run("", "ip", "-4", "rule", "show")
	if err != nil {
		return err
	}
	if err := onlyDefaultRules(rules); err != nil {
		return err
	}
	rules6, err := e.run("", "ip", "-6", "rule", "show")
	if err != nil {
		return err
	}
	if err := onlyDefaultRules(rules6); err != nil {
		return err
	}
	tables, err := e.run("", "nft", "list", "tables")
	if err != nil {
		return err
	}
	if strings.TrimSpace(tables) != "" {
		return errors.New("foreign nftables table in test namespace")
	}
	for _, w := range p.WANs {
		out, err := e.readRouteTable(4, w.Table, true)
		if err != nil {
			return err
		}
		if err := requireUnoccupiedTable(w.Table, out); err != nil {
			return err
		}
		out, err = e.readRouteTable(6, w.Table, true)
		if err != nil {
			return err
		}
		if err := requireUnoccupiedTable(w.Table, out); err != nil {
			return fmt.Errorf("IPv6 %w", err)
		}
		out, err = e.run("", "ip", "-o", "-4", "addr", "show", "dev", w.Interface)
		if err != nil {
			return err
		}
		if !strings.Contains(out, w.SourceCIDR) {
			return fmt.Errorf("source %s missing on %s", w.SourceCIDR, w.Interface)
		}
	}
	return nil
}

func onlyDefaultRules(rules string) error {
	for _, line := range strings.Split(rules, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			return errors.New("unrecognized policy rule output")
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n != 0 && n != 32766 && n != 32767 {
			return errors.New("foreign policy rule in test namespace")
		}
	}
	return nil
}

// UpdateWeights changes only new-flow selection. Existing owned conntrack
// marks remain restorable. Zero disables a WAN for new flows.
func (e *NamespaceEngine) UpdateWeights(weights map[string]int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.validate(); err != nil {
		return err
	}
	if e.applied == nil {
		return errors.New("no applied plan")
	}
	p := *e.applied
	p.WANs = append([]Allocation(nil), e.applied.WANs...)
	if len(weights) != len(p.WANs) {
		return errors.New("weights must name every WAN")
	}
	for i := range p.WANs {
		v, ok := weights[p.WANs[i].Interface]
		if !ok {
			return fmt.Errorf("missing weight for %s", p.WANs[i].Interface)
		}
		p.WANs[i].Weight = v
	}
	script, err := NFTWeightUpdate(p)
	if err != nil {
		return err
	}
	if _, err = e.run(script, "nft", "-f", "-"); err != nil {
		return err
	}
	e.applied = &p
	e.nftState, err = e.run("", "nft", "-j", "list", "table", "ip", p.NFTTable)
	if err != nil {
		return err
	}
	if err = e.writeJournal("active", &p, e.nftState); err != nil {
		return err
	}
	return nil
}

// Disable removes exactly the resources recorded by this engine. Repeating it
// is a no-op. Unknown entries in an owned table are treated as stale conflict.
func (e *NamespaceEngine) Disable() error { e.mu.Lock(); defer e.mu.Unlock(); return e.disableLocked() }
func (e *NamespaceEngine) disableLocked() error {
	if err := e.validate(); err != nil {
		return err
	}
	if e.applied == nil {
		return nil
	}
	if err := e.disableIPv6GuardLocked(); err != nil {
		return err
	}
	p := *e.applied
	tables, err := e.run("", "nft", "list", "tables")
	if err != nil {
		return err
	}
	ownedNFT := hasNFTTable(tables, p.NFTTable)
	if ownedNFT {
		if e.nftState == "" {
			current, err := e.run("", "nft", "-j", "list", "table", "ip", p.NFTTable)
			if err != nil {
				return err
			}
			decision := classifyIncompleteNFT(ownershipJournal{OperationID: e.operationID, NFTTable: p.NFTTable, Plan: &p}, current)
			if decision == "MANUAL_INTERVENTION_REQUIRED" {
				return errors.New("MANUAL_INTERVENTION_REQUIRED: nftables batch has no durable rule-expression snapshot; refusing ambiguous deletion")
			}
			return errors.New("CONFLICT: nftables table differs from durable ownership intent; refusing deletion")
		}
		current, err := e.run("", "nft", "-j", "list", "table", "ip", p.NFTTable)
		if err != nil {
			return err
		}
		if current != e.nftState {
			return errors.New("owned nftables table changed; refusing deletion")
		}
	}
	// Inspect every proposed deletion before changing any resource.
	for _, w := range p.WANs {
		pr, table := strconv.Itoa(w.Priority), strconv.Itoa(w.Table)
		rules, err := e.run("", "ip", "-4", "rule", "show")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), pr+":") && (!hasFWMark(strings.Fields(line), w.Mark) || !hasFieldPair(strings.Fields(line), "lookup", table)) {
				return fmt.Errorf("priority %d now belongs to another rule", w.Priority)
			}
		}
		out, err := e.readRouteTable(4, w.Table, true)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" && !ownedRouteLine(w, line) {
				return fmt.Errorf("unexpected route in owned table %d: %s", w.Table, line)
			}
		}
	}
	if err := e.writeJournal("cleaning", &p, e.nftState); err != nil {
		return err
	}
	if e.afterStage != nil {
		e.afterStage("rolling-back")
	}
	if ownedNFT {
		if _, err = e.run("", "nft", "delete", "table", "ip", p.NFTTable); err != nil {
			return err
		}
	}
	for i := len(p.WANs) - 1; i >= 0; i-- {
		w := p.WANs[i]
		t, pr := strconv.Itoa(w.Table), strconv.Itoa(w.Priority)
		mark := fmt.Sprintf("%#x/0xffffffff", w.Mark)
		rules, err := e.run("", "ip", "-4", "rule", "show")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(rules, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), pr+":") {
				continue
			}
			fields := strings.Fields(line)
			if !hasFWMark(fields, w.Mark) || !hasFieldPair(fields, "lookup", t) {
				return fmt.Errorf("priority %d now belongs to another rule", w.Priority)
			}
			if _, err = e.run("", "ip", "-4", "rule", "del", "priority", pr, "fwmark", mark, "lookup", t); err != nil {
				return err
			}
		}
		out, err := e.readRouteTable(4, w.Table, true)
		if err != nil {
			return err
		}
		_, subnet, _ := net.ParseCIDR(w.SourceCIDR)
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "default via "+w.Gateway+" dev "+w.Interface) && hasFieldPair(strings.Fields(line), "src", w.SourceIP) {
				if _, err = e.run("", "ip", "-4", "route", "del", "table", t, "default", "via", w.Gateway, "dev", w.Interface); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, "unreachable default") && hasFieldPair(strings.Fields(line), "metric", "4278198272") {
				if _, err = e.run("", "ip", "-4", "route", "del", "table", t, "unreachable", "default", "metric", "4278198272"); err != nil {
					return err
				}
				continue
			}
			if strings.HasPrefix(line, subnet.String()+" dev "+w.Interface) && hasFieldPair(strings.Fields(line), "src", w.SourceIP) {
				if _, err = e.run("", "ip", "-4", "route", "del", "table", t, subnet.String(), "dev", w.Interface); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("unexpected route in owned table %d: %s", w.Table, line)
		}
	}
	e.applied = nil
	e.nftState = ""
	if err := e.writeJournal("created", nil, ""); err != nil {
		return err
	}
	e.completed = true
	return nil
}

func hasNFTTable(list, name string) bool {
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == "ip" && fields[2] == name {
			return true
		}
	}
	return false
}

func ownedRouteLine(w Allocation, line string) bool {
	_, subnet, err := net.ParseCIDR(w.SourceCIDR)
	if err != nil {
		return false
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	if fields[0] == "default" {
		return hasFieldPair(fields, "via", w.Gateway) && hasFieldPair(fields, "dev", w.Interface) && hasFieldPair(fields, "src", w.SourceIP)
	}
	if fields[0] == "unreachable" && len(fields) > 1 && fields[1] == "default" {
		return hasFieldPair(fields, "metric", "4278198272")
	}
	return fields[0] == subnet.String() && hasFieldPair(fields, "dev", w.Interface) && hasFieldPair(fields, "src", w.SourceIP)
}

func hasFieldPair(fields []string, key, value string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == key && fields[i+1] == value {
			return true
		}
	}
	return false
}
func hasFWMark(fields []string, mark uint32) bool {
	want := fmt.Sprintf("%#x", mark)
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != "fwmark" {
			continue
		}
		value := fields[i+1]
		return value == want || value == want+"/0xffffffff"
	}
	return false
}

// Close is idempotent and deletes only the exact namespace created by this
// handle. A replaced name is never removed. In a disposable VM, discarding
// the VM remains the recovery path after abrupt process termination.
func (e *NamespaceEngine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	if e.applied == nil && e.journalPhase != "created" {
		return errors.New("incomplete journaled apply; recovery required before namespace deletion")
	}
	var errs []error
	if e.applied != nil {
		if err := e.disableLocked(); err != nil {
			return err // Keep the named namespace and journal for safe recovery.
		}
	}
	if err := e.validate(); err == nil {
		if out, delErr := exec.Command("ip", "netns", "del", e.name).CombinedOutput(); delErr != nil {
			errs = append(errs, fmt.Errorf("delete owned namespace: %w: %s", delErr, out))
		}
	} else {
		errs = append(errs, err)
	}
	if len(errs) == 0 && e.journalPath != "" {
		if err := os.Remove(e.journalPath); err != nil {
			errs = append(errs, err)
		}
		if e.ownJournalDir {
			if err := os.Remove(filepath.Dir(e.journalPath)); err != nil {
				errs = append(errs, err)
			}
		}
	}
	e.closed = true
	if e.fd != nil {
		if err := e.fd.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
