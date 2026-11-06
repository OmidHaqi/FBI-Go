package routing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TestExecutorConfig is supplied by a trusted isolated-test launcher, never
// by public daemon IPC. The request protocol accepts no resource identifiers.
type TestExecutorConfig struct {
	NamespaceFD      *os.File
	PID1NetNSFD      *os.File // opened by trusted VM test parent, never by IPC
	ControlNetNSFD   *os.File // pinned by trusted test parent before worker enters target
	PinnedWorker     bool
	ListenerFD       *os.File // socket prepared by trusted setup before capability drop
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
}

type testExecutorRequest struct {
	Version   int    `json:"version"`
	Method    string `json:"method"`
	SessionID string `json:"session_id"`
	Sequence  uint64 `json:"sequence"`
}
type testExecutorResponse struct {
	Version int            `json:"version"`
	Code    string         `json:"code"`
	Message string         `json:"message,omitempty"`
	State   ExecutionState `json:"state,omitempty"`
}

const testExecutorProtocolVersion = 1
const testExecutorRequestLimit = 4096

func processStartTime(pid int) (string, error) {
	if pid <= 1 {
		return "", errors.New("invalid process identity")
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	end := bytes.LastIndexByte(b, ')')
	if end < 0 {
		return "", errors.New("malformed process stat")
	}
	fields := strings.Fields(string(b[end+1:]))
	// starttime is field 22; the fields after comm begin at field 3.
	if len(fields) <= 19 {
		return "", errors.New("process starttime unavailable")
	}
	return fields[19], nil
}

func testExecutorIsolation(rootless, pinned bool) error {
	if rootless {
		return verifyRootlessIsolationMode(!pinned)
	}
	if os.Getenv("FBI_GO_RUN_NETNS") != "1" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" {
		return errors.New("VM test executor requires explicit disposable-VM opt-in")
	}
	if out, err := exec.Command("systemd-detect-virt", "--vm", "--quiet").CombinedOutput(); err != nil {
		return fmt.Errorf("VM test executor requires a detected VM: %w: %s", err, out)
	}
	return nil
}

// A restricted guest executor lacks CAP_SYS_PTRACE, so procfs may deny stat
// of a different-UID controller's ns links. In that VM-only case, the trusted
// parent must have pinned the guest's initial namespace identities, and the
// controller must retain the identical full UID/GID maps. A nonroot process
// with zero effective capabilities in that user namespace cannot unshare or
// enter another network namespace without first changing its user mapping.
func validateControllerNamespace(c TestExecutorConfig, kind, expected, self string) error {
	path := filepath.Join("/proc", strconv.Itoa(c.ControllerPID), "ns", kind)
	got, err := namespaceIdentity(path)
	if err == nil {
		if got != expected {
			return fmt.Errorf("controller %s namespace changed: expected %s, actual %s", kind, expected, got)
		}
		return nil
	}
	if c.Rootless || !errors.Is(err, os.ErrPermission) || expected != self || c.ControllerUID == 0 {
		return fmt.Errorf("read controller %s namespace: expected %s, actual unavailable: %w", kind, expected, err)
	}
	for _, mapName := range []string{"uid_map", "gid_map"} {
		controllerMap, mapErr := os.ReadFile(filepath.Join("/proc", strconv.Itoa(c.ControllerPID), mapName))
		if mapErr != nil {
			return fmt.Errorf("read controller %s after namespace access denied: %w", mapName, mapErr)
		}
		selfMap, mapErr := os.ReadFile(filepath.Join("/proc/self", mapName))
		if mapErr != nil || !bytes.Equal(controllerMap, selfMap) {
			return fmt.Errorf("controller %s differs from guest executor user mapping: %v", mapName, mapErr)
		}
	}
	if caps, capErr := processEffectiveCapabilities(c.ControllerPID); capErr != nil || caps != 0 {
		return fmt.Errorf("controller capabilities unavailable or nonzero after namespace access denied: %#x: %v", caps, capErr)
	}
	return nil
}

func loadTestExecutorEngine(c TestExecutorConfig) (*NamespaceEngine, error) {
	if err := testExecutorIsolation(c.Rootless, c.PinnedWorker); err != nil {
		return nil, err
	}
	if c.PinnedWorker {
		if err := validatePinnedWorkerPrivileges(); err != nil {
			return nil, fmt.Errorf("restricted worker privileges: %w", err)
		}
	}
	if c.NamespaceFD == nil || c.Name == "" || c.ControllerPID <= 1 || c.ControllerUserNS == "" || c.ControllerNetNS == "" || len(c.SessionID) != 32 {
		return nil, errors.New("incomplete trusted executor configuration")
	}
	if _, err := hex.DecodeString(c.SessionID); err != nil {
		return nil, errors.New("invalid session identity")
	}
	if err := validateNetworkNamespaceFD(c.NamespaceFD); err != nil {
		return nil, err
	}
	fdInfo, err := c.NamespaceFD.Stat()
	if err != nil {
		return nil, err
	}
	var pid1Info os.FileInfo
	if c.PinnedWorker {
		if c.ControlNetNSFD == nil || c.ListenerFD == nil {
			return nil, errors.New("pinned worker requires trusted control namespace and listener FDs")
		}
		if err := validateNetworkNamespaceFD(c.ControlNetNSFD); err != nil {
			return nil, fmt.Errorf("validate pinned control namespace FD: %w", err)
		}
		pid1Info, err = c.ControlNetNSFD.Stat()
		if err != nil || os.SameFile(pid1Info, fdInfo) {
			return nil, errors.New("pinned control namespace missing or equals owned target")
		}
		selfInfo, selfErr := os.Stat("/proc/self/ns/net")
		if selfErr != nil || !os.SameFile(selfInfo, fdInfo) {
			return nil, errors.New("restricted worker is not in owned target namespace")
		}
		control := fmt.Sprintf("%d:%d", pid1Info.Sys().(*syscall.Stat_t).Dev, pid1Info.Sys().(*syscall.Stat_t).Ino)
		if c.ControllerNetNS != control {
			return nil, fmt.Errorf("controller network namespace differs from pinned control namespace: expected %s, actual %s", control, c.ControllerNetNS)
		}
	}
	if !c.Rootless {
		if c.PID1NetNSFD == nil {
			return nil, errors.New("trusted PID 1 namespace FD is required in VM")
		}
		if err := validateNetworkNamespaceFD(c.PID1NetNSFD); err != nil {
			return nil, fmt.Errorf("validate pinned PID 1 namespace FD: %w", err)
		}
		vmPID1Info, err := c.PID1NetNSFD.Stat()
		if err != nil {
			return nil, err
		}
		if !c.PinnedWorker {
			pid1Info = vmPID1Info
		}
		selfInfo, err := os.Stat("/proc/self/ns/net")
		if err != nil || (!c.PinnedWorker && !os.SameFile(vmPID1Info, selfInfo)) || os.SameFile(vmPID1Info, fdInfo) || (c.PinnedWorker && !os.SameFile(vmPID1Info, pid1Info)) {
			return nil, errors.New("pinned PID 1 namespace is not the VM control namespace or matches target")
		}
	}
	path := filepath.Join("/run/netns", c.Name)
	registered, err := os.Stat(path)
	if err != nil || !os.SameFile(fdInfo, registered) {
		return nil, errors.New("namespace FD does not match owned registry")
	}
	identity, err := namespaceIdentity(path)
	if err != nil {
		return nil, err
	}
	if got, err := processStartTime(c.ControllerPID); err != nil || got != c.ControllerStart {
		return nil, errors.New("controller process identity changed")
	}
	selfUserNS, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		return nil, err
	}
	selfNetNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	if err := validateControllerNamespace(c, "user", c.ControllerUserNS, selfUserNS); err != nil {
		return nil, err
	}
	if !c.PinnedWorker && c.ControllerNetNS != selfNetNS {
		return nil, fmt.Errorf("controller control-plane network namespace differs: expected %s, executor %s", c.ControllerNetNS, selfNetNS)
	}
	controlNetNS := selfNetNS
	if c.PinnedWorker {
		controlNetNS = c.ControllerNetNS
	}
	if err := validateControllerNamespace(c, "net", c.ControllerNetNS, controlNetNS); err != nil {
		return nil, err
	}
	if c.Rootless && c.ControllerUserNS == selfUserNS || !c.Rootless && c.ControllerUID == 0 {
		return nil, errors.New("controller lacks a separate unprivileged identity")
	}
	dir := os.Getenv("FBI_GO_JOURNAL_DIR")
	if err := checkedJournalDir(dir); err != nil {
		return nil, err
	}
	j, err := loadJournal(filepath.Join(dir, c.Name+".json"))
	if err != nil {
		return nil, err
	}
	if j.Name != c.Name || j.Identity != identity || j.NFTTable != c.Plan.NFTTable || j.Phase != "created" && j.Phase != "active" {
		return nil, errors.New("journal does not identify approved namespace state")
	}
	if err := validateNamespacePlan(c.Plan, j.NFTTable); err != nil {
		return nil, err
	}
	if j.Phase == "active" && (j.Plan == nil || !reflect.DeepEqual(*j.Plan, c.Plan)) {
		return nil, errors.New("active journal differs from approved plan")
	}
	e := &NamespaceEngine{name: c.Name, tableName: j.NFTTable, fd: c.NamespaceFD, identity: fdInfo, pid1FD: c.PID1NetNSFD, pid1Identity: pid1Info, pinnedWorker: c.PinnedWorker, rootless: c.Rootless, journalPath: filepath.Join(dir, c.Name+".json"), journalPhase: j.Phase, nftState: j.NFTState, operationID: j.OperationID, nftScriptHash: j.NFTScriptHash, ipv6GuardIntent: j.IPv6GuardIntent, ipv6GuardState: j.IPv6GuardState, ipv6GuardHash: j.IPv6GuardHash}
	if j.Plan != nil {
		e.applied = j.Plan
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return e, nil
}

func validatePinnedWorkerPrivileges() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	want := map[string]uint64{"CapInh:": 0, "CapPrm:": 1 << 12, "CapEff:": 1 << 12, "CapBnd:": 1 << 12, "CapAmb:": 0}
	seen := map[string]bool{}
	var nnp, seccomp, filters bool
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if expected, ok := want[fields[0]]; ok {
			actual, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil || actual != expected {
				return fmt.Errorf("%s got %s, expected %#x: %v", fields[0], fields[1], expected, err)
			}
			seen[fields[0]] = true
		}
		switch fields[0] {
		case "NoNewPrivs:":
			nnp = fields[1] == "1"
		case "Seccomp:":
			seccomp = fields[1] == "2"
		case "Seccomp_filters:":
			count, err := strconv.Atoi(fields[1])
			filters = err == nil && count >= 1
		}
	}
	if len(seen) != len(want) || !nnp || !seccomp || !filters {
		return errors.New("capability, no_new_privs or seccomp state incomplete")
	}
	return nil
}

func validateTestSocketDir(dir string) error {
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), "fbi-go-exec-") {
		return errors.New("test socket directory must be dedicated and absolute")
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0711 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe test socket directory")
	}
	return nil
}

// prepareTestExecutorListener is called only by the trusted isolated-test
// setup, before the worker drops CAP_CHOWN and enters its owned network namespace.
func prepareTestExecutorListener(c TestExecutorConfig) (*net.UnixListener, os.FileInfo, error) {
	if err := validateTestSocketDir(c.SocketDir); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(c.SocketDir, "control.sock")
	if _, err := os.Lstat(path); err == nil {
		return nil, nil, errors.New("test executor socket path already exists")
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("bind executor socket: %w", err)
	}
	l.SetUnlinkOnClose(false)
	fail := func(err error) (*net.UnixListener, os.FileInfo, error) {
		_ = l.Close()
		_ = os.Remove(path)
		return nil, nil, err
	}
	bound, err := os.Lstat(path)
	if err != nil || bound.Mode()&os.ModeSocket == 0 {
		return fail(fmt.Errorf("inspect bound executor socket: %v", err))
	}
	const atSymlinkNoFollow = 0x100
	const atFDCWD = -100
	if err := syscall.Fchmodat(atFDCWD, path, 0600, atSymlinkNoFollow); err != nil {
		return fail(fmt.Errorf("chmod owned executor socket: %w", err))
	}
	if err := syscall.Fchownat(atFDCWD, path, int(c.ControllerUID), int(c.ControllerGID), atSymlinkNoFollow); err != nil {
		return fail(fmt.Errorf("chown executor socket: %w", err))
	}
	if current, err := os.Lstat(path); err != nil || !os.SameFile(bound, current) || current.Mode().Perm() != 0600 || current.Sys().(*syscall.Stat_t).Uid != c.ControllerUID || current.Sys().(*syscall.Stat_t).Gid != c.ControllerGID {
		return fail(errors.New("test executor socket identity, owner or mode changed"))
	}
	return l, bound, nil
}

// ServeIsolatedTestExecutor runs only in a test-owned namespace context. It is
// deliberately separate from the public read-only daemon and HOST_APPLY.
func ServeIsolatedTestExecutor(ctx context.Context, c TestExecutorConfig) error {
	return serveIsolatedTestExecutor(ctx, c, nil)
}

// onReady is used by the integration child to acknowledge that the bound
// filesystem socket has its final identity, owner and mode. It is not an IPC
// request and is never supplied by an untrusted controller.
func serveIsolatedTestExecutor(ctx context.Context, c TestExecutorConfig, onReady func() error) error {
	e, err := loadTestExecutorEngine(c)
	if err != nil {
		return fmt.Errorf("validate owned namespace and journal: %w", err)
	}
	path := filepath.Join(c.SocketDir, "control.sock")
	var l *net.UnixListener
	var bound os.FileInfo
	if c.PinnedWorker {
		if err := validateTestSocketDir(c.SocketDir); err != nil {
			return fmt.Errorf("validate executor socket directory: %w", err)
		}
		listener, err := net.FileListener(c.ListenerFD)
		if err != nil {
			return fmt.Errorf("adopt prepared executor socket: %w", err)
		}
		var ok bool
		l, ok = listener.(*net.UnixListener)
		if !ok {
			listener.Close()
			return errors.New("prepared listener is not a Unix socket")
		}
		bound, err = os.Lstat(path)
		if err != nil || bound.Mode()&os.ModeSocket == 0 || bound.Mode().Perm() != 0600 || bound.Sys().(*syscall.Stat_t).Uid != c.ControllerUID || bound.Sys().(*syscall.Stat_t).Gid != c.ControllerGID {
			l.Close()
			return errors.New("prepared executor socket identity or owner invalid")
		}
		_ = c.ListenerFD.Close()
		_ = c.ControlNetNSFD.Close()
		if c.PID1NetNSFD != nil {
			_ = c.PID1NetNSFD.Close()
		}
		if err := auditPinnedWorkerSockets(l); err != nil {
			l.Close()
			return fmt.Errorf("audit inherited worker sockets: %w", err)
		}
	} else {
		l, bound, err = prepareTestExecutorListener(c)
		if err != nil {
			return err
		}
	}
	defer l.Close()
	defer func() {
		if current, err := os.Lstat(path); err == nil && os.SameFile(bound, current) {
			_ = os.Remove(path)
		}
	}()
	if onReady != nil {
		if err := onReady(); err != nil {
			return fmt.Errorf("notify executor readiness: %w", err)
		}
	}
	var sequence uint64
	for {
		if err := l.SetDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
			return err
		}
		conn, err := l.AcceptUnix()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					return nil
				}
				continue
			}
			return err
		}
		stop := handleTestExecutorConnection(conn, c, e, &sequence)
		_ = conn.Close()
		if stop {
			return nil
		}
	}
}

func auditPinnedWorkerSockets(l *net.UnixListener) error {
	raw, err := l.SyscallConn()
	if err != nil {
		return err
	}
	var listenerLink string
	if err := raw.Control(func(fd uintptr) {
		listenerLink, err = os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	}); err != nil {
		return err
	}
	if err != nil || !strings.HasPrefix(listenerLink, "socket:[") {
		return errors.New("prepared listener socket identity unavailable")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") && link != listenerLink {
			return fmt.Errorf("unexpected inherited socket on fd %s", entry.Name())
		}
	}
	return nil
}

func handleTestExecutorConnection(conn *net.UnixConn, c TestExecutorConfig, e *NamespaceEngine, sequence *uint64) bool {
	respond := func(code, message string) {
		if len(message) > 512 {
			message = message[:512]
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_ = json.NewEncoder(conn).Encode(testExecutorResponse{Version: testExecutorProtocolVersion, Code: code, Message: message})
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false
	}
	var cred *syscall.Ucred
	var sockErr error
	raw, err := conn.SyscallConn()
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
	}
	if err != nil || sockErr != nil || cred == nil || int(cred.Pid) != c.ControllerPID || cred.Uid != c.ControllerUID || cred.Gid != c.ControllerGID {
		respond("UNAUTHORIZED", "peer credentials do not match approved controller")
		return false
	}
	if got, err := processStartTime(int(cred.Pid)); err != nil || got != c.ControllerStart {
		respond("UNAUTHORIZED", "controller process identity changed")
		return false
	}
	selfUserNS, err := namespaceIdentity("/proc/self/ns/user")
	if err != nil {
		respond("UNAUTHORIZED", "executor user namespace unavailable")
		return false
	}
	if err := validateControllerNamespace(c, "user", c.ControllerUserNS, selfUserNS); err != nil {
		respond("UNAUTHORIZED", err.Error())
		return false
	}
	selfNetNS, err := namespaceIdentity("/proc/self/ns/net")
	if err != nil || (!c.PinnedWorker && c.ControllerNetNS != selfNetNS) {
		respond("UNAUTHORIZED", "controller control-plane network namespace differs")
		return false
	}
	controlNetNS := selfNetNS
	if c.PinnedWorker {
		controlNetNS = c.ControllerNetNS
	}
	if err := validateControllerNamespace(c, "net", c.ControllerNetNS, controlNetNS); err != nil {
		respond("UNAUTHORIZED", err.Error())
		return false
	}
	if caps, err := processEffectiveCapabilities(int(cred.Pid)); err != nil || caps != 0 {
		respond("UNAUTHORIZED", "controller has unexpected effective capabilities")
		return false
	}
	line, err := bufio.NewReader(io.LimitReader(conn, testExecutorRequestLimit+1)).ReadBytes('\n')
	if len(line) > testExecutorRequestLimit {
		respond("TOO_LARGE", "request exceeds limit")
		return false
	}
	if err != nil || len(line) == 0 || line[len(line)-1] != '\n' {
		respond("INVALID_REQUEST", "complete newline-delimited request required")
		return false
	}
	var req testExecutorRequest
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		respond("INVALID_REQUEST", "invalid request")
		return false
	}
	if req.Version != testExecutorProtocolVersion {
		respond("UNSUPPORTED_VERSION", "protocol version 1 required")
		return false
	}
	if req.SessionID != c.SessionID {
		respond("UNAUTHORIZED", "operation session mismatch")
		return false
	}
	if req.Sequence != *sequence+1 {
		respond("REPLAY", "request sequence is not next")
		return false
	}
	if err := testExecutorIsolation(c.Rootless, c.PinnedWorker); err != nil {
		respond("ISOLATION_FAILED", err.Error())
		return false
	}
	if err := e.validate(); err != nil {
		respond("OWNERSHIP_FAILED", err.Error())
		return false
	}
	var opErr error
	switch req.Method {
	case "APPLY":
		opErr = e.Apply(c.Plan)
	case "INSTALL_IPV6_GUARD":
		opErr = e.InstallIPv6Guard()
		if opErr == nil {
			opErr = e.VerifyIPv6Guard()
		}
	case "VERIFY":
		if e.applied == nil || e.journalPhase != "active" {
			opErr = errors.New("no active transaction")
		} else {
			e.mu.Lock()
			opErr = e.verifyAppliedLocked(*e.applied)
			e.mu.Unlock()
			if opErr == nil && e.ipv6GuardIntent {
				opErr = e.VerifyIPv6Guard()
			}
		}
	case "ROLLBACK":
		opErr = e.Disable()
	case "SHUTDOWN":
		if e.applied != nil {
			opErr = errors.New("active transaction must be rolled back first")
		}
	default:
		respond("UNSUPPORTED", "operation is not authorized")
		return false
	}
	if opErr != nil {
		respond("FAILED", opErr.Error())
		return false
	}
	*sequence = req.Sequence
	respond("OK", "")
	return req.Method == "SHUTDOWN"
}

func processEffectiveCapabilities(pid int) (uint64, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		}
	}
	return 0, errors.New("process CapEff unavailable")
}

// NewTestSessionID is used only by the trusted isolated test launcher.
func NewTestSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
