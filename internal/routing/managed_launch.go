package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ManagedLaunch is deliberately limited to a preconfigured, test-owned rootless
// network namespace. The parent lab owns its routes, nftables table and FD.
// The command cannot attach to a namespace supplied by name or path.
type ManagedLaunch struct {
	NamespaceFD   *os.File
	ResolverFD    *os.File // optional test-owned resolv.conf, inherited as fd 4
	NSSwitchFD    *os.File // VM test only: private hosts: files dns, inherited as fd 5
	NamespaceName string
	WAN           string
	Command       []string
	// GuestVMTest permits the disposable-VM integration harness to launch a
	// nonroot target in an owned guest-root namespace. It is never set by CLI
	// or public IPC, and requires the independently approved VM workspace.
	GuestVMTest bool
}

func validateGuestVMManagedTest() (string, string, error) {
	if os.Geteuid() != 0 || os.Getenv("FBI_GO_VM_GUEST_WANS") != "YES" || os.Getenv("FBI_GO_DISPOSABLE_VM") != "YES" || os.Getenv("FBI_GO_VM_SNAPSHOT_CREATED") != "YES" || os.Getenv("FBI_GO_VM_SNAPSHOT_ID") == "" {
		return "", "", errors.New("guest VM managed test gate is not authorized")
	}
	if err := exec.Command("systemd-detect-virt", "--vm", "--quiet").Run(); err != nil {
		return "", "", fmt.Errorf("guest VM detection: %w", err)
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", "", err
	}
	pid1, err := os.Stat("/proc/1/ns/net")
	if err != nil || !os.SameFile(self, pid1) {
		return "", "", errors.New("guest VM test parent is not in initial network namespace")
	}
	workspace := os.Getenv("FBI_GO_VM_TEST_WORKSPACE")
	if !filepath.IsAbs(workspace) || workspace == "/" {
		return "", "", errors.New("guest VM test workspace missing")
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{
		{workspace, os.ModeDir | 0700},
		{filepath.Join(workspace, ".fbi-go-disposable-test-workspace"), 0600},
		{filepath.Join(workspace, ".fbi-go-guest-wan-approved"), 0600},
	} {
		st, err := os.Lstat(item.path)
		if err != nil || st.Mode() != item.mode || st.Sys().(*syscall.Stat_t).Uid != 0 {
			return "", "", fmt.Errorf("untrusted guest VM test path %q: %v", item.path, err)
		}
	}
	account, err := user.Lookup(os.Getenv("FBI_GO_VM_TEST_USER"))
	if err != nil || account.Uid != "1000" || account.Gid != "1000" {
		return "", "", fmt.Errorf("guest VM test user must map to UID/GID 1000: %v", err)
	}
	return account.Uid, account.Gid, nil
}

// limitedLogWriter caps test evidence without changing the application's
// normal stdout/stderr streams. It intentionally reports discarded bytes as
// written once the private diagnostic file reaches its limit.
type limitedLogWriter struct {
	file      *os.File
	remaining int
}

func (w *limitedLogWriter) Write(p []byte) (int, error) {
	length := len(p)
	if w.remaining == 0 {
		return length, nil
	}
	chunk := p
	if len(chunk) > w.remaining {
		chunk = chunk[:w.remaining]
	}
	n, err := w.file.Write(chunk)
	w.remaining -= n
	if err != nil {
		return n, err
	}
	if n != len(chunk) {
		return n, io.ErrShortWrite
	}
	return length, nil
}

func managedOutputFiles() (*os.File, *os.File, error) {
	label := os.Getenv("FBI_GO_APP_LOG_LABEL")
	if label == "" {
		return nil, nil, nil
	}
	if !interfaceName.MatchString(label) {
		return nil, nil, errors.New("invalid managed diagnostic label")
	}
	dir := os.Getenv("FBI_GO_EVIDENCE_DIR")
	if err := checkedJournalDir(dir); err != nil {
		return nil, nil, fmt.Errorf("unsafe managed diagnostic directory: %w", err)
	}
	open := func(kind string) (*os.File, error) {
		return os.OpenFile(filepath.Join(dir, "managed-"+label+".app."+kind), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	out, err := open("stdout")
	if err != nil {
		return nil, nil, err
	}
	errFile, err := open("stderr")
	if err != nil {
		closeErr := out.Close()
		removeErr := os.Remove(out.Name())
		return nil, nil, errors.Join(err, closeErr, removeErr)
	}
	return out, errFile, nil
}

// managedTargetIDs maps the invoking user's identity to nonzero IDs in a
// nested user namespace. The outer namespace maps only UID/GID 0, so these
// values are namespace-local identities, not host UID/GID mappings.
func managedTargetIDs(uidText, gidText string) (uint32, uint32, error) {
	uid, err := strconv.ParseUint(uidText, 10, 32)
	if err != nil || uid == 0 || uid == uint64(^uint32(0)) {
		return 0, 0, errors.New("nonzero caller UID required for managed target")
	}
	gid, err := strconv.ParseUint(gidText, 10, 32)
	if err != nil || gid == uint64(^uint32(0)) {
		return 0, 0, errors.New("valid caller GID required for managed target")
	}
	if gid == 0 {
		gid = uid
	}
	return uint32(uid), uint32(gid), nil
}

func (m ManagedLaunch) Validate() (string, error) {
	if m.GuestVMTest {
		if _, _, err := validateGuestVMManagedTest(); err != nil {
			return "", err
		}
	} else {
		if err := verifyRootlessIsolation(); err != nil {
			return "", err
		}
	}
	if m.NamespaceFD == nil || m.NamespaceFD.Fd() < 3 {
		return "", errors.New("owned application namespace FD required")
	}
	if err := validateNetworkNamespaceFD(m.NamespaceFD); err != nil {
		return "", fmt.Errorf("application namespace FD type: %w", err)
	}
	current, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return "", err
	}
	selected, err := m.NamespaceFD.Stat()
	if err != nil || os.SameFile(current, selected) {
		return "", errors.New("application namespace must differ from launcher namespace")
	}
	if !strings.HasPrefix(m.NamespaceName, "fbi-m2t-") || strings.Contains(m.NamespaceName, "/") {
		return "", errors.New("application namespace is not test-owned")
	}
	registered, err := os.Stat(filepath.Join("/run/netns", m.NamespaceName))
	if err != nil || !os.SameFile(registered, selected) {
		return "", errors.New("application namespace FD does not match private owned registry")
	}
	if m.WAN != "wan-a" && m.WAN != "wan-b" {
		return "", fmt.Errorf("unknown test WAN %q", m.WAN)
	}
	identity, err := namespaceIdentity(filepath.Join("/run/netns", m.NamespaceName))
	if err != nil {
		return "", err
	}
	journalDir := os.Getenv("FBI_GO_JOURNAL_DIR")
	if journalDir == "" {
		return "", errors.New("managed namespace ownership journal missing")
	}
	journal, err := loadJournal(filepath.Join(journalDir, m.NamespaceName+".json"))
	if err != nil {
		return "", fmt.Errorf("read managed ownership journal: %w", err)
	}
	if journal.Name != m.NamespaceName || journal.Identity != identity || journal.Phase != "active" || journal.Plan == nil {
		return "", errors.New("managed namespace has no matching active ownership journal")
	}
	selectedInterface := "fbi_ca"
	if m.WAN == "wan-b" {
		selectedInterface = "fbi_cb"
	}
	selectedWeight := 0
	for _, wan := range journal.Plan.WANs {
		if wan.Interface == selectedInterface {
			selectedWeight = wan.Weight
		} else if wan.Weight != 0 {
			return "", errors.New("managed namespace has a competing active WAN")
		}
	}
	if selectedWeight != 1 {
		return "", errors.New("selected WAN is not the active managed policy")
	}
	if !journal.IPv6GuardIntent || journal.IPv6GuardState == "" {
		return "", errors.New("kernel IPv6 guard is not durably active in owned namespace")
	}
	guard := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "nft", "-j", "-s", "list", "table", "ip6", ipv6GuardTable(journal.NFTTable))
	guard.ExtraFiles = []*os.File{m.NamespaceFD}
	guardState, err := guard.Output()
	if err != nil || string(guardState) != journal.IPv6GuardState {
		return "", fmt.Errorf("kernel IPv6 guard verification failed: %v", err)
	}
	if m.ResolverFD != nil {
		var resolverErr error
		if m.GuestVMTest {
			resolverErr = validateManagedResolverOwner(m.ResolverFD, 1000)
		} else {
			resolverErr = validateManagedResolver(m.ResolverFD)
		}
		if resolverErr != nil {
			return "", fmt.Errorf("managed resolver: %w", resolverErr)
		}
	}
	if m.NSSwitchFD != nil {
		if !m.GuestVMTest || m.ResolverFD == nil {
			return "", errors.New("private NSS configuration requires guest VM test resolver")
		}
		if err := validateGuestNSSwitch(m.NSSwitchFD); err != nil {
			return "", fmt.Errorf("managed NSS configuration: %w", err)
		}
	}
	if len(m.Command) == 0 || m.Command[0] == "" {
		return "", errors.New("absolute executable path required")
	}
	if !filepath.IsAbs(m.Command[0]) {
		return "", errors.New("executable path must be absolute")
	}
	path, err := filepath.EvalSymlinks(m.Command[0])
	if err != nil {
		return "", fmt.Errorf("resolve managed executable %q: %w", m.Command[0], err)
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat managed executable %q: %w", path, err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0111 == 0 {
		return "", errors.New("executable is not a regular executable file")
	}
	for _, arg := range m.Command {
		if strings.IndexByte(arg, 0) >= 0 {
			return "", errors.New("NUL byte in command argument")
		}
	}
	return path, nil
}

// This remains a diagnostic for unsupported external IPv6 routing, while the
// nftables guard enforces the boundary after launch despite route changes.
func rejectManagedExternalIPv6(fd *os.File) error {
	cmd := exec.Command("nsenter", "--net=/proc/self/fd/3", "--", "ip", "-j", "-6", "route", "show", "table", "all")
	cmd.ExtraFiles = []*os.File{fd}
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("inspect owned namespace IPv6 routes: %w", err)
	}
	var routes []struct {
		Dst  string `json:"dst"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return fmt.Errorf("decode owned namespace IPv6 routes: %w", err)
	}
	for _, route := range routes {
		if route.Type == "local" || route.Type == "broadcast" || route.Type == "multicast" || route.Type == "unreachable" || route.Type == "blackhole" || route.Type == "prohibit" || strings.HasPrefix(route.Dst, "fe80:") || strings.HasPrefix(route.Dst, "ff00:") || route.Dst == "::1" || route.Dst == "::1/128" {
			continue
		}
		return fmt.Errorf("managed IPv6 external route %q is unsupported; refusing launch to prevent WAN bypass", route.Dst)
	}
	return nil
}

func validateManagedResolver(fd *os.File) error {
	return validateManagedResolverOwner(fd, uint32(os.Geteuid()))
}

func validateManagedResolverOwner(fd *os.File, expectedUID uint32) error {
	if fd == nil || fd.Fd() < 3 {
		return errors.New("resolver FD missing")
	}
	st, err := fd.Stat()
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Size() == 0 || st.Size() > 4096 || st.Mode().Perm() != 0600 || stat.Uid != expectedUID {
		return errors.New("resolver must be an owned, mode-0600 regular file of at most 4096 bytes")
	}
	b := make([]byte, st.Size())
	if _, err := fd.ReadAt(b, 0); err != nil {
		return err
	}
	if strings.IndexByte(string(b), 0) >= 0 {
		return errors.New("resolver contains NUL byte")
	}
	nameservers := 0
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "nameserver":
			if len(fields) != 2 || net.ParseIP(fields[1]) == nil || fields[1] == "127.0.0.53" || strings.Contains(fields[1], ":") {
				return errors.New("invalid or host-stub resolver address")
			}
			nameservers++
		case "search":
			if len(fields) < 2 || len(fields) > 5 {
				return errors.New("invalid resolver search directive")
			}
		case "options":
			if len(fields) < 2 || len(fields) > 5 {
				return errors.New("invalid resolver options directive")
			}
		default:
			return fmt.Errorf("unsupported resolver directive %q", fields[0])
		}
	}
	if nameservers == 0 {
		return errors.New("resolver has no safe nameserver directive")
	}
	return nil
}

func validateGuestNSSwitch(fd *os.File) error {
	const expected = "passwd: files\ngroup: files\nhosts: files dns\n"
	if fd == nil || fd.Fd() < 3 {
		return errors.New("private NSS FD missing")
	}
	st, err := fd.Stat()
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || stat.Uid != 1000 || st.Size() != int64(len(expected)) {
		return errors.New("private NSS file ownership or size invalid")
	}
	b := make([]byte, st.Size())
	if _, err := fd.ReadAt(b, 0); err != nil {
		return err
	}
	if string(b) != expected {
		return errors.New("private NSS contents are not the fixed test policy")
	}
	return nil
}

// A named netns FD opened from /run/netns reads back as that pathname under
// /proc/self/fd, not necessarily as net:[inode]. NS_GET_NSTYPE checks the
// kernel object type without relying on a procfs symlink string.
func validateNetworkNamespaceFD(fd *os.File) error {
	if fd == nil {
		return errors.New("namespace FD missing")
	}
	const nsGetNSType = 0xb703 // _IO(NSIO, 0x3) from linux/nsfs.h
	typeValue, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), nsGetNSType, 0)
	if errno != 0 {
		return fmt.Errorf("NS_GET_NSTYPE: %w", errno)
	}
	if typeValue != uintptr(syscall.CLONE_NEWNET) {
		return fmt.Errorf("namespace type %#x is not CLONE_NEWNET", typeValue)
	}
	return nil
}

// RunManaged starts the application in an inherited network namespace and then
// a child user namespace mapped to the caller's nonzero UID/GID. This prevents the
// application from retaining CAP_NET_ADMIN in the network namespace's owner
// user namespace. All descendants inherit the selected network namespace.
func RunManaged(ctx context.Context, m ManagedLaunch) (runErr error) {
	path, err := m.Validate()
	if err != nil {
		return fmt.Errorf("validate managed namespace and policy: %w", err)
	}
	var uid, gid uint32
	if m.GuestVMTest {
		uidText, gidText, gateErr := validateGuestVMManagedTest()
		if gateErr != nil {
			return fmt.Errorf("prepare guest VM managed identity: %w", gateErr)
		}
		uid, gid, err = managedTargetIDs(uidText, gidText)
	} else {
		uid, gid, err = managedTargetIDs(os.Getenv("FBI_GO_CALLER_UID"), os.Getenv("FBI_GO_CALLER_GID"))
	}
	if err != nil {
		return fmt.Errorf("prepare managed UID/GID mapping: %w", err)
	}
	appOut, appErr, err := managedOutputFiles()
	if err != nil {
		return fmt.Errorf("prepare managed application output capture: %w", err)
	}
	if appOut != nil {
		defer func() {
			runErr = errors.Join(runErr, closeLogFile("stdout", appOut), closeLogFile("stderr", appErr))
		}()
	}
	// fd 3 is a test-owned namespace capability, used only by nsenter. The
	// final shell closes it before execing the application.
	// The outer namespace already has setgroups=deny. util-linux unshare
	// inherits that restriction; passing --setgroups=deny again causes EPERM.
	userArgs := []string{"unshare", "--user", "--map-user=" + strconv.FormatUint(uint64(uid), 10), "--map-group=" + strconv.FormatUint(uint64(gid), 10), "--", "sh", "-c", "exec 3<&-; exec \"$@\"", "fbi-app", path}
	if m.GuestVMTest {
		userArgs = []string{"setpriv", "--reuid=" + strconv.FormatUint(uint64(uid), 10), "--regid=" + strconv.FormatUint(uint64(gid), 10), "--clear-groups", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs", "--", "sh", "-c", "exec 3<&-; exec \"$@\"", "fbi-app", path}
	}
	userArgs = append(userArgs, m.Command[1:]...)
	args := []string{"--net=/proc/self/fd/3", "--"}
	if m.ResolverFD != nil {
		mountScript := "mount --bind /proc/self/fd/4 /etc/resolv.conf || { echo 'managed resolver bind failed' >&2; exit 125; }; exec 4<&-; exec \"$@\""
		if m.NSSwitchFD != nil {
			mountScript = "mount --bind /proc/self/fd/4 /etc/resolv.conf || { echo 'managed resolver bind failed' >&2; exit 125; }; mount --bind /proc/self/fd/5 /etc/nsswitch.conf || { echo 'managed NSS bind failed' >&2; exit 125; }; exec 4<&-; exec 5<&-; exec \"$@\""
		}
		args = append(args, "unshare", "--mount", "--propagation", "private", "--", "sh", "-c", mountScript, "fbi-resolver")
	}
	args = append(args, userArgs...)
	cmd := exec.Command("nsenter", args...)
	cmd.ExtraFiles = []*os.File{m.NamespaceFD}
	if m.ResolverFD != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, m.ResolverFD)
	}
	if m.NSSwitchFD != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, m.NSSwitchFD)
	}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "FBI_GO_APP_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if appOut != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, &limitedLogWriter{file: appOut, remaining: 16 << 10})
		cmd.Stderr = io.MultiWriter(os.Stderr, &limitedLogWriter{file: appErr, remaining: 16 << 10})
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start nsenter/nonroot managed command in %s: %w", m.NamespaceName, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("managed command chain in %s for %s exited %d: %w", m.NamespaceName, m.WAN, exit.ExitCode(), err)
		}
		return fmt.Errorf("wait for managed command in %s: %w", m.NamespaceName, err)
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return fmt.Errorf("cancel managed command in %s: %w", m.NamespaceName, ctx.Err())
	}
}

func closeLogFile(kind string, f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("close managed %s diagnostic file: %w", kind, err)
	}
	return nil
}

// RunManagedWithSignals forwards terminal cancellation to the process group.
func RunManagedWithSignals(m ManagedLaunch) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return RunManaged(ctx, m)
}
