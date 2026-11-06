package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/omidhaqi/FBI-Go/internal/diagnostics"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
)

type fakeBackend struct {
	mu    sync.Mutex
	calls int
	snap  network.Snapshot
}

func (f *fakeBackend) Snapshot(ctx context.Context) (network.Snapshot, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.snap, nil
}

func startTestServer(t *testing.T, backend Backend) (string, context.CancelFunc) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("server intentionally refuses initial root UID")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Socket: path, Service: Service{Backend: backend}}).Serve(ctx) }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case serveErr := <-done:
			cancel()
			if errors.Is(serveErr, syscall.EPERM) {
				t.Skipf("Unix socket creation blocked by sandbox: %v", serveErr)
			}
			t.Fatalf("server start: %v", serveErr)
		default:
		}
		result, err := Call(context.Background(), path, Request{Version: Version, Method: "daemon.ping"})
		if err == nil && result.Error == nil {
			break
		}
		select {
		case serveErr := <-done:
			cancel()
			if errors.Is(serveErr, syscall.EPERM) {
				t.Skipf("Unix socket creation blocked by sandbox: %v", serveErr)
			}
			t.Fatalf("server start: %v", serveErr)
		case <-deadline.C:
			cancel()
			t.Fatalf("server never became ready: last response=%+v, error=%v", result, err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("server shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("server did not stop")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("socket not removed: %v", err)
		}
	})
	return path, cancel
}
func raw(t *testing.T, path, msg string) Response {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var r Response
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func requireCode(t *testing.T, r Response, code string) {
	t.Helper()
	if r.Error == nil {
		t.Fatalf("got no structured error: %+v; want %s", r, code)
	}
	if r.Error.Code != code {
		t.Fatalf("got error code=%q message=%q; want %s", r.Error.Code, r.Error.Message, code)
	}
}

func framedPing(size int) string {
	const ping = `{"version":1,"method":"daemon.ping"}`
	return ping + strings.Repeat(" ", size-len(ping)-1) + "\n"
}

func TestRequestSizeBoundaries(t *testing.T) {
	path, _ := startTestServer(t, &fakeBackend{})
	for _, tc := range []struct {
		name string
		size int
		code string
	}{
		{"below", maxRequest - 1, ""},
		{"exact", maxRequest, ""},
		{"above", maxRequest + 1, "TOO_LARGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := framedPing(tc.size)
			if len(msg) != tc.size {
				t.Fatalf("fixture size=%d want=%d", len(msg), tc.size)
			}
			r := raw(t, path, msg)
			if tc.code != "" {
				requireCode(t, r, tc.code)
				return
			}
			if r.Error != nil {
				t.Fatalf("valid boundary request rejected: code=%q message=%q", r.Error.Code, r.Error.Message)
			}
		})
	}
	if r := raw(t, path, framedPing(40)); r.Error != nil {
		t.Fatalf("normal request after oversize: %+v", r.Error)
	}
}

func TestFragmentedAndIncompleteFrames(t *testing.T) {
	path, _ := startTestServer(t, &fakeBackend{})
	connect := func(t *testing.T) *net.UnixConn {
		t.Helper()
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		return c
	}
	read := func(t *testing.T, c *net.UnixConn) Response {
		t.Helper()
		line, err := bufio.NewReader(c).ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var r Response
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	t.Run("fragmented oversized", func(t *testing.T) {
		c := connect(t)
		defer c.Close()
		msg := framedPing(maxRequest + 1)
		for i := 0; i < len(msg); i += 4096 {
			end := i + 4096
			if end > len(msg) {
				end = len(msg)
			}
			if _, err := c.Write([]byte(msg[i:end])); err != nil {
				t.Fatalf("fragment %d: %v", i, err)
			}
		}
		requireCode(t, read(t, c), "TOO_LARGE")
	})
	t.Run("very large", func(t *testing.T) {
		c := connect(t)
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			msg := framedPing(maxRequest * 16)
			for i := 0; i < len(msg); i += 4096 {
				end := i + 4096
				if end > len(msg) {
					end = len(msg)
				}
				if _, err := c.Write([]byte(msg[i:end])); err != nil {
					return
				}
			}
		}()
		requireCode(t, read(t, c), "TOO_LARGE")
		_ = c.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("writer did not stop")
		}
	})
	t.Run("missing newline", func(t *testing.T) {
		c := connect(t)
		defer c.Close()
		if _, err := c.Write([]byte(`{"version":1,"method":"daemon.ping"}`)); err != nil {
			t.Fatal(err)
		}
		if err := c.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		requireCode(t, read(t, c), "INVALID_REQUEST")
	})
	t.Run("disconnect during read", func(t *testing.T) {
		c := connect(t)
		_, _ = c.Write([]byte(`{"version":1`))
		_ = c.Close()
		r := raw(t, path, framedPing(40))
		if r.Error != nil {
			t.Fatalf("subsequent request: %+v", r.Error)
		}
	})
	t.Run("malformed within limit", func(t *testing.T) { requireCode(t, raw(t, path, `{"version":1,`+"\n"), "INVALID_REQUEST") })
}
func TestProtocolSecurity(t *testing.T) {
	f := &fakeBackend{}
	path, _ := startTestServer(t, f)
	for _, tc := range []struct{ name, msg, code string }{
		{"spoofed identity", `{"version":1,"method":"daemon.ping","uid":0,"pid":1}` + "\n", "INVALID_REQUEST"},
		{"malformed", `{"version":1,"method":` + "\n", "INVALID_REQUEST"},
		{"unsupported version", `{"version":2,"method":"daemon.ping"}` + "\n", "UNSUPPORTED_VERSION"},
		{"mutation", `{"version":1,"method":"daemon.apply"}` + "\n", "UNSUPPORTED"},
		{"host apply", `{"version":1,"method":"HOST_APPLY"}` + "\n", "UNSUPPORTED"},
		{"invalid policy", `{"version":1,"method":"daemon.plan","params":{"policy":{"mode":"PINNED_WAN","enabled":true}}}` + "\n", "INVALID_POLICY"},
		{"unknown param", `{"version":1,"method":"daemon.plan","params":{"policy":{"mode":"AUTO","enabled":true},"uid":0}}` + "\n", "INVALID_REQUEST"},
		{"too large", strings.Repeat("x", maxRequest+1) + "\n", "TOO_LARGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := raw(t, path, tc.msg)
			if r.Error == nil || r.Error.Code != tc.code {
				if r.Error == nil {
					t.Fatalf("got no structured error: %+v; want %s", r, tc.code)
				}
				t.Fatalf("got error code=%q message=%q; want %s", r.Error.Code, r.Error.Message, tc.code)
			}
		})
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls != 0 {
		t.Fatalf("invalid/mutating requests reached backend: %d", f.calls)
	}
}

func TestPlanAndConcurrentClients(t *testing.T) {
	f := &fakeBackend{snap: network.Snapshot{Devices: []network.Device{{ID: "stable-a", Name: "wan-a", Candidate: true, State: "up", Addresses: []string{"192.0.2.2/24"}}}}}
	path, _ := startTestServer(t, f)
	params, _ := json.Marshal(PlanRequest{Policy: policy.ApplicationPolicy{ID: "test.desktop", Mode: policy.PinnedWAN, PreferredWAN: "stable-a", FailureBehavior: policy.Strict, Enabled: true}})
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			method := "daemon.ping"
			if i%2 == 0 {
				method = "daemon.plan"
			}
			r, err := Call(context.Background(), path, Request{Version: Version, Method: method, Params: func() json.RawMessage {
				if method == "daemon.plan" {
					return params
				}
				return nil
			}()})
			if err != nil || r.Error != nil {
				t.Errorf("client %d: %+v %v", i, r.Error, err)
				return
			}
			if method == "daemon.plan" {
				b, _ := json.Marshal(r.Result)
				var p Preview
				if err := json.Unmarshal(b, &p); err != nil || p.Applied || p.Resources.SafeToApply || p.ValidatedWANID != "stable-a" || len(p.Conflicts) == 0 {
					t.Errorf("unsafe preview: %+v, %v", p, err)
				}
			}
		}(i)
	}
	wg.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Call(ctx, path, Request{Version: Version, Method: "daemon.ping"}); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	bad, _ := json.Marshal(PlanRequest{Policy: policy.ApplicationPolicy{ID: "test.desktop", Mode: policy.PinnedWAN, PreferredWAN: "missing", FailureBehavior: policy.Strict, Enabled: true}})
	r, err := Call(context.Background(), path, Request{Version: Version, Method: "daemon.plan", Params: bad})
	if err != nil || r.Error == nil || r.Error.Code != "WAN_UNRESOLVED" {
		t.Fatalf("missing WAN: %+v %v", r, err)
	}
	// A disconnected client cannot hold the single-request service open.
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte(`{"version":1`))
	_ = c.Close()
	r, err = Call(context.Background(), path, Request{Version: Version, Method: "daemon.ping"})
	if err != nil || r.Error != nil {
		t.Fatalf("after disconnect: %+v %v", r, err)
	}
}

func TestSocketPathAndCancellation(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	if err := safeSocketPath(filepath.Join(link, "socket")); err == nil {
		t.Fatal("symlink parent accepted")
	}
	path := filepath.Join(private, "socket")
	if err := os.Symlink("target", path); err != nil {
		t.Fatal(err)
	}
	if err := safeSocketPath(path); err == nil {
		t.Fatal("symlink socket accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Call(ctx, path, Request{Version: Version, Method: "daemon.ping"}); err == nil {
		t.Fatal("cancelled call accepted")
	}
}

func TestNoFollowFilesystemChmod(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Fchmodat(-100, link, 0600, 0x100); err == nil {
		t.Fatal("symlink chmod unexpectedly succeeded")
	}
	st, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0644 {
		t.Fatalf("symlink target mode changed: %o", st.Mode().Perm())
	}
	if err := syscall.Fchmodat(-100, target, 0600, 0x100); err != nil {
		t.Fatalf("fchmodat2 unavailable: %v", err)
	}
	st, err = os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("path mode not changed: %o", st.Mode().Perm())
	}
}

func TestFilesystemSocketIdentity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("regular-user socket test")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("Unix socket blocked by sandbox: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	fdInfo, err := f.Stat()
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	pathInfo, err := socketFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(fdInfo, pathInfo) {
		t.Fatal("listener sockfs FD unexpectedly shares filesystem socket identity")
	}
	if err := syscall.Fchmodat(-100, path, 0600, 0x100); err != nil {
		t.Fatal(err)
	}
	current, err := socketFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(pathInfo, current) || current.Mode().Perm() != 0600 {
		t.Fatalf("filesystem socket identity or mode changed unexpectedly: %v", current)
	}
}

func TestSocketLifecycleAndForeignPreservation(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("regular-user socket test")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	launch := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- (&Server{Socket: path, Service: Service{Backend: &fakeBackend{}}}).Serve(ctx) }()
		for i := 0; i < 200; i++ {
			select {
			case err := <-done:
				cancel()
				if errors.Is(err, syscall.EPERM) {
					t.Skipf("Unix socket blocked by sandbox: %v", err)
				}
				t.Fatalf("startup: %v", err)
			default:
			}
			resp, err := Call(context.Background(), path, Request{Version: Version, Method: "daemon.ping"})
			if err == nil && resp.Error == nil {
				return cancel, done
			}
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
		t.Fatal("server did not become ready")
		return nil, nil
	}
	cancel, done := launch()
	st, err := socketFile(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("bound socket: %v %v", st, err)
	}
	peer, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := peerCredentials(peer)
	_ = peer.Close()
	if err != nil || cred == nil || cred.Uid != uint32(os.Geteuid()) || cred.Gid != uint32(os.Getegid()) || cred.Pid <= 0 {
		t.Fatalf("SO_PEERCRED: %+v, %v", cred, err)
	}
	second := (&Server{Socket: path, Service: Service{Backend: &fakeBackend{}}}).Serve(context.Background())
	if second == nil || !strings.Contains(second.Error(), "already exists") {
		t.Fatalf("second server was not refused: %v", second)
	}
	if _, err := Call(context.Background(), path, Request{Version: Version, Method: "daemon.ping"}); err != nil {
		t.Fatalf("first server damaged by second: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("owned socket remained: %v", err)
	}
	// A fresh instance can reuse the pathname only after clean shutdown.
	cancel, done = launch()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	foreign.SetUnlinkOnClose(false)
	defer func() { _ = foreign.Close(); _ = os.Remove(path) }()
	foreignInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("shutdown after replacement: %v", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(foreignInfo, current) {
		t.Fatalf("foreign replacement removed: %v", err)
	}
}

func TestStartupRefusesExistingPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("regular-user socket test")
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "control.sock")
	if err := os.Symlink("other", path); err != nil {
		t.Fatal(err)
	}
	err := (&Server{Socket: path, Service: Service{Backend: &fakeBackend{}}}).Serve(context.Background())
	if err == nil {
		t.Fatal("existing symlink accepted")
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("foreign path modified: %v", err)
	}
}

func TestReadOnlyServiceWithoutSocket(t *testing.T) {
	if authorizedPeer(&syscall.Ucred{Uid: uint32(os.Geteuid()) + 1, Gid: uint32(os.Getegid())}) {
		t.Fatal("foreign peer UID authorized")
	}
	if authorizedPeer(&syscall.Ucred{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid()) + 1}) {
		t.Fatal("foreign peer GID authorized")
	}
	if os.Geteuid() != 0 && !authorizedPeer(&syscall.Ucred{Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}) {
		t.Fatal("same-UID peer rejected")
	}
	f := &fakeBackend{snap: network.Snapshot{Devices: []network.Device{{ID: "wan-stable", Name: "w0", Candidate: true, State: "up", Addresses: []string{"192.0.2.2/24"}}}}}
	s := Service{Backend: f}
	for _, method := range []string{"daemon.apply", "daemon.disable", "daemon.recover", "daemon.host-apply"} {
		r := s.call(context.Background(), Request{Version: Version, Method: method})
		if r.Error == nil || r.Error.Code != "UNSUPPORTED" {
			t.Fatalf("mutation %q: %+v", method, r)
		}
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 0 {
		t.Fatalf("mutation reached backend %d times", calls)
	}
	for _, tc := range []struct {
		policy policy.ApplicationPolicy
		code   string
	}{
		{policy.ApplicationPolicy{ID: "p", Mode: policy.PinnedWAN, Enabled: true}, "INVALID_POLICY"},
		{policy.ApplicationPolicy{ID: "p", Mode: policy.PinnedWAN, PreferredWAN: "missing", FailureBehavior: policy.Strict, Enabled: true}, "WAN_UNRESOLVED"},
	} {
		b, _ := json.Marshal(PlanRequest{Policy: tc.policy})
		r := s.call(context.Background(), Request{Version: Version, Method: "daemon.plan", Params: b})
		if r.Error == nil || r.Error.Code != tc.code {
			t.Fatalf("plan validation: %+v", r)
		}
	}
	b, _ := json.Marshal(PlanRequest{Policy: policy.ApplicationPolicy{ID: "p", Mode: policy.PinnedWAN, PreferredWAN: "wan-stable", FailureBehavior: policy.Strict, Enabled: true}})
	r := s.call(context.Background(), Request{Version: Version, Method: "daemon.plan", Params: b})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	p, ok := r.Result.(Preview)
	if !ok || p.Applied || p.Resources.SafeToApply || p.ValidatedWANID != "wan-stable" || len(p.Conflicts) == 0 {
		t.Fatalf("unsafe preview: %+v", r.Result)
	}
}

func TestDiagnosticsMethodIsReadOnly(t *testing.T) {
	calls := 0
	s := Service{CollectDiagnostics: func(ctx context.Context) diagnostics.Report {
		calls++
		return diagnostics.Report{ReadOnly: true, Findings: []diagnostics.Finding{{Code: "nft", Status: "UNKNOWN", Detail: "inventory unavailable"}}}
	}}
	r := s.call(context.Background(), Request{Version: Version, Method: "daemon.diagnostics"})
	report, ok := r.Result.(diagnostics.Report)
	if r.Error != nil || !ok || !report.ReadOnly || calls != 1 || len(report.Findings) != 1 {
		t.Fatalf("diagnostics result: %+v calls=%d", r, calls)
	}
	capabilities := s.call(context.Background(), Request{Version: Version, Method: "daemon.capabilities"})
	data, err := json.Marshal(capabilities.Result)
	if err != nil || !strings.Contains(string(data), "daemon.diagnostics") || !strings.Contains(string(data), `"host_apply":"UNSUPPORTED"`) {
		t.Fatalf("capabilities: %s %v", data, err)
	}
	if calls != 1 {
		t.Fatal("capabilities unexpectedly collected diagnostics")
	}
}
