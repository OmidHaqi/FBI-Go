// Package daemon provides an unprivileged, read-only local control plane.
package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omidhaqi/FBI-Go/internal/diagnostics"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"github.com/omidhaqi/FBI-Go/internal/routing"
)

const Version = 1
const maxRequest = 64 << 10
const maxResponse = 1 << 20
const ioTimeout = 5 * time.Second

type Mode string

const (
	PlanOnly     Mode = "PLAN_ONLY"
	IsolatedTest Mode = "ISOLATED_TEST" // Reserved; never accepted by this server.
	HostApply    Mode = "HOST_APPLY"    // Reserved; never accepted by this server.
)

type Request struct {
	Version int             `json:"version"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type Response struct {
	Version int       `json:"version"`
	Result  any       `json:"result,omitempty"`
	Error   *APIError `json:"error,omitempty"`
}
type PlanRequest struct {
	Policy policy.ApplicationPolicy `json:"policy"`
}
type Preview struct {
	State          string                   `json:"state"`
	Mode           Mode                     `json:"mode"`
	Applied        bool                     `json:"applied"`
	Requested      policy.ApplicationPolicy `json:"requested_policy"`
	ValidatedWANID string                   `json:"validated_wan_id,omitempty"`
	Resources      routing.M2Plan           `json:"proposed_resources"`
	Conflicts      []string                 `json:"conflicts"`
	Warnings       []string                 `json:"warnings"`
	Operations     []string                 `json:"required_operations"`
}
type Backend interface {
	Snapshot(context.Context) (network.Snapshot, error)
}
type ReadOnlyBackend struct{}

func (ReadOnlyBackend) Snapshot(ctx context.Context) (network.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return network.Snapshot{}, err
	}
	return network.Scan()
}

// Service has no Apply method. Consequently IPC cannot reach host mutations.
type Service struct {
	Backend            Backend
	CollectDiagnostics func(context.Context) diagnostics.Report // Optional test seam; nil uses read-only host collection.
}

func (s Service) call(ctx context.Context, req Request) Response {
	bad := func(code, message string) Response {
		return Response{Version: Version, Error: &APIError{Code: code, Message: message}}
	}
	if req.Version != Version {
		return bad("UNSUPPORTED_VERSION", "protocol version 1 required")
	}
	if req.Method == "" {
		return bad("INVALID_REQUEST", "method required")
	}
	if len(req.Params) != 0 && string(req.Params) != "null" && req.Method != "daemon.plan" {
		return bad("INVALID_REQUEST", "parameters are not supported for this method")
	}
	switch req.Method {
	case "daemon.ping":
		return Response{Version: Version, Result: map[string]any{"pong": true}}
	case "daemon.version":
		return Response{Version: Version, Result: map[string]any{"protocol": Version, "mode": PlanOnly}}
	case "daemon.capabilities":
		return Response{Version: Version, Result: map[string]any{"mode": PlanOnly, "read_only": []string{"daemon.ping", "daemon.version", "daemon.capabilities", "daemon.status", "daemon.diagnostics", "daemon.plan"}, "host_apply": "UNSUPPORTED", "isolated_test": "UNSUPPORTED"}}
	case "daemon.diagnostics":
		collect := s.CollectDiagnostics
		if collect == nil {
			collect = diagnostics.CollectHostContext
		}
		return Response{Version: Version, Result: collect(ctx)}
	case "daemon.status":
		if s.Backend == nil {
			return bad("INTERNAL", "inventory backend unavailable")
		}
		snap, err := s.Backend.Snapshot(ctx)
		if err != nil {
			return bad("INVENTORY_UNAVAILABLE", err.Error())
		}
		return Response{Version: Version, Result: map[string]any{"state": "PLANNED", "mode": PlanOnly, "applied": false, "snapshot": snap}}
	case "daemon.plan":
		var p PlanRequest
		if len(req.Params) == 0 || decodeStrict(req.Params, &p) != nil {
			return bad("INVALID_REQUEST", "valid policy parameters required")
		}
		if err := p.Policy.Validate(); err != nil {
			return bad("INVALID_POLICY", err.Error())
		}
		if !p.Policy.Enabled {
			return bad("INVALID_POLICY", "policy must be enabled")
		}
		if s.Backend == nil {
			return bad("INTERNAL", "inventory backend unavailable")
		}
		snap, err := s.Backend.Snapshot(ctx)
		if err != nil {
			return bad("INVENTORY_UNAVAILABLE", err.Error())
		}
		resolved := policy.Resolve(p.Policy, snap)
		if resolved.Status == "UNAVAILABLE" || resolved.Status == "UNSUPPORTED" {
			return bad("WAN_UNRESOLVED", resolved.Reason)
		}
		// Ownership and live health are intentionally unknown to this unprivileged process.
		inv := routing.Inventory{Snapshot: snap, IPv6Policy: "system"}
		for _, d := range snap.Devices {
			if d.Kind == "vpn" {
				inv.VPNPresent = true
			}
		}
		resources := (routing.DryRunExecutor{}).Plan(inv)
		preview := Preview{State: "PLANNED", Mode: PlanOnly, Applied: false, Requested: p.Policy, Resources: resources,
			Conflicts: resources.Reasons, Warnings: append([]string{}, resources.Warnings...), Operations: []string{}}
		if p.Policy.Mode == policy.PinnedWAN {
			preview.ValidatedWANID = p.Policy.PreferredWAN
		}
		preview.Warnings = append(preview.Warnings, "read-only inventory does not verify health, rule/table/mark/nft ownership or packet egress")
		if p.Policy.Mode == policy.PinnedWAN && p.Policy.FailureBehavior == policy.Strict {
			preview.Warnings = append(preview.Warnings, "IPv4-only M2 plan cannot provide complete IPv6 STRICT enforcement")
		}
		for _, w := range resources.WANs {
			preview.Operations = append(preview.Operations, fmt.Sprintf("future owned table %d, rule priority %d, mark %#x, nftables %s for %s", w.Table, w.Priority, w.Mark, resources.NFTTable, w.Interface))
		}
		return Response{Version: Version, Result: preview}
	default:
		return bad("UNSUPPORTED", "method is not available in PLAN_ONLY mode")
	}
}

func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

type Server struct {
	Socket       string
	Service      Service
	mu           sync.Mutex
	listener     *net.UnixListener
	active       map[*net.UnixConn]struct{}
	closed       bool
	identity     os.FileInfo
	shutdownOnce sync.Once
	shutdownErr  error
}

func socketParent(path string) error {
	if !filepath.IsAbs(path) || len(path) > 100 || filepath.Base(path) == "." || filepath.Base(path) == ".." {
		return errors.New("socket path must be a short absolute path")
	}
	parent := filepath.Dir(path)
	clean := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(parent, clean), clean) {
		if part == "" {
			continue
		}
		clean = filepath.Join(clean, part)
		st, err := os.Lstat(clean)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("socket parent includes non-directory or symlink")
		}
	}
	st, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	uid := st.Sys().(*syscall.Stat_t).Uid
	if uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0 {
		return errors.New("socket parent must be owned by daemon UID and private (0700)")
	}
	return nil
}

func safeSocketPath(path string) error {
	if err := socketParent(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Server) Serve(ctx context.Context) (serveErr error) {
	if os.Geteuid() == 0 {
		return errors.New("dry-run daemon must run as a nonroot user")
	}
	if err := safeSocketPath(s.Socket); err != nil {
		return err
	}
	addr := &net.UnixAddr{Name: s.Socket, Net: "unix"}
	l, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	l.SetUnlinkOnClose(false)
	// The listener FD refers to sockfs. Ownership and permissions must be
	// checked on the filesystem socket entry, which has a different inode.
	owned, err := socketFile(s.Socket)
	if err != nil {
		_ = l.Close()
		return err
	}
	defer func() {
		if serveErr != nil {
			serveErr = errors.Join(serveErr, removeIfSame(s.Socket, owned))
		}
	}()
	// fchmodat2 with AT_SYMLINK_NOFOLLOW changes the filesystem entry and
	// refuses a symlink substituted between validation and chmod. No fallback
	// to path-following chmod is safe here.
	const atFDCWD = -100
	const atSymlinkNoFollow = 0x100
	if err := syscall.Fchmodat(atFDCWD, s.Socket, 0600, atSymlinkNoFollow); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod bound filesystem socket without following symlinks: %w", err)
	}
	st, err := socketFile(s.Socket)
	if err != nil {
		_ = l.Close()
		return err
	}
	if !os.SameFile(owned, st) {
		_ = l.Close()
		return errors.New("socket path was replaced during chmod")
	}
	if st.Mode().Perm() != 0600 {
		_ = l.Close()
		return errors.New("bound socket mode is not 0600")
	}
	s.mu.Lock()
	s.listener = l
	s.active = map[*net.UnixConn]struct{}{}
	s.identity = owned
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { serveErr = errors.Join(serveErr, s.shutdown()) }()
	go func() { <-ctx.Done(); s.shutdown() }()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || s.isClosed() {
				break
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = conn.SetWriteDeadline(time.Now().Add(ioTimeout))
			writeResponse(conn, Response{Version: Version, Error: &APIError{Code: "BUSY", Message: "too many concurrent clients"}})
			conn.Close()
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			<-sem
			conn.Close()
			break
		}
		s.active[conn] = struct{}{}
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() { s.mu.Lock(); delete(s.active, conn); s.mu.Unlock(); conn.Close() }()
			s.handle(ctx, conn)
		}()
	}
	wg.Wait()
	return nil
}
func (s *Server) isClosed() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.closed }
func (s *Server) shutdown() error {
	s.shutdownOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		l := s.listener
		for c := range s.active {
			_ = c.Close()
		}
		st, path := s.identity, s.Socket
		s.mu.Unlock()
		if l != nil {
			s.shutdownErr = l.Close()
		}
		s.shutdownErr = errors.Join(s.shutdownErr, removeIfSame(path, st))
	})
	return s.shutdownErr
}
func socketFile(path string) (os.FileInfo, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode()&os.ModeSymlink != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return nil, errors.New("bound path is not an owned filesystem socket")
	}
	return st, nil
}
func removeIfSame(path string, owned os.FileInfo) error {
	if owned == nil {
		return nil
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket for cleanup: %w", err)
	}
	if !os.SameFile(owned, current) {
		return nil
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove owned socket: %w", err)
	}
	return nil
}
func peerCredentials(c *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	if sockErr != nil {
		return nil, sockErr
	}
	return cred, nil
}

func authorizedPeer(cred *syscall.Ucred) bool {
	return cred != nil && os.Geteuid() != 0 && cred.Uid == uint32(os.Geteuid()) && cred.Gid == uint32(os.Getegid())
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	conn.SetDeadline(time.Now().Add(ioTimeout))
	cred, err := peerCredentials(conn)
	if err != nil || !authorizedPeer(cred) {
		writeResponse(conn, Response{Version: Version, Error: &APIError{Code: "UNAUTHORIZED", Message: "peer UID not authorized"}})
		return
	}
	// Same-UID peers may inspect only. No mutation method is authorized.
	b, err := bufio.NewReader(io.LimitReader(conn, maxRequest+1)).ReadBytes('\n')
	// A LimitReader reports EOF when the frame extends beyond its cap.
	// Classify by the number of bytes read before treating EOF as a missing
	// newline; otherwise an oversized frame is mislabeled INVALID_REQUEST.
	if len(b) > maxRequest {
		writeResponse(conn, Response{Version: Version, Error: &APIError{Code: "TOO_LARGE", Message: "request exceeds 64 KiB"}})
		return
	}
	if err != nil {
		writeResponse(conn, Response{Version: Version, Error: &APIError{Code: "INVALID_REQUEST", Message: "one newline-terminated JSON request required"}})
		return
	}
	var req Request
	if err := decodeStrict(b, &req); err != nil {
		writeResponse(conn, Response{Version: Version, Error: &APIError{Code: "INVALID_REQUEST", Message: "invalid JSON request"}})
		return
	}
	if ctx.Err() != nil {
		return
	}
	writeResponse(conn, s.Service.call(ctx, req))
}
func writeResponse(conn *net.UnixConn, resp Response) {
	b, err := json.Marshal(resp)
	if err != nil || len(b) >= maxResponse {
		b = []byte(`{"version":1,"error":{"code":"INTERNAL","message":"response too large"}}`)
	}
	_, _ = conn.Write(append(b, '\n'))
}

func Call(ctx context.Context, path string, req Request) (Response, error) {
	if err := safeSocketClientPath(path); err != nil {
		return Response{}, err
	}
	d := net.Dialer{Timeout: ioTimeout}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	uc := c.(*net.UnixConn)
	cred, err := peerCredentials(uc)
	if err != nil {
		return Response{}, err
	}
	if !authorizedPeer(cred) {
		return Response{}, errors.New("daemon peer UID/GID mismatch")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	} else {
		_ = c.SetDeadline(time.Now().Add(ioTimeout))
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	b, err := json.Marshal(req)
	if err != nil {
		return Response{}, err
	}
	if len(b)+1 > maxRequest {
		return Response{}, errors.New("request too large")
	}
	if _, err = c.Write(append(b, '\n')); err != nil {
		return Response{}, err
	}
	line, err := bufio.NewReader(io.LimitReader(c, maxResponse+1)).ReadBytes('\n')
	if err != nil {
		return Response{}, err
	}
	if len(line) > maxResponse {
		return Response{}, errors.New("response too large")
	}
	var resp Response
	if err := decodeStrict(line, &resp); err != nil {
		return Response{}, err
	}
	if resp.Version != Version {
		return Response{}, errors.New("response version mismatch")
	}
	return resp, nil
}
func safeSocketClientPath(path string) error {
	if err := socketParent(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0077 != 0 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return errors.New("socket ownership or permissions invalid")
	}
	return nil
}
