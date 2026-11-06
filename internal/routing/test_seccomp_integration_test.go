//go:build integration

package routing

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// writeExecutorSeccompFilter creates a test-only raw cBPF filter for setpriv.
// It denies namespace transitions and creation before the Go worker starts.
// No fallback is allowed on another architecture or if the filter cannot load.
func writeExecutorSeccompFilter(dir string) (string, error) {
	if runtime.GOARCH != "amd64" || runtime.GOOS != "linux" {
		return "", errors.New("executor seccomp filter requires linux/amd64")
	}
	const (
		ldAbs             = 0x20
		jeq               = 0x15
		jset              = 0x45
		and               = 0x54
		ret               = 0x06
		allow             = 0x7fff0000
		deny              = 0x00050000 | uint32(syscall.EPERM)
		clone3Unavailable = 0x00050000 | uint32(syscall.ENOSYS) // glibc retries ordinary thread clone
		kill              = 0x80000000
		archX8664         = 0xc000003e
		clone3            = 435
		setns             = 308
		namespaceFlags    = 0x7e020080 // NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET, NEWTIME
	)
	filter := []syscall.SockFilter{
		{Code: ldAbs, K: 4},
		{Code: jeq, Jt: 1, K: archX8664},
		{Code: ret, K: kill},
		{Code: ldAbs, K: 0},
		{Code: jset, Jf: 1, K: 0x40000000}, // reject x32 ABI syscall-number aliases
		{Code: ret, K: deny},
		{Code: jeq, Jf: 1, K: setns},
		{Code: ret, K: deny},
		{Code: jeq, Jf: 1, K: syscall.SYS_UNSHARE},
		{Code: ret, K: deny},
		{Code: jeq, Jf: 1, K: clone3},
		{Code: ret, K: clone3Unavailable},
		{Code: jeq, Jf: 4, K: syscall.SYS_CLONE},
		{Code: ldAbs, K: 16},
		{Code: and, K: namespaceFlags},
		{Code: jeq, Jt: 1, K: 0},
		{Code: ret, K: deny},
		{Code: ret, K: allow},
	}
	path := filepath.Join(dir, "executor-seccomp.bpf")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := binary.Write(f, binary.LittleEndian, filter); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	return path, nil
}
