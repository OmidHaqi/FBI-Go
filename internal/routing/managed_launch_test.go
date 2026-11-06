package routing

import (
	"os"
	"strings"
	"testing"
)

func TestManagedOutputCaptureIsPrivateAndBounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FBI_GO_EVIDENCE_DIR", dir)
	t.Setenv("FBI_GO_APP_LOG_LABEL", "capture-test")
	out, errFile, err := managedOutputFiles()
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	defer errFile.Close()
	if out.Name() == errFile.Name() {
		t.Fatal("stdout and stderr share a file")
	}
	writer := &limitedLogWriter{file: out, remaining: 16 << 10}
	payload := strings.Repeat("x", 20<<10)
	if n, err := writer.Write([]byte(payload)); err != nil || n != len(payload) {
		t.Fatalf("bounded write = %d, %v", n, err)
	}
	st, err := out.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 16<<10 || st.Mode().Perm() != 0600 {
		t.Fatalf("unexpected diagnostic size/mode: %d %o", st.Size(), st.Mode().Perm())
	}
}

func TestNetworkNamespaceFDType(t *testing.T) {
	netFD, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer netFD.Close()
	if err := validateNetworkNamespaceFD(netFD); err != nil {
		t.Fatalf("network namespace FD rejected: %v", err)
	}
	userFD, err := os.Open("/proc/self/ns/user")
	if err != nil {
		t.Fatal(err)
	}
	defer userFD.Close()
	if err := validateNetworkNamespaceFD(userFD); err == nil {
		t.Fatal("user namespace FD accepted as network namespace")
	}
	regular, err := os.CreateTemp(t.TempDir(), "regular-")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if err := validateNetworkNamespaceFD(regular); err == nil {
		t.Fatal("regular file accepted as network namespace")
	}
}

func TestManagedTargetIDs(t *testing.T) {
	tests := []struct {
		name, uid, gid   string
		wantUID, wantGID uint32
		fails            bool
	}{
		{"caller identity", "1001", "1002", 1001, 1002, false},
		{"root group uses nonzero namespace GID", "1001", "0", 1001, 1001, false},
		{"no subordinate mapping required", "4242", "4243", 4242, 4243, false},
		{"root target rejected", "0", "1002", 0, 0, true},
		{"missing UID rejected", "", "1002", 0, 0, true},
		{"missing GID rejected", "1001", "", 0, 0, true},
		{"invalid GID rejected", "1001", "invalid", 0, 0, true},
		{"out of range UID rejected", "4294967296", "1002", 0, 0, true},
		{"reserved UID rejected", "4294967295", "1002", 0, 0, true},
		{"reserved GID rejected", "1001", "4294967295", 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uid, gid, err := managedTargetIDs(tt.uid, tt.gid)
			if (err != nil) != tt.fails || uid != tt.wantUID || gid != tt.wantGID {
				t.Fatalf("IDs=(%d,%d) err=%v; want (%d,%d) failure=%t", uid, gid, err, tt.wantUID, tt.wantGID, tt.fails)
			}
		})
	}
}

func TestGuestNSSwitchPolicyFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "nss-")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const policy = "passwd: files\ngroup: files\nhosts: files dns\n"
	if _, err := f.WriteString(policy); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		if err := f.Chown(1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	if os.Geteuid() == 0 || os.Geteuid() == 1000 {
		if err := validateGuestNSSwitch(f); err != nil {
			t.Fatalf("fixed private NSS file rejected: %v", err)
		}
	}
	if err := f.Chmod(0644); err != nil {
		t.Fatal(err)
	}
	if err := validateGuestNSSwitch(f); err == nil {
		t.Fatal("readable private NSS file accepted")
	}
	if err := f.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("hosts: files resolve dns\n"), 0); err != nil {
		t.Fatal(err)
	}
	if err := validateGuestNSSwitch(f); err == nil {
		t.Fatal("host resolver path accepted")
	}
}
