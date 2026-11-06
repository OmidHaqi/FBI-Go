package policy

import (
	"github.com/omidhaqi/FBI-Go/internal/network"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func samplePolicy(id string) ApplicationPolicy {
	return ApplicationPolicy{ID: id, DesktopEntry: id, Mode: PinnedWAN, PreferredWAN: "mac:aa:bb:cc:dd:ee:01", FailureBehavior: Strict, Enabled: true}
}

func TestStoreRoundTripAndSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fbi-go", "policies.toml")
	if err := Update(path, func(f *File) error { f.Policies = append(f.Policies, samplePolicy("sample.desktop")); return nil }); err != nil {
		t.Fatal(err)
	}
	f, err := Read(path)
	if err != nil || len(f.Policies) != 1 || f.Policies[0].ID != "sample.desktop" {
		t.Fatalf("roundtrip: %+v %v", f, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("file mode: %v %v", st, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Update(path, func(f *File) error {
		f.Policies = append(f.Policies, samplePolicy("other.desktop"))
		return os.ErrInvalid
	}); err == nil {
		t.Fatal("failing update accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed update changed policy file")
	}
	if err := os.WriteFile(path, []byte("version = 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil || !strings.Contains(err.Error(), "unsupported policy schema") {
		t.Fatalf("schema accepted: %v", err)
	}
}

func TestStoreRejectsInvalidAndSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policies.toml")
	for _, content := range []string{"version = 1\n[[policies]]\nid = \"x.desktop\"\nmode = \"PINNED_WAN\"\npreferred_wan = \"a\"\nfailure_behavior = \"FAILOVER\"\nenabled = true\n", "version = 1\n[[policies]]\nid = \"x.desktop\"\nmode = \"BAD\"\n", "version = 1\nunknown = 2\n"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); err == nil {
			t.Fatalf("invalid document accepted: %q", content)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("symlink read accepted")
	}
	if err := Update(path, func(*File) error { return nil }); err == nil {
		t.Fatal("symlink update accepted")
	}
	b, _ := os.ReadFile(other)
	if string(b) != "unchanged" {
		t.Fatal("unrelated file modified")
	}
}

func TestConcurrentPolicyUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fbi-go", "policies.toml")
	var wg sync.WaitGroup
	errors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- Update(path, func(f *File) error {
				f.Policies = append(f.Policies, samplePolicy(string(rune('a'+i))+".desktop"))
				return nil
			})
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	f, err := Read(path)
	if err != nil || len(f.Policies) != 16 {
		t.Fatalf("concurrent updates lost: %d %v", len(f.Policies), err)
	}
}

func TestPolicyResolutionIdentity(t *testing.T) {
	p := samplePolicy("app.desktop")
	s := network.Snapshot{Devices: []network.Device{{ID: p.PreferredWAN, Name: "wan0", Candidate: true}}}
	if r := Resolve(p, s); r.Status != "RESOLVED" || r.PreferredInterface != "wan0" {
		t.Fatalf("resolved: %+v", r)
	}
	if r := Resolve(p, network.Snapshot{}); r.Status != "UNAVAILABLE" || r.PreferredInterface != "" {
		t.Fatalf("strict missing WAN: %+v", r)
	}
	s.Devices = append(s.Devices, network.Device{ID: p.PreferredWAN, Name: "wan1", Candidate: true})
	if r := Resolve(p, s); r.Status != "UNAVAILABLE" || !strings.Contains(r.Reason, "ambiguous") {
		t.Fatalf("ambiguous WAN: %+v", r)
	}
	p.FailureBehavior = Failover
	p.FallbackWAN = "mac:aa:bb:cc:dd:ee:02"
	s.Devices = s.Devices[:1]
	if r := Resolve(p, s); r.Status != "UNAVAILABLE" {
		t.Fatalf("missing fallback: %+v", r)
	}
}
