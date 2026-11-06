package main

import (
	"encoding/json"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/applications"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppListJSONUsesSyntheticXDG(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	if err := os.MkdirAll(filepath.Join(data, "applications"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "applications", "sample.desktop"), []byte("[Desktop Entry]\nType=Application\nName=Sample\nExec=/bin/true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("XDG_DATA_DIRS", filepath.Join(base, "empty"))
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	t.Cleanup(func() { os.Stdout = old })
	if err := run([]string{"app", "list", "--json"}); err != nil {
		t.Fatal(err)
	}
	os.Stdout = old
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var entries []applications.Entry
	if err := json.NewDecoder(reader).Decode(&entries); err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if len(entries) != 1 || entries[0].ID != "sample.desktop" || entries[0].Name != "Sample" {
		t.Fatalf("CLI discovery: %+v", entries)
	}
}

func TestPolicyCLIStoresAndRemoves(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("XDG_DATA_HOME", filepath.Join(base, "data"))
	t.Setenv("XDG_DATA_DIRS", filepath.Join(base, "empty"))
	if err := run([]string{"app", "policy", "set", "sample.desktop", "--auto"}); err != nil {
		t.Fatal(err)
	}
	path, err := policy.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	f, err := policy.Read(path)
	if err != nil || len(f.Policies) != 1 || f.Policies[0].Mode != policy.Auto {
		t.Fatalf("set: %+v %v", f, err)
	}
	if err := run([]string{"app", "policy", "set", "sample.desktop", "--wan", "mac:aa:bb:cc:dd:ee:ff", "--mode", "strict"}); err != nil {
		t.Fatal(err)
	}
	f, err = policy.Read(path)
	if err != nil || len(f.Policies) != 1 || f.Policies[0].FailureBehavior != policy.Strict {
		t.Fatalf("replace: %+v %v", f, err)
	}
	if err := run([]string{"app", "policy", "remove", "sample.desktop"}); err != nil {
		t.Fatal(err)
	}
	f, err = policy.Read(path)
	if err != nil || len(f.Policies) != 0 {
		t.Fatalf("remove: %+v %v", f, err)
	}
	if err := run([]string{"app", "run", "--app", "sample.desktop", "--", "/bin/true"}); err == nil || !strings.Contains(err.Error(), "test-owned namespace FD") {
		t.Fatalf("host launcher did not fail closed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyCLIRejectsInvalidOptions(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	for _, args := range [][]string{
		{"app", "policy", "set", "sample.desktop", "--wan", "eth0", "--mode", "strict"},
		{"app", "policy", "set", "sample.desktop", "--wan", "mac:a", "--mode", "failover"},
		{"app", "policy", "set", "sample.desktop", "--auto", "--wan", "mac:a"},
		{"app", "policy", "set", "../bad.desktop", "--auto"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestWrappedManagedExitCode(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 42").Run()
	if err == nil {
		t.Fatal("expected nonzero command")
	}
	if got := processExitCode(fmt.Errorf("managed command: %w", err)); got != 42 {
		t.Fatalf("wrapped exit code = %d, want 42", got)
	}
	if got := processExitCode(fmt.Errorf("validation failure")); got != 1 {
		t.Fatalf("validation exit code = %d, want 1", got)
	}
}

func TestManagedRunRequiresOwnedLabContext(t *testing.T) {
	t.Setenv("FBI_GO_APP_NETNS_FD", "")
	t.Setenv("FBI_GO_APP_NETNS_NAME", "")
	t.Setenv("FBI_GO_APP_WAN", "")
	for _, args := range [][]string{
		{"app", "run", "--wan", "wan-a", "--", "/bin/true"},
		{"app", "run", "--wan", "wan-b", "--", "/bin/true"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "test-owned namespace FD") {
			t.Fatalf("%v: expected fail-closed lab context error, got %v", args, err)
		}
	}
}

func TestManagedRunRequiresSeparatorAndCommand(t *testing.T) {
	for _, args := range [][]string{
		{"app", "run", "--wan", "wan-a", "/bin/true"},
		{"app", "run", "--wan", "wan-a", "--"},
	} {
		if err := run(args); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Fatalf("%v: expected usage error, got %v", args, err)
		}
	}
}
