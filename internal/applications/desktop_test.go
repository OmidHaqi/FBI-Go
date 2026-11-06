package applications

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func desktop(t *testing.T, root, relative, body string) {
	t.Helper()
	path := filepath.Join(root, "applications", relative)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopPrecedenceAndHiddenOverride(t *testing.T) {
	user, system := t.TempDir(), t.TempDir()
	desktop(t, system, "org/example.desktop", "[Desktop Entry]\nType=Application\nName=System\nExec=/bin/true\n")
	desktop(t, user, "org/example.desktop", "[Desktop Entry]\nType=Application\nName=User\nExec=/bin/true\n")
	desktop(t, system, "masked.desktop", "[Desktop Entry]\nType=Application\nName=Masked\nExec=/bin/true\n")
	desktop(t, user, "masked.desktop", "[Desktop Entry]\nType=Application\nName=Hidden\nHidden=true\n")
	entries, err := Discover([]string{user, system})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != "org-example.desktop" || entries[0].Name != "User" {
		t.Fatalf("unexpected precedence: %+v", entries)
	}
}

func TestDesktopActivationLimitations(t *testing.T) {
	dir := t.TempDir()
	desktop(t, dir, "dbus.desktop", "[Desktop Entry]\nType=Application\nName=Bus\nExec=app %U\nDBusActivatable=true\nTerminal=true\n")
	e, err := Discover([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 1 || e[0].LaunchSupported || len(e[0].Limitations) < 2 {
		t.Fatalf("unsupported activation accepted: %+v", e)
	}
	for _, raw := range []string{`app "unclosed`, `app %U`, `app %Q`, `app 'bad'`, `app %`} {
		if _, err := ParseExec(raw); err == nil {
			t.Fatalf("Exec %q accepted", raw)
		}
	}
	args, err := ParseExec(`app "two words" %%`)
	if err != nil || strings.Join(args, "|") != "app|two words|%" {
		t.Fatalf("Exec parse %q: %v", args, err)
	}
}

func TestXDGDataDirectories(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/tmp/fbi-user-data")
	t.Setenv("XDG_DATA_DIRS", "/tmp/fbi-system-data:relative:/tmp/fbi-system-data")
	dirs := DataDirs()
	if len(dirs) != 2 || dirs[0] != "/tmp/fbi-user-data" || dirs[1] != "/tmp/fbi-system-data" {
		t.Fatalf("XDG order: %v", dirs)
	}
}
