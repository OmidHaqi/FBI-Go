package policy

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
)

const SchemaVersion = 1

type File struct {
	Version  int                 `json:"version"`
	Policies []ApplicationPolicy `json:"policies"`
}

type Resolution struct {
	Policy             ApplicationPolicy `json:"policy"`
	Status             string            `json:"status"`
	Reason             string            `json:"reason,omitempty"`
	PreferredInterface string            `json:"preferred_interface,omitempty"`
	FallbackInterface  string            `json:"fallback_interface,omitempty"`
}

func DefaultPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "fbi-go", "policies.toml"), nil
}

func validID(id string) bool {
	if !utf8.ValidString(id) || !strings.HasSuffix(id, ".desktop") || strings.Contains(id, "/") || strings.Contains(id, "\\") || strings.Contains(id, "..") {
		return false
	}
	for _, c := range id {
		if unicode.IsControl(c) || unicode.IsSpace(c) {
			return false
		}
	}
	return true
}

func ValidDesktopID(id string) bool { return validID(id) }

func ValidateFile(f File) error {
	if f.Version != SchemaVersion {
		return fmt.Errorf("unsupported policy schema version %d", f.Version)
	}
	seen := map[string]bool{}
	for _, p := range f.Policies {
		if !validID(p.ID) {
			return fmt.Errorf("invalid desktop entry ID %q", p.ID)
		}
		if seen[p.ID] {
			return fmt.Errorf("duplicate policy %q", p.ID)
		}
		seen[p.ID] = true
		if err := p.Validate(); err != nil {
			return fmt.Errorf("policy %s: %w", p.ID, err)
		}
		if p.Mode != PinnedWAN && p.FailureBehavior != "" {
			return fmt.Errorf("policy %s: failure behavior requires PINNED_WAN", p.ID)
		}
	}
	return nil
}

// Read accepts only the documented TOML subset and fails closed on unknown keys.
func Read(path string) (File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return File{Version: SchemaVersion}, nil
	}
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return File{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return File{}, fmt.Errorf("policy file must be regular and below 1 MiB")
	}
	if st.Mode().Perm()&0077 != 0 {
		return File{}, fmt.Errorf("policy file permissions are not private")
	}
	if st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return File{}, fmt.Errorf("policy file has another owner")
	}
	result := File{}
	var current *ApplicationPolicy
	keys := map[string]bool{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[policies]]" {
			result.Policies = append(result.Policies, ApplicationPolicy{})
			current = &result.Policies[len(result.Policies)-1]
			keys = map[string]bool{}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return File{}, fmt.Errorf("line %d: invalid TOML assignment", lineNo)
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if keys[key] {
			return File{}, fmt.Errorf("line %d: duplicate key %q", lineNo, key)
		}
		keys[key] = true
		if current == nil {
			if key != "version" {
				return File{}, fmt.Errorf("line %d: unsupported top-level key %q", lineNo, key)
			}
			if result.Version != 0 {
				return File{}, fmt.Errorf("line %d: duplicate version", lineNo)
			}
			result.Version, err = strconv.Atoi(value)
		} else {
			switch key {
			case "id":
				err = parseTOMLString(value, &current.ID)
			case "display_name":
				err = parseTOMLString(value, &current.DisplayName)
			case "desktop_entry":
				err = parseTOMLString(value, &current.DesktopEntry)
			case "executable":
				err = parseTOMLString(value, &current.Executable)
			case "mode":
				var v string
				err = parseTOMLString(value, &v)
				current.Mode = Mode(v)
			case "preferred_wan":
				err = parseTOMLString(value, &current.PreferredWAN)
			case "fallback_wan":
				err = parseTOMLString(value, &current.FallbackWAN)
			case "failure_behavior":
				var v string
				err = parseTOMLString(value, &v)
				current.FailureBehavior = FailureBehavior(v)
			case "enabled":
				current.Enabled, err = strconv.ParseBool(value)
			default:
				return File{}, fmt.Errorf("line %d: unsupported key %q", lineNo, key)
			}
		}
		if err != nil {
			return File{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return File{}, err
	}
	if err := ValidateFile(result); err != nil {
		return File{}, err
	}
	return result, nil
}

func parseTOMLString(raw string, dst *string) error {
	if !strings.HasPrefix(raw, "\"") {
		return fmt.Errorf("expected quoted TOML string")
	}
	v, err := strconv.Unquote(raw)
	if err != nil {
		return err
	}
	*dst = v
	return nil
}

func render(f File) []byte {
	var b strings.Builder
	b.WriteString("version = 1\n")
	policies := append([]ApplicationPolicy(nil), f.Policies...)
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	for _, p := range policies {
		b.WriteString("\n[[policies]]\n")
		for _, kv := range [][2]string{{"id", p.ID}, {"display_name", p.DisplayName}, {"desktop_entry", p.DesktopEntry}, {"executable", p.Executable}, {"mode", string(p.Mode)}, {"preferred_wan", p.PreferredWAN}, {"fallback_wan", p.FallbackWAN}, {"failure_behavior", string(p.FailureBehavior)}} {
			if kv[1] != "" {
				fmt.Fprintf(&b, "%s = %s\n", kv[0], strconv.Quote(kv[1]))
			}
		}
		fmt.Fprintf(&b, "enabled = %t\n", p.Enabled)
	}
	return []byte(b.String())
}

// Update serializes writers with a private sidecar lock and atomically
// replaces only the owned policy file. The callback runs with the lock held.
func Update(path string, change func(*File) error) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != "policies.toml" {
		return fmt.Errorf("invalid policy path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("policy directory must be private and user-owned")
	}
	lock, err := os.OpenFile(filepath.Join(dir, "policies.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil {
		return err
	}
	if !lockInfo.Mode().IsRegular() || lockInfo.Mode().Perm() != 0600 || lockInfo.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("policy lock is not a private user-owned file")
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	f, err := Read(path)
	if err != nil {
		return err
	}
	if err := change(&f); err != nil {
		return err
	}
	if err := ValidateFile(f); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".policies-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(render(f)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Resolve is read-only identity resolution. It never represents enforcement.
func Resolve(p ApplicationPolicy, snapshot network.Snapshot) Resolution {
	r := Resolution{Policy: p, Status: "CONFIGURED"}
	if err := p.Validate(); err != nil {
		r.Status = "UNSUPPORTED"
		r.Reason = err.Error()
		return r
	}
	if !p.Enabled {
		r.Status = "UNAVAILABLE"
		r.Reason = "policy disabled"
		return r
	}
	if p.Mode == Auto {
		r.Reason = "global automatic policy is not resolved by the saved application record"
		return r
	}
	if p.Mode == SystemDefault {
		r.Status = "RESOLVED"
		return r
	}
	match := func(id string) (string, string) {
		var matches []string
		for _, d := range snapshot.Devices {
			if d.ID == id && d.Candidate {
				matches = append(matches, d.Name)
			}
		}
		if len(matches) == 0 {
			return "", "WAN identifier is unavailable"
		}
		if len(matches) > 1 {
			return "", "WAN identifier is ambiguous"
		}
		return matches[0], ""
	}
	r.PreferredInterface, r.Reason = match(p.PreferredWAN)
	if r.Reason != "" {
		r.Status = "UNAVAILABLE"
		return r
	}
	if p.FailureBehavior == Failover {
		r.FallbackInterface, r.Reason = match(p.FallbackWAN)
		if r.Reason != "" {
			r.Status = "UNAVAILABLE"
			return r
		}
	}
	if r.FallbackInterface != "" && r.FallbackInterface == r.PreferredInterface {
		r.Status = "UNAVAILABLE"
		r.Reason = "WAN IDs resolve to the same interface"
		return r
	}
	r.Status = "RESOLVED"
	return r
}
