// Package applications discovers desktop entries without executing them.
package applications

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type Entry struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	GenericName      string   `json:"generic_name,omitempty"`
	Icon             string   `json:"icon,omitempty"`
	Exec             string   `json:"exec,omitempty"`
	TryExec          string   `json:"try_exec,omitempty"`
	Terminal         bool     `json:"terminal"`
	DBusActivatable  bool     `json:"dbus_activatable"`
	NoDisplay        bool     `json:"no_display"`
	Hidden           bool     `json:"hidden"`
	WorkingDirectory string   `json:"working_directory,omitempty"`
	Source           string   `json:"source"`
	LaunchSupported  bool     `json:"launch_supported"`
	Limitations      []string `json:"limitations,omitempty"`
}

// DataDirs follows XDG precedence. Invalid relative locations are ignored.
func DataDirs() []string {
	home := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(home) {
		if h, err := os.UserHomeDir(); err == nil {
			home = filepath.Join(h, ".local/share")
		}
	}
	dirs := []string{home}
	other := os.Getenv("XDG_DATA_DIRS")
	if other == "" {
		other = "/usr/local/share:/usr/share"
	}
	for _, dir := range strings.Split(other, ":") {
		dirs = append(dirs, dir)
	}
	var valid []string
	seen := map[string]bool{}
	for _, dir := range dirs {
		if filepath.IsAbs(dir) && !seen[dir] {
			valid = append(valid, dir)
			seen[dir] = true
		}
	}
	return valid
}

// Discover keeps the first desktop ID, including Hidden tombstones that mask
// lower-priority system entries. It does not follow symlinked entry files.
func Discover(dirs []string) ([]Entry, error) {
	seen := map[string]bool{}
	var entries []Entry
	for _, dataDir := range dirs {
		if !filepath.IsAbs(dataDir) {
			continue
		}
		root := filepath.Join(dataDir, "applications")
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		var paths []string
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".desktop") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(paths)
		for _, path := range paths {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil, err
			}
			id := strings.ReplaceAll(rel, string(filepath.Separator), "-")
			if seen[id] {
				continue
			}
			entry, err := Parse(path, id)
			if err != nil {
				// A broken or non-application entry does not prevent discovery of
				// other installed applications.
				continue
			}
			seen[id] = true
			if !entry.Hidden {
				entries = append(entries, entry)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries, nil
}

func Parse(path, id string) (Entry, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return Entry{}, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return Entry{}, fmt.Errorf("entry is not a regular file below 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return Entry{}, err
	}
	defer f.Close()
	e := Entry{ID: id, Source: path}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	inEntry := false
	values := map[string]string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[Desktop Entry]" {
			inEntry = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inEntry = false
			continue
		}
		if !inEntry || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && !strings.Contains(key, "[") {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return Entry{}, err
	}
	if values["Type"] != "Application" || values["Name"] == "" {
		return Entry{}, fmt.Errorf("not a named Application entry")
	}
	e.Name, e.GenericName, e.Icon = values["Name"], values["GenericName"], values["Icon"]
	e.Exec, e.TryExec, e.WorkingDirectory = values["Exec"], values["TryExec"], values["Path"]
	e.Terminal = values["Terminal"] == "true"
	e.DBusActivatable = values["DBusActivatable"] == "true"
	e.NoDisplay, e.Hidden = values["NoDisplay"] == "true", values["Hidden"] == "true"
	if e.DBusActivatable {
		e.Limitations = append(e.Limitations, "D-Bus activation is not managed")
	}
	if e.Terminal {
		e.Limitations = append(e.Limitations, "terminal activation requires a desktop launcher")
	}
	if e.TryExec != "" {
		if _, err := exec.LookPath(e.TryExec); err != nil {
			e.Limitations = append(e.Limitations, "TryExec is unavailable")
		}
	}
	if e.Exec == "" {
		e.Limitations = append(e.Limitations, "Exec is missing")
	} else if argv, err := ParseExec(e.Exec); err != nil {
		e.Limitations = append(e.Limitations, "unsupported Exec: "+err.Error())
	} else if len(argv) > 1 && (filepath.Base(argv[0]) == "sh" || filepath.Base(argv[0]) == "bash" || filepath.Base(argv[0]) == "zsh") && argv[1] == "-c" {
		e.Limitations = append(e.Limitations, "shell activation is not managed")
	}
	if strings.Contains(strings.ToLower(e.Exec), "flatpak ") {
		e.Limitations = append(e.Limitations, "Flatpak sandbox integration is unverified")
	}
	e.LaunchSupported = len(e.Limitations) == 0
	return e, nil
}

// ParseExec validates Desktop Entry quoting and field codes. Its result is
// metadata only; M3.2 never executes it or applies shell expansion.
func ParseExec(raw string) ([]string, error) {
	var args []string
	var token strings.Builder
	quoted, escaped, active := false, false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if escaped {
			token.WriteByte(c)
			escaped = false
			active = true
			continue
		}
		if c == '\\' && quoted {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			active = true
			continue
		}
		if c == '\'' {
			return nil, fmt.Errorf("single quote is not Desktop Entry quoting")
		}
		if c == '%' {
			if i+1 >= len(raw) {
				return nil, fmt.Errorf("trailing field code")
			}
			i++
			if raw[i] == '%' {
				token.WriteByte('%')
				active = true
				continue
			}
			return nil, fmt.Errorf("field code %%%c needs desktop activation", raw[i])
		}
		if (c == ' ' || c == '\t') && !quoted {
			if active {
				args = append(args, token.String())
				token.Reset()
				active = false
			}
			continue
		}
		if c == '\n' || c == '\r' || c == 0 {
			return nil, fmt.Errorf("control character in Exec")
		}
		token.WriteByte(c)
		active = true
	}
	if quoted || escaped {
		return nil, fmt.Errorf("unterminated Exec quoting")
	}
	if active {
		args = append(args, token.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty Exec")
	}
	return args, nil
}
