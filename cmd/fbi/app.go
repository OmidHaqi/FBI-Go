package main

import (
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/applications"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"github.com/omidhaqi/FBI-Go/internal/routing"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func appCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fbi app list|policy|run")
	}
	switch args[0] {
	case "list":
		if len(args) > 2 || len(args) == 2 && args[1] != "--json" {
			return errors.New("usage: fbi app list [--json]")
		}
		entries, err := applications.Discover(applications.DataDirs())
		if err != nil {
			return err
		}
		return emit(entries, len(args) == 2)
	case "policy":
		return appPolicyCommand(args[1:])
	case "run":
		return appRunCommand(args[1:])
	default:
		return fmt.Errorf("unknown app command %q", args[0])
	}
}

func policyFilePath() (string, error) { return policy.DefaultPath() }

func appPolicyCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fbi app policy list|show|set|remove")
	}
	path, err := policyFilePath()
	if err != nil {
		return err
	}
	switch args[0] {
	case "list", "show":
		jsonOutput := len(args) > 1 && args[len(args)-1] == "--json"
		if jsonOutput {
			args = args[:len(args)-1]
		}
		if args[0] == "list" && len(args) != 1 || args[0] == "show" && len(args) != 2 {
			return errors.New("usage: fbi app policy list [--json] | show <app-id> [--json]")
		}
		file, err := policy.Read(path)
		if err != nil {
			return err
		}
		entries, discoveryErr := applications.Discover(applications.DataDirs())
		installed := map[string]applications.Entry{}
		if discoveryErr == nil {
			for _, entry := range entries {
				installed[entry.ID] = entry
			}
		}
		snapshot, scanErr := network.Scan()
		if scanErr != nil {
			snapshot = network.Snapshot{}
		}
		var resolved []policy.Resolution
		for _, p := range file.Policies {
			r := policy.Resolve(p, snapshot)
			if scanErr != nil {
				r.Status = "UNAVAILABLE"
				r.Reason = "network inventory: " + scanErr.Error()
			}
			if discoveryErr != nil {
				r.Status = "UNAVAILABLE"
				r.Reason = "desktop discovery: " + discoveryErr.Error()
			} else if entry, ok := installed[p.ID]; !ok {
				r.Status = "UNAVAILABLE"
				r.Reason = "desktop entry is not installed"
			} else if !entry.LaunchSupported {
				r.Status = "UNSUPPORTED"
				r.Reason = strings.Join(entry.Limitations, "; ")
			}
			resolved = append(resolved, r)
		}
		if args[0] == "show" {
			for _, r := range resolved {
				if r.Policy.ID == args[1] {
					return emit(r, jsonOutput)
				}
			}
			return fmt.Errorf("policy %q not found", args[1])
		}
		return emit(resolved, jsonOutput)
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: fbi app policy remove <app-id>")
		}
		return policy.Update(path, func(f *policy.File) error {
			for i, p := range f.Policies {
				if p.ID == args[1] {
					f.Policies = append(f.Policies[:i], f.Policies[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("policy %q not found", args[1])
		})
	case "set":
		if len(args) < 3 || !policy.ValidDesktopID(args[1]) {
			return errors.New("usage: fbi app policy set <desktop-id> --auto | --wan <stable-id> --mode strict|failover [--fallback <stable-id>]")
		}
		p := policy.ApplicationPolicy{ID: args[1], DesktopEntry: args[1], Enabled: true}
		seen := map[string]bool{}
		for i := 2; i < len(args); i++ {
			flag := args[i]
			if seen[flag] {
				return fmt.Errorf("duplicate option %s", flag)
			}
			seen[flag] = true
			switch flag {
			case "--auto":
				p.Mode = policy.Auto
			case "--wan", "--mode", "--fallback":
				if i+1 >= len(args) {
					return fmt.Errorf("%s requires a value", flag)
				}
				i++
				value := args[i]
				switch flag {
				case "--wan":
					p.PreferredWAN = value
				case "--fallback":
					p.FallbackWAN = value
				case "--mode":
					switch strings.ToLower(value) {
					case "strict":
						p.FailureBehavior = policy.Strict
					case "failover":
						p.FailureBehavior = policy.Failover
					default:
						return fmt.Errorf("unknown mode %q", value)
					}
				}
			default:
				return fmt.Errorf("unknown option %q", flag)
			}
		}
		if p.Mode == "" {
			p.Mode = policy.PinnedWAN
		}
		if p.Mode == policy.Auto && (seen["--wan"] || seen["--mode"] || seen["--fallback"]) {
			return errors.New("--auto cannot be combined with WAN options")
		}
		if err := p.Validate(); err != nil {
			return err
		}
		if p.Mode == policy.PinnedWAN {
			for _, id := range []string{p.PreferredWAN, p.FallbackWAN} {
				if id != "" && !(os.Getenv("FBI_GO_ROOTLESS_TEST") == "1" && (id == "wan-a" || id == "wan-b")) {
					if !strings.HasPrefix(id, "mac:") {
						return fmt.Errorf("WAN %q is not a stable supported ID (expected mac:...)", id)
					}
					if _, err := net.ParseMAC(strings.TrimPrefix(id, "mac:")); err != nil {
						return fmt.Errorf("invalid MAC WAN ID %q: %w", id, err)
					}
				}
			}
		}
		entries, err := applications.Discover(applications.DataDirs())
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.ID == p.ID {
				p.DisplayName = e.Name
				p.Executable = e.Exec
				break
			}
		}
		return policy.Update(path, func(f *policy.File) error {
			for i := range f.Policies {
				if f.Policies[i].ID == p.ID {
					f.Policies[i] = p
					return nil
				}
			}
			f.Policies = append(f.Policies, p)
			return nil
		})
	default:
		return fmt.Errorf("unknown policy command %q", args[0])
	}
}

func appRunCommand(args []string) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator != 2 || len(args) < 4 || (args[0] != "--wan" && args[0] != "--app") {
		return errors.New("usage: fbi app run --wan <wan-a|wan-b> | --app <desktop-id> -- <ABSOLUTE_COMMAND> [ARGS...]")
	}
	fdNumber, err := strconv.Atoi(os.Getenv("FBI_GO_APP_NETNS_FD"))
	if err != nil || fdNumber != 3 {
		return errors.New("managed routing requires an inherited test-owned namespace FD; host activation is unavailable")
	}
	fd := os.NewFile(uintptr(fdNumber), "owned-app-netns")
	if fd == nil {
		return errors.New("managed namespace FD unavailable")
	}
	defer fd.Close()
	var resolverFD *os.File
	if raw := os.Getenv("FBI_GO_APP_RESOLVER_FD"); raw != "" {
		if raw != "4" {
			return errors.New("managed resolver requires inherited FD 4")
		}
		resolverFD = os.NewFile(4, "owned-app-resolver")
		if resolverFD == nil {
			return errors.New("managed resolver FD unavailable")
		}
		defer resolverFD.Close()
	}
	wan := args[1]
	if args[0] == "--app" {
		path, err := policyFilePath()
		if err != nil {
			return err
		}
		file, err := policy.Read(path)
		if err != nil {
			return err
		}
		var selected *policy.ApplicationPolicy
		for i := range file.Policies {
			if file.Policies[i].ID == args[1] {
				selected = &file.Policies[i]
				break
			}
		}
		if selected == nil {
			return fmt.Errorf("no managed policy for %q; default routing is not applied by this lab launcher", args[1])
		}
		if !selected.Enabled {
			return fmt.Errorf("policy %q is disabled", args[1])
		}
		if selected.Mode != policy.PinnedWAN {
			return fmt.Errorf("policy %q mode %s is not supported by the pinned lab launcher", args[1], selected.Mode)
		}
		if selected.FailureBehavior != policy.Strict {
			return fmt.Errorf("policy %q failure behavior %s is not enforced by the pinned lab launcher", args[1], selected.FailureBehavior)
		}
		wan = selected.PreferredWAN
		if wan != os.Getenv("FBI_GO_APP_WAN") {
			return fmt.Errorf("saved policy %q selects %s but owned lab has applied %s; launch refused", args[1], wan, os.Getenv("FBI_GO_APP_WAN"))
		}
	}
	if wan != os.Getenv("FBI_GO_APP_WAN") {
		return errors.New("selected WAN differs from the lab's applied policy")
	}
	if !filepath.IsAbs(args[3]) {
		return errors.New("managed executable path must be absolute")
	}
	return routing.RunManagedWithSignals(routing.ManagedLaunch{NamespaceFD: fd, ResolverFD: resolverFD, NamespaceName: os.Getenv("FBI_GO_APP_NETNS_NAME"), WAN: wan, Command: args[3:]})
}
