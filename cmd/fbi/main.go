package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/omidhaqi/FBI-Go/internal/applications"
	"github.com/omidhaqi/FBI-Go/internal/diagnostics"
	"github.com/omidhaqi/FBI-Go/internal/network"
	"github.com/omidhaqi/FBI-Go/internal/policy"
	"github.com/omidhaqi/FBI-Go/internal/routing"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const version = "2.0.0-lab"

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: fbi version | multiwan scan|status|doctor|plan [--json] | multiwan plan-m2 <inventory.json> [--json] | app list|policy|run | daemon serve|ping|version|capabilities|status|diagnostics|plan | <IP_ADDRESS> <COMMAND> [ARGS...]")
}
func emit(v any, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(v)
	}
	switch x := v.(type) {
	case network.Snapshot:
		for _, d := range x.Devices {
			fmt.Printf("%s  %s  %s  candidate=%t  addresses=%s  gateways=%s\n", d.Name, d.Kind, d.State, d.Candidate, strings.Join(d.Addresses, ","), strings.Join(d.Gateways, ","))
		}
		for _, w := range x.Warnings {
			fmt.Println("warning:", w)
		}
	case network.Status:
		fmt.Println("Multi-WAN enforcement: inactive; live health monitoring: inactive")
		return emit(x.Snapshot, false)
	case routing.Plan:
		fmt.Println("Read-only plan; no network changes")
		for _, c := range x.Candidates {
			fmt.Println("candidate:", c)
		}
		for _, a := range x.Actions {
			fmt.Println(a)
		}
		for _, w := range x.Warnings {
			fmt.Println("warning:", w)
		}
	case routing.M2Plan:
		fmt.Printf("M2 namespace plan: safe_to_apply=%t\n", x.SafeToApply)
		for _, w := range x.WANs {
			fmt.Printf("%s table=%d priority=%d mark=%#x source=%s gateway=%s\n", w.Interface, w.Table, w.Priority, w.Mark, w.SourceIP, w.Gateway)
		}
		for _, r := range x.Reasons {
			fmt.Println("rejected:", r)
		}
		for _, w := range x.Warnings {
			fmt.Println("warning:", w)
		}
	case diagnostics.Report:
		fmt.Println("Read-only host compatibility report")
		for _, f := range x.Findings {
			fmt.Printf("%s %s: %s\n", f.Status, f.Code, f.Detail)
		}
	case []applications.Entry:
		for _, e := range x {
			fmt.Printf("%s  %s  managed_exec_supported=%t", e.ID, e.Name, e.LaunchSupported)
			if len(e.Limitations) > 0 {
				fmt.Printf("  limitations=%s", strings.Join(e.Limitations, "; "))
			}
			fmt.Println()
		}
	case []policy.Resolution:
		for _, r := range x {
			fmt.Printf("%s  %s  %s", r.Policy.ID, r.Policy.Mode, r.Status)
			if r.Reason != "" {
				fmt.Printf("  %s", r.Reason)
			}
			fmt.Println()
		}
	case policy.Resolution:
		fmt.Printf("%s  %s  %s", x.Policy.ID, x.Policy.Mode, x.Status)
		if x.Reason != "" {
			fmt.Printf("  %s", x.Reason)
		}
		fmt.Println()
	default:
		fmt.Println(v)
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("missing command")
	}
	if args[0] == "version" {
		return emit(version, len(args) > 1 && args[1] == "--json")
	}
	if args[0] == "-h" || args[0] == "--help" {
		usage()
		return nil
	}
	if args[0] == "app" {
		return appCommand(args[1:])
	}
	if args[0] == "daemon" {
		return daemonCommand(args[1:])
	}
	if args[0] == "multiwan" {
		if len(args) >= 3 && args[1] == "plan-m2" {
			if len(args) > 4 || len(args) == 4 && args[3] != "--json" {
				return fmt.Errorf("usage: fbi multiwan plan-m2 <inventory.json> [--json]")
			}
			b, err := os.ReadFile(args[2])
			if err != nil {
				return err
			}
			var inv routing.Inventory
			if err = json.Unmarshal(b, &inv); err != nil {
				return err
			}
			return emit(routing.PlanM2(inv), len(args) == 4)
		}
		if len(args) < 2 || len(args) > 3 {
			usage()
			return fmt.Errorf("invalid multiwan command")
		}
		jsonOutput := len(args) == 3 && args[2] == "--json"
		if len(args) == 3 && !jsonOutput {
			return fmt.Errorf("unknown option %s", args[2])
		}
		if args[1] != "scan" && args[1] != "status" && args[1] != "plan" && args[1] != "doctor" {
			return fmt.Errorf("unknown multiwan command %s", args[1])
		}
		if args[1] == "doctor" {
			return emit(diagnostics.CollectHost(), jsonOutput)
		}
		s, err := network.Scan()
		if err != nil {
			return err
		}
		if args[1] == "plan" {
			return emit(routing.Generate(s), jsonOutput)
		}
		if args[1] == "status" {
			return emit(network.Status{Snapshot: s}, jsonOutput)
		}
		return emit(s, jsonOutput)
	}
	if len(args) < 2 {
		usage()
		return fmt.Errorf("legacy usage requires IP and command")
	}
	if net.ParseIP(args[0]) == nil {
		return fmt.Errorf("invalid IP address %q", args[0])
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	binder := filepath.Join(filepath.Dir(exe), "binder.so")
	if _, err := os.Stat(binder); err != nil {
		return fmt.Errorf("legacy binder unavailable at %s: %w", binder, err)
	}
	cmd := exec.Command(args[1], args[2:]...)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+binder, "FORCE_BIND_IP="+args[0])
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fbi:", err)
		os.Exit(processExitCode(err))
	}
}

func processExitCode(err error) int {
	var e *exec.ExitError
	if errors.As(err, &e) {
		return e.ExitCode()
	}
	return 1
}
