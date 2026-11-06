package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/omidhaqi/FBI-Go/internal/daemon"
	"github.com/omidhaqi/FBI-Go/internal/policy"
)

func daemonCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: fbi daemon serve|ping|version|capabilities|status|diagnostics|plan --socket <private-path>")
	}
	method := args[0]
	fs := flag.NewFlagSet("daemon "+method, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", "private Unix socket path")
	jsonOutput := fs.Bool("json", false, "print JSON")
	dryRun := fs.Bool("dry-run", false, "serve in plan-only mode")
	mode := fs.String("mode", "AUTO", "requested policy mode for plan")
	wan := fs.String("wan", "", "stable WAN ID for pinned plan")
	fallback := fs.String("fallback", "", "explicit fallback WAN ID")
	failure := fs.String("failure", "STRICT", "STRICT or FAILOVER")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if len(fs.Args()) != 0 || *socket == "" {
		return errors.New("--socket <private-path> is required; positional arguments are unsupported")
	}
	if method == "serve" {
		if !*dryRun {
			return errors.New("daemon serve requires --dry-run")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return (&daemon.Server{Socket: *socket, Service: daemon.Service{Backend: daemon.ReadOnlyBackend{}}}).Serve(ctx)
	}
	if *dryRun {
		return errors.New("--dry-run is valid only for serve")
	}
	methods := map[string]string{"ping": "daemon.ping", "version": "daemon.version", "capabilities": "daemon.capabilities", "status": "daemon.status", "diagnostics": "daemon.diagnostics", "plan": "daemon.plan"}
	apiMethod, ok := methods[method]
	if !ok {
		return fmt.Errorf("unsupported daemon command %q", method)
	}
	req := daemon.Request{Version: daemon.Version, Method: apiMethod}
	if method == "plan" {
		p := policy.ApplicationPolicy{ID: "daemon-preview", Enabled: true, Mode: policy.Mode(*mode)}
		if p.Mode == policy.PinnedWAN {
			p.PreferredWAN = *wan
			p.FailureBehavior = policy.FailureBehavior(*failure)
			p.FallbackWAN = *fallback
		}
		b, err := json.Marshal(daemon.PlanRequest{Policy: p})
		if err != nil {
			return err
		}
		req.Params = b
	} else if *mode != "AUTO" || *wan != "" || *fallback != "" || *failure != "STRICT" {
		return errors.New("policy options require daemon plan")
	}
	resp, err := daemon.Call(context.Background(), *socket, req)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(resp)
	}
	b, err := json.MarshalIndent(resp.Result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}
