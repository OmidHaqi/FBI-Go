# FBI-Go

FBI-Go is a Linux desktop client and Go backend for inspecting multiple network interfaces, previewing routing plans, and saving per-application WAN policies. The desktop shows live interface traffic rates and connects to a read-only Unix socket daemon.

**Host routing is not available.** `HOST_APPLY` is unsupported; a saved policy or `PLAN_ONLY` preview never changes your network. Packet routing has been tested only in isolated namespaces and a disposable VM.

## Quick start

Requires Go 1.23+ and Linux. Run as your normal user:

```sh
go build -o fbi ./cmd/fbi
./fbi multiwan scan --json
mkdir -p "$XDG_RUNTIME_DIR/fbi-go"
chmod 700 "$XDG_RUNTIME_DIR/fbi-go"
./fbi daemon serve --dry-run --socket "$XDG_RUNTIME_DIR/fbi-go/control.sock"
```

In another terminal, build and run the [Tauri desktop](desktop/README.md), or install an architecture-matched Linux package when a release is published. The daemon must be started separately by the same user.

## What works

- Read-only network discovery, diagnostics, and routing plans.
- XDG desktop application discovery and private TOML policy editing.
- Six desktop pages, custom window, tray menu, and per-interface RX/TX rates.
- Isolated rootless/VM routing tests with DNS and IPv6 fail-closed protection.

See [installation](docs/install.md), [CLI](docs/cli.md), [safety](docs/safety.md), [UI/backend contract](docs/ui-backend-contract.md), and [releases](docs/releases.md). Licensed under MIT.
