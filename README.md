# FBI-Go

FBI-Go is a Linux desktop client and Go backend for inspecting multiple network interfaces, previewing routing plans, and saving per-application WAN policies. The desktop shows live interface traffic rates and connects to a read-only Unix socket daemon.

**Host routing is not available.** `HOST_APPLY` is unsupported; a saved policy or `PLAN_ONLY` preview never changes your network. Packet routing has been tested only in isolated namespaces and a disposable VM.

## Quick start

Requires Go 1.23+ and Linux. Run as your normal user:

```sh
go build -o fbi ./cmd/fbi
./fbi multiwan scan --json
```

Install an architecture-matched desktop package or [build the desktop](desktop/README.md). The desktop starts its bundled read-only daemon as your user when needed. It creates a private socket under `XDG_RUNTIME_DIR` and stops its child daemon on normal exit.

## What works

- Read-only network discovery, diagnostics, and routing plans.
- XDG desktop application discovery and private TOML policy editing.
- Six desktop pages, custom window, tray menu, and per-interface RX/TX rates.
- Isolated rootless/VM routing tests with DNS and IPv6 fail-closed protection.

See [installation](docs/install.md), [CLI](docs/cli.md), [safety](docs/safety.md), [UI/backend contract](docs/ui-backend-contract.md), and [releases](docs/releases.md). Licensed under MIT.
