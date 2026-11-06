# Installation and prerequisites

FBI-Go 2.0 currently builds from source on Linux. Go 1.23 or later is required. `make all` also builds the optional legacy `binder.so` library, which requires a C compiler and cgo. No daemon or system service is installed by this build.

```sh
go build ./...
make all
./fbi version
./fbi multiwan scan --json
```

Keep `fbi` and `binder.so` together only if using legacy ForceBindIP mode. The current command reports `2.0.0-lab`; this label reflects that host routing is unavailable. Read-only inspection and policy-file commands run as the calling user. Do not run the CLI as root for ordinary inspection.

Rootless integration tests additionally require `unshare`, `mount`, `ip`, `nft`, `nsenter`, `ping`, Python 3, and kernel support for unprivileged user and network namespaces. The launcher checks capabilities and isolation before it changes any test namespace. `bash scripts/test-rootless-netns.sh` never authorizes host routing. The separate VM harness requires a disposable VM, a verified snapshot, and interactive approval; it is not an installation step.

Fedora, Debian, and Ubuntu packaging and production service installation are not provided. See [CLI commands](cli.md), [IPC](daemon-ipc.md), and [safety](safety.md).

## Desktop client

The optional Tauri 2 client lives in [desktop](../desktop/README.md). It needs Node.js, Rust, and the Linux WebKitGTK 4.1/GTK development libraries listed by Tauri. Build and run the Go `fbi` binary and its read-only daemon as the same regular user before opening the desktop client. The desktop does not install or start a privileged service. Its `VITE_DEMO=1` mode is only a labelled visual preview.
