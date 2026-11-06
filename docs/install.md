# Installation and prerequisites

FBI-Go 2.0 builds from source on Linux with Go 1.23 or later. No daemon or system service is installed by this build.

```sh
go build ./...
go build -o fbi ./cmd/fbi
./fbi version
./fbi multiwan scan --json
```

A source-tree CLI build reports `2.0.0-lab`; release packages embed the release version. Neither label implies host routing is available. Read-only inspection and policy-file commands run as the calling user. Do not run the CLI as root for ordinary inspection.

The desktop release workflow builds x86_64 and aarch64 RPM, DEB, and AppImage artifacts. Download only the package for your architecture and verify it against `SHA256SUMS.txt`. RPM/DEB packages include the `fbi` CLI next to the desktop executable. AppImage also includes the sidecar. No production service is installed. Stable and development-release packages use different version metadata; see [releases](releases.md). See [CLI commands](cli.md), [IPC](daemon-ipc.md), and [safety](safety.md).

## Desktop client

The optional Tauri 2 client lives in [desktop](../desktop/README.md). It needs Node.js, Rust, and the Linux WebKitGTK 4.1/GTK development libraries listed by Tauri. Build and run the Go `fbi` binary and its read-only daemon as the same regular user before opening the desktop client. The desktop does not install or start a privileged service. Its `VITE_DEMO=1` mode is only a labelled visual preview.
