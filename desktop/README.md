# FBI-Go desktop

This Tauri 2, React and TypeScript client is an unprivileged view of the existing FBI-Go backend. It uses the version 1 read-only Unix socket daemon for network status, diagnostics, capabilities and routing previews. The Rust bridge invokes only allowlisted `fbi app` commands for desktop-entry discovery and the calling user's policy file. No shell, sudo, host apply, or generic command endpoint is exposed.

## Requirements

- Linux, Node.js 20 or later, npm, Rust and Cargo.
- Tauri 2 Linux development libraries. On Fedora, install the packages in the [official Tauri prerequisites](https://v2.tauri.app/start/prerequisites/), including `webkit2gtk4.1-devel`, `gtk3-devel`, `dbus-devel`, `librsvg2-devel`, `libappindicator-gtk3-devel`, and `libxdo-devel`. Review the package transaction before installing system packages.
- A built `fbi` binary for source-tree development. Release packages include it.

Build the backend with `go build -o fbi ./cmd/fbi`. The desktop starts it in read-only mode as your user when the default socket is absent:

```sh
go build -o fbi ./cmd/fbi
```

Start the desktop development build:

```sh
cd desktop
npm ci
FBI_GO_BIN="$(realpath ../fbi)" npm run tauri dev
```

To build and run a native binary without creating an installer:

```sh
cd desktop
npm ci
npm run tauri build -- --no-bundle
FBI_GO_BIN="$(realpath ../fbi)" ./src-tauri/target/release/fbi-go-desktop
```

`npm run tauri build -- --bundles deb,rpm,appimage` creates Linux installers for the current architecture. The build script compiles the Go `fbi` CLI as a bundled sidecar; installed RPM/DEB packages place it alongside the desktop binary in `/usr/bin`. The desktop starts the sidecar as an unprivileged `PLAN_ONLY` daemon on demand. It creates `XDG_RUNTIME_DIR/fbi-go` with mode `0700`, verifies the `0600` socket, and stops only its own child daemon on normal exit. An explicitly set `FBI_GO_SOCKET` remains externally managed and is never auto-started. See [installation](../docs/install.md) and [release process](../docs/releases.md).

The native window uses custom title controls and follows the system light/dark preference. Settings can enable or disable **close to tray**. When enabled, closing the window hides it; the tray menu has Open and Quit actions. On Linux, use the tray menu rather than relying on tray-icon click events. The tray and Dashboard display sampled `/sys/class/net` RX/TX rates; a rate is an interface counter difference over a monotonic interval, not an Internet speed test. A newly seen, removed, or reset interface shows no rate until the next valid sample. WAN health and RTT are still unavailable.

The native process refuses UID 0. If daemon startup fails, the header shows `DAEMON OFFLINE` and Diagnostics displays the startup error. Check that `XDG_RUNTIME_DIR` is an owned private directory and that no stale or foreign socket occupies `fbi-go/control.sock`, then use Refresh data. The desktop refuses to remove a socket it does not own. A force-killed desktop may leave its read-only child running; a later desktop instance reconnects to that socket. The daemon socket and its parent directory must be owned by the current user and private (`0600` and `0700` respectively).

The web-only layout preview uses `VITE_DEMO=1 npm run dev` and displays a prominent `DEMO DATA` badge. `VITE_DEMO=1 npm run tauri dev` does the same in a native development window when the Vite port is available. Demo policy actions are disabled. Without that flag, the desktop uses actual daemon/CLI data; if either service is unavailable, its error is shown and no values are fabricated. `npm run build`, `npm test`, and `npm run lint` check the frontend. `cargo test --manifest-path src-tauri/Cargo.toml` checks the Rust bridge when Linux Tauri libraries are installed. If those system libraries are unavailable, `cargo test --manifest-path src-tauri/Cargo.toml --no-default-features --lib` checks the isolated Rust bridge; this does not validate the Tauri window build.

Policy edits save only the current user's TOML configuration. Saved policy does not mean active routing. Application launch, session management, rollback and `HOST_APPLY` have no desktop action. Cumulative RX/TX totals come from the daemon's network snapshot; rates come from the local sysfs sampler and are labelled separately. The UI uses logical spacing to support future Persian RTL translation, but English is the only current translation.

See [the UI backend contract](../docs/ui-backend-contract.md), [IPC protocol](../docs/daemon-ipc.md), and [operator safety](../docs/safety.md).
