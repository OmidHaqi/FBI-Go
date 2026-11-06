# Application discovery and saved policies

`fbi app list [--json]` reads `applications/**/*.desktop` under `XDG_DATA_HOME` (default `~/.local/share`) and then `XDG_DATA_DIRS` (default `/usr/local/share:/usr/share`). Desktop IDs replace subdirectory separators with `-`. The first ID wins; a user `Hidden=true` entry masks a lower-priority entry. Discovery reads regular files below 1 MiB, does not follow entry symlinks, and never runs `Exec` or `TryExec`. It reports `Name`, `GenericName`, `Icon`, `Exec`, `TryExec`, `Terminal`, `DBusActivatable`, `NoDisplay`, `Hidden`, and `Path` metadata. Invalid or non-application entries are skipped.

`Exec` is parsed only to flag unsupported activation; it is never shell-evaluated. Field codes other than `%%`, invalid quoting, D-Bus activation, terminal activation, unavailable `TryExec`, and recognizable Flatpak commands are marked unsupported. `launch_supported` means only that the metadata has no known parser blocker. Discovery never launches a desktop entry. The laboratory `app run` command requires an explicit absolute executable and arguments.

## Policy file

`$XDG_CONFIG_HOME/fbi-go/policies.toml`, or `~/.config/fbi-go/policies.toml`, is private mode 0600 in a mode 0700 directory. The versioned TOML subset is:

```toml
version = 1

[[policies]]
id = "org.example.Browser.desktop"
display_name = "Browser"
desktop_entry = "org.example.Browser.desktop"
mode = "PINNED_WAN"
preferred_wan = "mac:aa:bb:cc:dd:ee:ff"
failure_behavior = "STRICT"
enabled = true
```

Modes are `AUTO`, `PINNED_WAN`, and `SYSTEM_DEFAULT`. `FAILOVER` requires a distinct `fallback_wan`; `STRICT` forbids one. The CLI currently writes `AUTO` or pinned policies; `SYSTEM_DEFAULT` is accepted when reading a valid file but is not a CLI set option yet. Unsupported schema versions, unknown keys, duplicate policies, malformed values, loose file permissions, and symlinked policy files are rejected. Writes use a private sidecar flock, a same-directory temporary file, fsync, atomic rename, and directory fsync. The policy file stores a stable desktop ID and a WAN identity. The CLI accepts `mac:` WAN IDs for persistent host inventory; test-only `wan-a`/`wan-b` IDs are accepted only in the owned rootless lab. A MAC ID is more stable than an interface name but can still change with hardware replacement, spoofing, or Wi-Fi randomization.

## Commands and status

```sh
fbi app list --json
fbi app policy list --json
fbi app policy show org.example.Browser.desktop --json
fbi app policy set org.example.Browser.desktop --auto
fbi app policy set org.example.Browser.desktop --wan mac:aa:bb:cc:dd:ee:ff --mode strict
fbi app policy set org.example.Browser.desktop --wan mac:aa:bb:cc:dd:ee:ff --mode failover --fallback mac:11:22:33:44:55:66
fbi app policy remove org.example.Browser.desktop
```

`CONFIGURED` means a record exists. `RESOLVED` means its WAN IDs uniquely match current *candidate* interfaces, without claiming health or enforcement. `UNAVAILABLE` means a required ID is absent, ambiguous, or the policy is disabled. `UNSUPPORTED` indicates invalid policy semantics. `APPLIED` and `VERIFIED` are never emitted by read commands. A saved policy does not reroute an existing process. Explicit managed policy takes precedence over global automatic selection; unmanaged traffic remains on system routing. A missing explicit policy leaves the process outside managed scope.

The experimental lab command `fbi app run --app <desktop-id> -- /absolute/command [args...]` reads the saved pinned policy and checks that its WAN equals the test-owned namespace's already applied routing. A missing or mismatched policy fails before target execution. `--wan` remains available. `AUTO`, `SYSTEM_DEFAULT`, and dynamic failover launch are not available through this pinned-only lab command. No host activation path exists.

## Desktop limitations

Each managed app currently needs its own isolated network namespace. Host `127.0.0.1` services, host loopback DNS stubs, local development servers, proxies, VPN routes, and some session services are inaccessible unless explicitly bridged. D-Bus activation and single-instance applications may reuse an existing host process, breaking namespace assumptions. Flatpak has its own sandbox and launch portal; GNOME Wayland may need session sockets and environment integration. Child processes normally inherit the namespace, but detached descendants after parent exit are not fully tracked. Namespace-specific DNS and an IPv4-only application's IPv6 fail-closed guard passed isolated packet tests; they do not establish compatibility with arbitrary desktop applications or production WANs.

Unit tests use synthetic XDG directories and temporary policy files. Rootless packet validation, when permitted, uses `bash scripts/test-rootless-netns.sh`. Passing isolated tests does not verify or authorize production host routing.

The CLI does not cryptographically bind a saved desktop ID to the caller-supplied absolute executable. This lab-only identity is not suitable as production authorization. The public daemon IPC remains read-only and does not write policy files or launch applications.
