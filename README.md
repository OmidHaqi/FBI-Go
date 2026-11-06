# FBI-Go 2.0

FBI-Go is a Linux Multi-WAN research backend with a read-only host CLI and an isolated networking laboratory. It discovers devices and builds routing plans. Managed application routing, DNS, IPv6 fail-closed protection, and transactional recovery have been tested in rootless namespaces and a disposable VM. **Production host routing and `HOST_APPLY` remain unsupported.** A plan or saved policy does not change host networking. The legacy ForceBindIP mode remains available.

## Build

Go 1.23 and Linux are required. The legacy shared library additionally needs a C compiler. See [installation and prerequisites](docs/install.md).

```sh
make all
go test ./...
go vet ./...
```

The Makefile builds `fbi` and `binder.so` in this directory. For the legacy mode, keep both files together.

## Host inspection

```sh
./fbi version
./fbi multiwan scan
./fbi multiwan status --json
./fbi multiwan doctor --json
./fbi multiwan plan --json
./fbi multiwan plan-m2 internal/routing/testdata/fedora_topology.json --json
```

These commands require no sudo and never change routing, DNS, nftables, NetworkManager, or sysctls. `doctor` reports host compatibility read-only; denied inventory reads are `UNKNOWN`. `scan` reports addresses, routes, counters, carrier/operstate, and conservative IPv4 WAN candidates. `status` reports that host enforcement and live health probes are absent. `plan-m2` reads a JSON inventory and reports proposed resources or rejection reasons. The included fixture is synthetic. A candidate is **not** proof of Internet reachability or independent uplinks. See [CLI commands](docs/cli.md) and [network discovery](docs/network-discovery.md).

The primary discovery path uses Linux netlink. Where a restricted environment denies even read-only netlink access, `/sys`, `/proc`, and interface ioctls provide limited fallback data. The output warns about missing policy tables/rules; empty addresses or routes in such environments must not be treated as proof that the host has none.

## Legacy ForceBindIP

```sh
./fbi 192.0.2.10 curl https://example.com
```

This sets `LD_PRELOAD` and `FORCE_BIND_IP` for the launched process using the existing `binder.so`. It works only for applications and socket calls the library can intercept. It does not guarantee that a chosen interface is used, and it is not the Multi-WAN routing engine. IPv4 and IPv6 address strings are accepted by the legacy library; behavior depends on the application's socket family.

## Application policies and local control

`fbi app list` discovers desktop entries from XDG directories. `fbi app policy list/show/set/remove` manages the calling user's TOML policy file. These commands change configuration only. The managed `app run` launcher requires an explicitly owned test namespace and rejects ordinary host execution. Saved policies affect future managed launches and new connections, not established TCP connections or already running processes.

The version 1 Unix socket service is unprivileged and read-only. It exposes status, diagnostics and plan previews; mutation methods and `HOST_APPLY` are rejected. See [the IPC protocol](docs/daemon-ipc.md) and [UI backend contract](docs/ui-backend-contract.md).

## Isolated validation and limitations

The namespace backend generates owned policy routes and nftables rules for new IPv4 TCP/UDP flows. Managed IPv4-only application namespaces have a kernel-enforced IPv6 fail-closed guard. DNS and routing tests use isolated synthetic WANs. The rootless suite is run with `bash scripts/test-rootless-netns.sh`; the VM suite has separate snapshot and interactive approval gates. Neither suite proves production host compatibility. D-Bus activation, Flatpak, Wayland, local host services, and application-specific DNS clients are not generally supported. The project does not implement bonding or packet striping; a single TCP connection does not gain additive bandwidth.

See [application routing](docs/application-routing.md), [application policies](docs/application-policies.md), [operator safety and recovery](docs/safety.md), and [UI backend contract](docs/ui-backend-contract.md). The MIT license is unchanged.
