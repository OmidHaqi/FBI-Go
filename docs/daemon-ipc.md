# Local control IPC (protocol version 1)

The daemon is a regular-user, `PLAN_ONLY` process. It has no network apply method. It does not install a service, modify a cgroup, or change routing, nftables, DNS or sysctls. `ISOLATED_TEST` and `HOST_APPLY` are reserved mode names, not selectable modes. The Linux desktop package includes the `fbi` CLI sidecar but does not start this daemon automatically; launch it in the same user's private runtime directory before connecting the desktop.

## Trust boundary and framing

Run `fbi daemon serve --dry-run --socket /path/to/private/control.sock` where the parent directory already belongs to the current user and has mode `0700`. The path must be absolute, absent before bind, and have no symlink component. The server binds a `0600` Unix socket and removes only the same **filesystem socket** inode on shutdown. The listener FD refers to a separate sockfs inode and is never used for filesystem identity checks or chmod. The bound pathname is chmodded with Linux `fchmodat2(AT_SYMLINK_NOFOLLOW)` and rechecked; an unavailable syscall causes startup to fail closed. The server refuses UID 0. Same-UID and same-GID connections are authenticated using kernel `SO_PEERCRED`; JSON-supplied UID/PID fields are rejected as unknown fields. No PID is retained after the connection, so PID reuse is not an authority mechanism.

The private parent directory prevents other UIDs from replacing the socket. A process already running as the same UID can mutate its own directory between checks; the inode-aware cleanup preserves a detected replacement, but Linux pathname unlink is not an atomic compare-and-delete operation. Same-UID hostile races are not claimed to be impossible. The server refuses an existing pathname, including stale sockets, and never unlinks one blindly. Startup and shutdown cleanup errors are returned to the caller.

One newline-terminated JSON request is accepted per connection, at most 64 KiB **including the newline**. A frame of exactly 64 KiB is accepted when its JSON is valid; a frame that exceeds the limit returns `TOO_LARGE` before JSON decoding, including when the newline lies beyond the read cap. A shorter frame without a newline returns `INVALID_REQUEST`. Reads are capped at 64 KiB plus one classification byte, so fragmented and very large frames do not cause unbounded request allocation. Responses are at most 1 MiB. Both directions have a 5-second deadline; client context cancellation closes its connection. The daemon handles clients concurrently and closes active connections on cancellation. Protocol version is `1`.

```json
{"version":1,"method":"daemon.plan","params":{"policy":{"id":"preview","mode":"PINNED_WAN","preferred_wan":"mac:00:11:22:33:44:55","failure_behavior":"STRICT","enabled":true}}}
```

Responses are `{"version":1,"result":...}` or `{"version":1,"error":{"code":"...","message":"..."}}`. Codes include `INVALID_REQUEST`, `TOO_LARGE`, `UNSUPPORTED_VERSION`, `INVALID_POLICY`, `WAN_UNRESOLVED`, `INVENTORY_UNAVAILABLE`, `UNAUTHORIZED`, `BUSY`, and `UNSUPPORTED`. At most 64 connections are serviced concurrently. Only `daemon.ping`, `daemon.version`, `daemon.capabilities`, `daemon.status`, `daemon.diagnostics`, and `daemon.plan` are implemented. Mutating method names return `UNSUPPORTED` before inventory access. Authentication grants only this fixed read-only allowlist; it is not privileged authorization.

`daemon.plan` uses the live read-only link/route snapshot, resolves a stable WAN ID using the existing policy resolver, and calls the existing M2 planner. It returns the requested policy, selected ID, proposed table/rule/mark resources, conflicts, warnings and future operations. The result always has `state=PLANNED`, `mode=PLAN_ONLY`, `applied=false`. An ordinary user scan does not provide complete foreign rule/table/mark/nft ownership or live WAN health. Consequently `safe_to_apply` is false; numeric allocations are proposals only. No packet verification is implied.

`daemon.diagnostics` returns a read-only host compatibility report. Each external inspection command has a three-second timeout. An unavailable nftables inventory is reported as `UNKNOWN`, and the service never interprets that as an empty ruleset. The companion CLI is `fbi daemon diagnostics --socket <private-path> --json`.

## Manual local smoke test

```sh
TEST_SOCKET_DIR=$(mktemp -d /tmp/fbi-go-ipc.XXXXXX)
go test -v ./internal/daemon
go test -race ./internal/daemon
go build -o /tmp/fbi-go-test ./cmd/fbi
/tmp/fbi-go-test daemon serve --dry-run --socket "$TEST_SOCKET_DIR/control.sock"
```

In a second terminal:

```sh
/tmp/fbi-go-test daemon ping --socket "$TEST_SOCKET_DIR/control.sock"
/tmp/fbi-go-test daemon status --socket "$TEST_SOCKET_DIR/control.sock" --json
/tmp/fbi-go-test daemon diagnostics --socket "$TEST_SOCKET_DIR/control.sock" --json
/tmp/fbi-go-test daemon plan --socket "$TEST_SOCKET_DIR/control.sock" --json
```

Export or copy `TEST_SOCKET_DIR` to the second terminal. Send SIGINT to the server and verify that only its own socket was removed. The IPC tests use temporary private directories and do not require root. Some sandboxes deny Unix socket creation; socket-dependent tests report `SKIP` there. A passing test suite with those skips does not establish Fedora IPC success.
