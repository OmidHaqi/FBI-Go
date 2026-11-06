# UI backend contract

This describes the version 1, read-only integration boundary for a future
unprivileged desktop UI. The version 1 method allowlist and response framing
are stable for this backend handoff. The UI must never run as root or infer
enforcement from configuration.

## Current Unix socket protocol

- Version `1`; one newline-delimited JSON request and response per connection.
- Same-UID/GID `SO_PEERCRED` authentication and private filesystem socket identity checks.
- Request limit 64 KiB, response limit 1 MiB, I/O deadline 5 seconds.
- Read-only methods: `daemon.ping`, `daemon.version`, `daemon.capabilities`, `daemon.status`, `daemon.diagnostics`, `daemon.plan`.
- `daemon.status` returns `mode=PLAN_ONLY`, `applied=false`, and a network snapshot.
- `daemon.diagnostics` returns read-only compatibility findings. Permission-denied inventory is unknown, not clean.
- `daemon.plan` validates an `ApplicationPolicy` and returns a proposal, without reserving or applying resources.
- Other methods return structured errors; `HOST_APPLY` is unsupported.

Each request has `{"version":1,"method":"..."}` and optionally `params`.
Each response has `version` and either `result` or
`error:{"code":"...","message":"..."}`. A request frame is terminated by a
newline. Unknown parameters are rejected. Clients must call
`daemon.capabilities` after connecting and must not assume additional methods.

| Method | Parameters | Current result |
| --- | --- | --- |
| `daemon.ping` | None | `{"pong":true}` |
| `daemon.version` | None | `{"protocol":1,"mode":"PLAN_ONLY"}` |
| `daemon.capabilities` | None | `mode`, `read_only`, `host_apply`, `isolated_test` |
| `daemon.status` | None | `state="PLANNED"`, `mode="PLAN_ONLY"`, `applied=false`, `snapshot` |
| `daemon.diagnostics` | None | `read_only=true`, `findings[]` with `code`, `status`, `detail` |
| `daemon.plan` | `{"policy":ApplicationPolicy}` | `state="PLANNED"`, `applied=false`, `requested_policy`, `validated_wan_id`, `proposed_resources`, `conflicts`, `warnings`, `required_operations` |

`snapshot.devices[]` includes stable `id`, `name`, `kind`, `state`, `admin_up`,
`oper_state`, optional `carrier`, `addresses`, optional `gateways`, RX/TX byte
counters, `candidate`, and `reasons`. `snapshot.routes[]` includes family,
destination, gateway, interface, table, metric, and optional source. These are
inventory observations. `candidate=true` does not establish health or uplink
independence. Diagnostic finding statuses are `INFO`, `WARNING`, `BLOCKED`,
and `UNKNOWN`; a blocked or unknown finding must remain visible to the user.

`daemon.plan` is an offline preview. Its numeric identifiers have not been
reserved and its conflict list is incomplete when foreign inventory is
unreadable. The current daemon reports neither measured RTT nor live probe
health. The CLI's `fbi multiwan status` likewise reports health monitoring
inactive.

See [daemon IPC](daemon-ipc.md) for message examples and socket lifecycle rules.

## Other existing CLI surfaces

`fbi app list --json` returns desktop entries with stable ID, display metadata,
`launch_supported`, and explicit `limitations`. `fbi app policy list --json`
returns policy resolutions with `policy`, `status`, `reason`, and resolved
interface names where available; `show <desktop-id> --json` returns one.
These are CLI JSON shapes, **not** daemon IPC methods. `fbi multiwan
scan/status/doctor/plan` are also local reads. Policy `set/remove` writes only
the calling user's TOML under XDG configuration. `fbi app run` requires an
owned laboratory namespace and cannot start a host-routed desktop
application. The daemon does not yet expose policy writes or launches.

## UI state model

Display **discovered**, **configured**, **resolved**, **planned**, **applied**, and **packet verified** separately. A `PLANNED` response must never become an active-session badge. Disconnected, degraded, conflict, unsupported, and awaiting-approval states must remain distinct. Live health and active sessions are not currently published by the daemon.

## Missing operations

The current protocol does not expose policy mutation, authorized launch, active-session inventory, termination, rollback, or event streaming. These require a separately reviewed authorization model and an executor confined to exact owned resources. No generic privileged command endpoint should be added. The current rootless and guest test workers are not a production host service.

Physical-host activation requires complete host inventory, proven nonconflicting ownership, an independently tested rollback watchdog, a bounded mutation plan, and fresh interactive operator approval. An environment variable or saved policy is never approval.
