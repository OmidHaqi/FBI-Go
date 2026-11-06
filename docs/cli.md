# CLI reference

`fbi version [--json]` prints the source-tree build label or embedded package release version. It does not imply that routing is active. All `multiwan` commands below are read-only and need no sudo:

| Command | Result |
| --- | --- |
| `fbi multiwan scan [--json]` | Device and route snapshot, with WAN candidate reasons |
| `fbi multiwan status [--json]` | Snapshot plus inactive host enforcement and health monitoring flags |
| `fbi multiwan doctor [--json]` | Host compatibility findings; inaccessible data is `UNKNOWN` |
| `fbi multiwan plan [--json]` | Read-only conceptual routing plan |
| `fbi multiwan plan-m2 <inventory.json> [--json]` | M2 resource proposal from a supplied inventory; never applies it |

Application commands:

| Command | Result |
| --- | --- |
| `fbi app list [--json]` | XDG desktop-entry discovery and launch limitations |
| `fbi app policy list [--json]` | Saved policies with current resolution status |
| `fbi app policy show <desktop-id> [--json]` | One saved policy and resolution status |
| `fbi app policy set <desktop-id> --auto` | Save an automatic policy for future managed launches |
| `fbi app policy set <desktop-id> --wan mac:aa:bb:cc:dd:ee:ff --mode strict` | Save a strict pinned policy |
| `fbi app policy set <desktop-id> --wan mac:aa:bb:cc:dd:ee:ff --mode failover --fallback mac:11:22:33:44:55:66` | Save an explicit fallback policy |
| `fbi app policy remove <desktop-id>` | Remove a saved policy |

Policy writes affect only the calling user's private TOML file. They do not route an existing process or activate the host. See [policy file and ID rules](application-policies.md).

`fbi app run --wan <lab-wan> -- /absolute/command [args...]` and `fbi app run --app <desktop-id> -- /absolute/command [args...]` require an inherited verified test-owned namespace FD and an already applied laboratory policy. Ordinary host invocation is rejected. The saved-policy launch form currently supports pinned `STRICT` only. It does not authenticate an arbitrary executable by desktop ID.

`fbi daemon serve --dry-run --socket /absolute/private/control.sock` starts an unprivileged read-only Unix socket server. `fbi daemon ping|version|capabilities|status|diagnostics|plan --socket <path> [--json]` calls its version 1 methods. `plan` additionally accepts `--mode`, `--wan`, `--failure`, and `--fallback` for a preview. The parent socket directory must belong to the user and have mode `0700`. See [IPC](daemon-ipc.md).

No CLI command enables `HOST_APPLY` or rewrites host routes.
