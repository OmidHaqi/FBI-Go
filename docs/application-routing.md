# Application routing

`ApplicationPolicy` supports `AUTO`, `PINNED_WAN`, and `SYSTEM_DEFAULT`. A
pinned policy uses `STRICT` or an explicitly configured `FAILOVER` WAN.
Managed application policy takes precedence over global automatic selection;
unmanaged traffic retains the existing system route. Changes affect new
connections. Established TCP sessions are not migrated.

The current launcher requires an inherited FD for a verified, test-owned
application network namespace. It starts the application as a nonroot user;
children inherit the namespace. Each namespace has its own IPv4 policy
routing, connection marking, DNS configuration, and IPv6 fail-closed guard.
The isolated laboratory has packet-verified TCP, UDP, DNS, HTTP, source
addresses, and selected synthetic WAN paths. The `STRICT` test route prevents
an unavailable selected WAN from silently falling through to another test
gateway. Full positive IPv6 WAN routing is unsupported.

This launcher is not a production host routing service. It cannot capture an
already running process, and a desktop entry ID alone does not authenticate
the executable supplied to `app run`. The ordinary host CLI and public daemon
IPC do not activate routing. See [application policies](application-policies.md)
and [the UI backend contract](ui-backend-contract.md).
