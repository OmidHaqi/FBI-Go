# Safety and operator boundaries

The ordinary host CLI inspects devices and produces plans without sudo. The
public Unix socket daemon runs as a regular user in `PLAN_ONLY` mode and has
no apply method. `HOST_APPLY` is unsupported. A saved policy or plan never
changes routing, nftables, DNS, sysctls, or NetworkManager.

Rootless and disposable-VM tests create private network namespaces and
test-owned virtual links. The VM guest initial namespace is touched only by
the explicitly approved test harness: it creates disposable veth/bridge
objects without changing the management default route, DNS, policy rules,
or nftables there. Test resource journals are durable, and cleanup checks
namespace and kernel identities. Ambiguous objects are preserved for manual
review. Foreign routes, rules, nftables objects, and network links must not
be removed to make a test pass.

The internal laboratory executor uses a separate process, verified namespace
FDs, bounded authenticated IPC, and a worker restricted to CAP_NET_ADMIN in
its test-owned namespace. The worker uses `NoNewPrivs` and seccomp. These
controls do not establish production host confinement. An application runs
without unnecessary effective capabilities and only after IPv4 routing and
the IPv6 guard are verified in its namespace.

`fbi multiwan doctor --json` reports compatibility issues, including
VPN/TUN, Docker, NetworkManager, DNS, IPv6, foreign marks and routing state.
An inaccessible nftables inventory is `UNKNOWN`, never proof of a clean
ruleset. Candidate WANs are not proof of independent Internet uplinks.

Physical-host activation would require a complete, exact mutation plan,
ownership checks, a separately tested rollback watchdog, bounded lifetime,
and fresh interactive operator approval. The current implementation offers
none of those host mutation operations. Never use the VM test harness on a
physical host or flush global nftables rules to recover a test.

## Recovery of laboratory resources

On a failed test, stop launching new managed applications and retain the
test workspace, journal, operation ID, namespace identities, and before/after
network snapshots. The owned-resource recovery path compares the journal's
durable intent with kernel objects before deleting anything. A reported
`MANUAL_INTERVENTION_REQUIRED` or `CONFLICT` is a refusal to delete; it is not
permission to remove a matching name by hand. Preserve the objects and
evidence for review by an operator who can compare the exact identities and
foreign state. Repeating an authorized cleanup is safe only when the
ownership check succeeds again.

The public CLI and daemon have no emergency host rollback command because
they cannot apply host routing. In a disposable VM, retain the management
network baseline and use only the test harness's owned cleanup and recovery.
Do not reset NetworkManager, flush nftables, replace the main default route,
or restore a VM snapshot automatically in response to a failed test.
