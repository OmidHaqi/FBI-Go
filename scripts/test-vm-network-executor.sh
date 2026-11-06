#!/usr/bin/env bash
set -euo pipefail

# Run only inside an operator-provisioned disposable VM after a verified snapshot.
# This script never selects a host interface or accepts a namespace name/path.
if ! command -v systemd-detect-virt >/dev/null || ! systemd-detect-virt --vm --quiet; then
  echo 'BLOCKED: a disposable virtual machine was not detected' >&2
  exit 2
fi
if [[ ${FBI_GO_DISPOSABLE_VM:-} != YES || ${FBI_GO_VM_SNAPSHOT_CREATED:-} != YES || -z ${FBI_GO_VM_SNAPSHOT_ID:-} ]]; then
  echo 'BLOCKED: set FBI_GO_DISPOSABLE_VM=YES, FBI_GO_VM_SNAPSHOT_CREATED=YES and FBI_GO_VM_SNAPSHOT_ID after creating a VM snapshot' >&2
  exit 2
fi
if [[ $(id -u) != 0 ]]; then
  echo 'BLOCKED: enter the disposable VM as root before the privileged phase; this launcher never escalates privileges' >&2
  exit 2
fi
if ! command -v setpriv >/dev/null; then
  echo 'BLOCKED: setpriv is required to run the IPC tests with a nonroot identity' >&2
  exit 2
fi
if ! command -v nmcli >/dev/null; then
  echo 'BLOCKED: NetworkManager read-only device inspection requires nmcli' >&2
  exit 2
fi
if ! command -v flock >/dev/null; then
  echo 'BLOCKED: flock is required to serialize the VM ownership gate' >&2
  exit 2
fi
if ! command -v udevadm >/dev/null; then
  echo 'BLOCKED: udevadm is required before recording stable veth MAC identities' >&2
  exit 2
fi
test_user=${FBI_GO_VM_TEST_USER:-}
if [[ -z $test_user ]] || ! test_uid=$(id -u "$test_user") || [[ $test_uid == 0 ]]; then
  echo 'BLOCKED: provide an existing nonroot FBI_GO_VM_TEST_USER in the disposable VM' >&2
  exit 2
fi
test_gid=$(id -g "$test_user")
test_home=$(getent passwd "$test_user" | cut -d: -f6)
if [[ -z $test_home || ! -d $test_home ]]; then
  echo 'BLOCKED: nonroot VM test user has no home directory' >&2
  exit 2
fi
workspace=${FBI_GO_VM_TEST_WORKSPACE:-}
if [[ -z $workspace || $workspace != /* || $workspace == / || -L $workspace || ! -d $workspace ]]; then
  echo 'BLOCKED: provide a separately created absolute, real FBI_GO_VM_TEST_WORKSPACE directory' >&2
  exit 2
fi
marker=$workspace/.fbi-go-disposable-test-workspace
if [[ $(stat -c %u:%a -- "$workspace") != 0:700 || -L $marker || ! -f $marker || $(stat -c %u:%a -- "$marker") != 0:600 ]]; then
  echo 'BLOCKED: workspace must be root-owned mode 0700 with the operator-created .fbi-go-disposable-test-workspace marker' >&2
  exit 2
fi
if [[ $(find "$workspace" -mindepth 1 -maxdepth 1 ! -name .fbi-go-disposable-test-workspace -print -quit) ]]; then
  echo 'BLOCKED: workspace must be empty apart from its marker' >&2
  exit 2
fi
if [[ $(readlink /proc/self/ns/net) != "$(readlink /proc/1/ns/net)" ]]; then
  echo 'BLOCKED: this VM test expects the guest initial namespace and creates its own test namespaces' >&2
  exit 2
fi
initial_netns=$(readlink /proc/self/ns/net)
cap_eff=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
if (( (16#$cap_eff & (1 << 12)) == 0 || (16#$cap_eff & (1 << 21)) == 0 )); then
  echo 'BLOCKED: guest root lacks CAP_NET_ADMIN or CAP_SYS_ADMIN for owned named namespaces' >&2
  exit 2
fi

# Read-only snapshots of the guest management namespace. Differences fail the
# gate; an operator must decide whether they came from the test or guest churn.
ip -j link show >"$workspace/guest-links.before.json"
ip -j addr show >"$workspace/guest-addrs.before.json"
ip -j -4 route show table all >"$workspace/guest-routes.before.json"
ip -j -6 route show table all >"$workspace/guest-routes6.before.json"
ip -j -4 rule show >"$workspace/guest-rules.before.json"
ip -j -6 rule show >"$workspace/guest-rules6.before.json"
nft -j -s list ruleset >"$workspace/guest-nft.before.json"
cat /etc/resolv.conf >"$workspace/guest-resolv.before.conf"
nmcli -t -f DEVICE,STATE,CONNECTION device status >"$workspace/guest-nm.before.txt"

# Address lifetimes are countdowns (and may be refreshed by the guest's DHCP/RA
# client). Preserve raw evidence, but compare configuration-bearing fields.
normalize_guest_addresses() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    interfaces = json.load(source)
for interface in interfaces:
    for address in interface.get("addr_info", []):
        address.pop("valid_life_time", None)
        address.pop("preferred_life_time", None)
with open(sys.argv[2], "w", encoding="utf-8") as output:
    json.dump(interfaces, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
}

cat <<EOF
Disposable VM snapshot: ${FBI_GO_VM_SNAPSHOT_ID}
Test workspace: ${workspace}
Guest root UID/CapEff/netns: $(id -u)/${cap_eff}/${initial_netns}
IPC test UID/GID: ${test_uid}/${test_gid}, with no effective capabilities
Planned privileged operations: create fresh FBI-Go-owned network namespaces;
create two uniquely named, journaled veth WANs briefly in the guest initial
namespace (no default routes or rules there), each with a gateway peer in a
test-owned namespace; verify exact link identities, carrier and NetworkManager
state, then remove only matching links. A later guest data-plane phase creates
two more test-owned veth WAN ports and two dedicated test-owned L2 bridges in
the guest initial namespace, each connecting only its application veth port
to its synthetic gateway veth port. No guest-initial IP address, default
route, policy rule, forwarding setting, NAT rule, DNS setting, NetworkManager
profile or management-link bridge membership is planned in that phase.
Exact bridge membership and peer fingerprints are checked before cleanup.
Separately, install test IPv4 routes,
policy rules and an
FBI-Go-owned nftables table in those namespaces; observe TCP/UDP packets;
remove only test-owned resources. No guest physical interface or default route
will be selected. HOST_APPLY and public IPC mutations remain unsupported.
VM_ISOLATED_TEST: go test -tags=integration -count=1 -v ./internal/routing -run ^TestNamespacePacketEgress$
Read-only IPC test: compile daemon tests, then run as the nonroot test user.
VM_PROCESS_BOUNDARY_TEST: compile the integration binary, then run a nonroot
controller against one and then two concurrent guest-root workers, each pinned
to its own test-owned namespace.
VM_GUEST_DATA_PLANE_TEST: two UID-1000 applications and restricted workers
send real DNS/TCP/UDP/HTTP through the test-only guest-visible WAN bridge ports.
Each owned synthetic gateway peer is briefly set down and restored while
both managed applications remain alive; no management device is toggled.
VM_ROOTLESS_MANAGED_TEST: run the separate-process IPv6-guard and concurrent
managed TCP/UDP, DNS and curl HTTP packet tests as the nonroot guest user in
fresh user/net/mount namespaces. Kill each worker in a separate round while
its managed application is alive, then verify journal recovery and cleanup.
Trusted setup verifies the FD/plan and prepares the Unix socket before nsenter;
setpriv then retains CAP_NET_ADMIN only, installs a seccomp namespace-denial
filter and no_new_privs. Public IPC remains read-only.
EOF
read -r -p 'Type RUN DISPOSABLE VM TEST to approve this privileged test phase: ' approval
if [[ $approval != 'RUN DISPOSABLE VM TEST' ]]; then
  echo 'Cancelled without running privileged tests' >&2
  exit 2
fi
exec {guest_wan_lock}>"$workspace/.fbi-go-guest-wan.lock"
if ! flock -n "$guest_wan_lock"; then
  echo 'BLOCKED: another VM ownership gate holds this workspace lock' >&2
  exit 2
fi
install -m 0600 /dev/null "$workspace/.fbi-go-guest-wan-approved"
client_dir=$(mktemp -d /tmp/fbi-go-vm-ipc.XXXXXXXX)
exec_dir=$(mktemp -d /tmp/fbi-go-vm-exec.XXXXXXXX)
finish_vm_test() {
  local status=$?
  trap - EXIT
  rm -rf -- "$client_dir" "$exec_dir"
  # Check management state even when the isolated process test fails.
  if [[ $(readlink /proc/self/ns/net) != "$initial_netns" ]]; then
    echo 'FAIL: guest management namespace identity changed' >&2
    status=1
  fi
  if ! ip -j link show >"$workspace/guest-links.after.json" ||
     ! ip -j addr show >"$workspace/guest-addrs.after.json" ||
     ! ip -j -4 route show table all >"$workspace/guest-routes.after.json" ||
     ! ip -j -6 route show table all >"$workspace/guest-routes6.after.json" ||
     ! ip -j -4 rule show >"$workspace/guest-rules.after.json" ||
     ! ip -j -6 rule show >"$workspace/guest-rules6.after.json" ||
     ! nft -j -s list ruleset >"$workspace/guest-nft.after.json" ||
     ! cat /etc/resolv.conf >"$workspace/guest-resolv.after.conf" ||
     ! nmcli -t -f DEVICE,STATE,CONNECTION device status >"$workspace/guest-nm.after.txt"; then
    echo 'FAIL: could not capture guest management state after testing' >&2
    status=1
  else
    if ! normalize_guest_addresses "$workspace/guest-addrs.before.json" "$workspace/guest-addrs.before.normalized.json" ||
       ! normalize_guest_addresses "$workspace/guest-addrs.after.json" "$workspace/guest-addrs.after.normalized.json" ||
       ! cmp -s "$workspace/guest-addrs.before.normalized.json" "$workspace/guest-addrs.after.normalized.json"; then
      echo 'FAIL: guest management namespace address configuration changed; inspect raw and normalized evidence' >&2
      status=1
    fi
    for resource in guest-links guest-routes guest-routes6 guest-rules guest-rules6 guest-nft; do
      if ! cmp -s "$workspace/$resource.before.json" "$workspace/$resource.after.json"; then
        echo "FAIL: guest management namespace $resource changed; inspect workspace evidence" >&2
        status=1
      fi
    done
    if ! cmp -s "$workspace/guest-resolv.before.conf" "$workspace/guest-resolv.after.conf"; then
      echo 'FAIL: guest management resolver changed; inspect workspace evidence' >&2
      status=1
    fi
    if ! cmp -s "$workspace/guest-nm.before.txt" "$workspace/guest-nm.after.txt"; then
      echo 'FAIL: guest NetworkManager device state changed; inspect workspace evidence' >&2
      status=1
    fi
  fi
  if (( status == 0 )); then
    echo 'PASS: guest management namespace identity and read-only resource snapshots unchanged'
    echo 'VM_PROCESS_BOUNDARY_TEST: PASS (test-owned namespaces only; production unverified)'
  fi
  exit "$status"
}
trap finish_vm_test EXIT
install -d -m 0700 "$workspace/journal"
FBI_GO_VM_GUEST_WANS=YES FBI_GO_JOURNAL_DIR="$workspace/journal" FBI_GO_RUN_NETNS=1 FBI_GO_DISPOSABLE_VM=YES \
  go test -tags=integration -count=1 -v ./internal/routing -run '^TestVMGuest(InitialWAN(Ownership|CrashRecovery)|WANForeignNameCollision|BridgePartialCrashRecovery)$' \
  >"$workspace/guest-wan.log" 2>&1 || {
    cat "$workspace/guest-wan.log"
    exit 1
  }
cat "$workspace/guest-wan.log"
# The initial-namespace phase must leave the management plane identical
# before any other privileged phase begins.
ip -j link show >"$workspace/guest-links.after-wan.json"
ip -j addr show >"$workspace/guest-addrs.after-wan.json"
ip -j -4 route show table all >"$workspace/guest-routes.after-wan.json"
ip -j -6 route show table all >"$workspace/guest-routes6.after-wan.json"
ip -j -4 rule show >"$workspace/guest-rules.after-wan.json"
ip -j -6 rule show >"$workspace/guest-rules6.after-wan.json"
nft -j -s list ruleset >"$workspace/guest-nft.after-wan.json"
cat /etc/resolv.conf >"$workspace/guest-resolv.after-wan.conf"
nmcli -t -f DEVICE,STATE,CONNECTION device status >"$workspace/guest-nm.after-wan.txt"
normalize_guest_addresses "$workspace/guest-addrs.before.json" "$workspace/guest-addrs.before.normalized.json"
normalize_guest_addresses "$workspace/guest-addrs.after-wan.json" "$workspace/guest-addrs.after-wan.normalized.json"
cmp -s "$workspace/guest-addrs.before.normalized.json" "$workspace/guest-addrs.after-wan.normalized.json" || {
  echo 'FAIL: guest address configuration changed after WAN ownership phase' >&2
  exit 1
}
for resource in guest-links guest-routes guest-routes6 guest-rules guest-rules6 guest-nft; do
  cmp -s "$workspace/$resource.before.json" "$workspace/$resource.after-wan.json" || {
    echo "FAIL: guest initial-namespace $resource changed after WAN ownership phase" >&2
    exit 1
  }
done
cmp -s "$workspace/guest-resolv.before.conf" "$workspace/guest-resolv.after-wan.conf" || {
  echo 'FAIL: guest resolver changed after WAN ownership phase' >&2
  exit 1
}
cmp -s "$workspace/guest-nm.before.txt" "$workspace/guest-nm.after-wan.txt" || {
  echo 'FAIL: NetworkManager state changed after WAN ownership phase' >&2
  exit 1
}
chmod 0700 "$client_dir"
chmod 0755 "$exec_dir"
install -d -m 0700 -o "$test_uid" -g "$test_gid" "$client_dir/go-cache"
go test -c -o "$client_dir/daemon.test" ./internal/daemon
chown -R "$test_uid:$test_gid" "$client_dir"
drop_priv=(setpriv --reuid="$test_uid" --regid="$test_gid" --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs)
client_context=$("${drop_priv[@]}" sh -c 'printf "%s %s %s\n" "$(id -u)" "$(awk '\''/^CapEff:/ {print $2}'\'' /proc/self/status)" "$(readlink /proc/self/ns/net)"')
read -r actual_uid actual_cap actual_netns <<< "$client_context"
if [[ $actual_uid != "$test_uid" || $actual_netns != "$initial_netns" ]] || (( 16#$actual_cap != 0 )); then
  echo "BLOCKED: nonroot IPC context invalid: $client_context" >&2
  exit 2
fi
printf 'UID=%s CapEff=%s netns=%s\n' "$actual_uid" "$actual_cap" "$actual_netns" >"$workspace/unprivileged-context.log"
( cd "$client_dir" && "${drop_priv[@]}" "$client_dir/daemon.test" -test.v ) >"$workspace/unprivileged-ipc.log" 2>&1 || {
    cat "$workspace/unprivileged-ipc.log"
    exit 1
  }
cat "$workspace/unprivileged-ipc.log"
go test -c -tags=integration -o "$exec_dir/routing.test" ./internal/routing
chmod 0755 "$exec_dir/routing.test"
FBI_GO_VM_PROCESS_TEST=YES FBI_GO_VM_TEST_USER="$test_user" FBI_GO_VM_TEST_BINARY="$exec_dir/routing.test" \
  FBI_GO_JOURNAL_DIR="$workspace/journal" FBI_GO_RUN_NETNS=1 FBI_GO_DISPOSABLE_VM=YES \
  "$exec_dir/routing.test" -test.v -test.run '^TestVM(ExecutorProcessBoundary|ConcurrentExecutorWorkers)$' \
  >"$workspace/process-boundary.log" 2>&1 || {
    cat "$workspace/process-boundary.log"
    exit 1
  }
cat "$workspace/process-boundary.log"
FBI_GO_VM_GUEST_WANS=YES FBI_GO_VM_PROCESS_TEST=YES FBI_GO_VM_TEST_USER="$test_user" FBI_GO_VM_TEST_BINARY="$exec_dir/routing.test" \
  FBI_GO_JOURNAL_DIR="$workspace/journal" FBI_GO_RUN_NETNS=1 FBI_GO_DISPOSABLE_VM=YES \
  sh -c 'cd internal/routing && exec "$1" -test.v -test.run "^TestVMGuestVisibleWANDataPlane$"' sh "$exec_dir/routing.test" \
  >"$workspace/guest-data-plane.log" 2>&1 || {
    cat "$workspace/guest-data-plane.log"
    exit 1
  }
cat "$workspace/guest-data-plane.log"
FBI_GO_ROOTLESS_SUITE=process "${drop_priv[@]}" env HOME="$test_home" GOCACHE="$client_dir/go-cache" bash scripts/test-rootless-netns.sh \
  >"$workspace/rootless-managed-executor.log" 2>&1 || {
    cat "$workspace/rootless-managed-executor.log"
    exit 1
  }
cat "$workspace/rootless-managed-executor.log"
install -d -m 0700 "$workspace/packet-evidence"
FBI_GO_EVIDENCE_DIR="$workspace/packet-evidence" FBI_GO_JOURNAL_DIR="$workspace/journal" FBI_GO_RUN_NETNS=1 FBI_GO_DISPOSABLE_VM=YES \
  go test -tags=integration -count=1 -v ./internal/routing -run '^TestNamespacePacketEgress$' \
  >"$workspace/network-executor.log" 2>&1 || {
    cat "$workspace/network-executor.log"
    exit 1
  }
cat "$workspace/network-executor.log"
if [[ $(find "$workspace/journal" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
  echo 'FAIL: test-owned journal directory is not empty after cleanup' >&2
  exit 1
fi
echo 'PASS: unprivileged read-only IPC, separate-process VM boundary and isolated packet tests; checking guest management state'
