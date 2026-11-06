#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")/.."
script=$(realpath "$0")

if [[ ${1:-} != --inside ]]; then
    if [[ $(id -u) -eq 0 ]]; then
        echo 'BLOCKED: start as an unprivileged user, without sudo' >&2
        exit 2
    fi
    for tool in unshare mount ip nft nsenter go python3 ping stat mktemp; do
        command -v "$tool" >/dev/null || { echo "BLOCKED: missing $tool" >&2; exit 2; }
    done
    export FBI_GO_CALLER_UID=$(id -u)
    export FBI_GO_CALLER_GID=$(id -g)
    export FBI_GO_PARENT_NETNS=$(stat -Lc '%d:%i' /proc/self/ns/net)
    export FBI_GO_PARENT_USERNS=$(stat -Lc '%d:%i' /proc/self/ns/user)
    if unshare --user --map-root-user --net --mount --fork -- bash "$script" --inside; then
        status=0
    else
        status=$?
    fi
    if [[ $(stat -Lc '%d:%i' /proc/self/ns/net) != "$FBI_GO_PARENT_NETNS" || $(stat -Lc '%d:%i' /proc/self/ns/user) != "$FBI_GO_PARENT_USERNS" ]]; then
        echo 'FAIL: launcher parent namespace identity changed' >&2
        exit 1
    fi
    exit "$status"
fi

block() { echo "BLOCKED: $*" >&2; exit 2; }
[[ ${FBI_GO_CALLER_UID:-} != 0 && ${FBI_GO_CALLER_GID:-} && ${FBI_GO_PARENT_NETNS:-} && ${FBI_GO_PARENT_USERNS:-} ]] || block 'launcher parent identity missing'
[[ $(id -u) -eq 0 ]] || block 'UID mapping failed'
[[ $(stat -Lc '%d:%i' /proc/self/ns/net) != "$FBI_GO_PARENT_NETNS" ]] || block 'network namespace was not isolated'
[[ $(stat -Lc '%d:%i' /proc/self/ns/user) != "$FBI_GO_PARENT_USERNS" ]] || block 'user namespace was not isolated'
if init_net=$(stat -Lc '%d:%i' /proc/1/ns/net 2>/dev/null); then
    [[ $(stat -Lc '%d:%i' /proc/self/ns/net) != "$init_net" ]] || block 'network namespace matches PID 1'
fi
[[ $(awk 'NR==1 {print $1, $2, $3}' /proc/self/uid_map) == "0 $FBI_GO_CALLER_UID 1" ]] || block 'unexpected UID map'
[[ $(awk 'NR==1 {print $1, $2, $3}' /proc/self/gid_map) == "0 $FBI_GO_CALLER_GID 1" ]] || block 'unexpected GID map'
[[ $(cat /proc/self/setgroups) == deny ]] || block 'outer setgroups restriction not inherited'

mount --make-rprivate / || block 'cannot make mount propagation private'
mount -t tmpfs -o mode=0755,nodev,nosuid,noexec tmpfs /run || block 'cannot create private /run'
mkdir -m 0700 /run/netns
grep -q ' /run .* - tmpfs ' /proc/self/mountinfo || block 'private /run mount not proven'

caps=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
for bit in 12 13 21; do
    (( (16#$caps & (1 << bit)) != 0 )) || block "missing effective capability bit $bit"
done
echo 'PASS: isolated user, network and mount namespaces; private /run; required capabilities'

evidence=$(mktemp -d -p /tmp fbi-go-rootless-evidence.XXXXXXXX) || block 'cannot create evidence directory'
chmod 0700 "$evidence"
export FBI_GO_EVIDENCE_DIR=$evidence FBI_GO_ROOTLESS_TEST=1
mkdir -m 0700 "$evidence/journal"
export FBI_GO_JOURNAL_DIR="$evidence/journal"
echo "Evidence: $evidence"
printf 'capability\tresult\tdetail\n' > "$evidence/capabilities.tsv"

cleanup() {
    status=$?
    trap - EXIT
    for name in fbi-probe-a fbi-probe-b; do
        ip netns del "$name" >/dev/null 2>&1 || true
    done
    if compgen -G '/run/netns/*' >/dev/null; then
        echo 'FAIL: test namespace registry is not empty; private mount will be discarded on exit' >&2
        status=1
    fi
    printf '{"exit_status":%d,"evidence_dir":"%s"}\n' "$status" "$evidence" > "$evidence/launcher-summary.json"
    exit "$status"
}
trap cleanup EXIT

dump_probe_diagnostics() {
    local namespace command output
    for namespace in fbi-probe-a fbi-probe-b; do
        [[ -e /run/netns/$namespace ]] || continue
        printf 'namespace %s identity: ' "$namespace"
        stat -Lc '%d:%i' "/run/netns/$namespace" || true
        for command in link addr route rule; do
            printf '$ ip -n %s -j %s\n' "$namespace" "$command"
            if output=$(ip -n "$namespace" -j "$command" show 2>&1); then
                printf '%s\n' "$output"
            else
                printf 'diagnostic failed: %s\n' "$output"
            fi
        done
    done
}

probe() {
    local label=$1
    shift
    local output
    if ! output=$("$@" 2>&1); then
        printf 'BLOCKED: %s; command:' "$label" >&2
        printf ' %q' "$@" >&2
        printf '\n%s\n' "$output" >&2
        printf '%s\tBLOCKED\t%s\n' "$label" "$output" >> "$evidence/capabilities.tsv"
        dump_probe_diagnostics > "$evidence/probe-diagnostics.txt" 2>&1 || true
        exit 2
    fi
    echo "PASS: $label"
    printf '%s\tPASS\t\n' "$label" >> "$evidence/capabilities.tsv"
}

probe 'child namespace creation A' ip netns add fbi-probe-a
probe 'child namespace creation B' ip netns add fbi-probe-b
probe 'veth creation' ip -n fbi-probe-a link add fbi_probe_a type veth peer name fbi_probe_b
probe 'veth move to owned child namespace' ip -n fbi-probe-a link set fbi_probe_b netns fbi-probe-b
probe 'client veth exists after move' ip -n fbi-probe-a link show dev fbi_probe_a
probe 'gateway veth exists after move' ip -n fbi-probe-b link show dev fbi_probe_b
probe 'client IPv4 address' ip -n fbi-probe-a addr add 192.0.2.9/24 dev fbi_probe_a
probe 'gateway IPv4 address' ip -n fbi-probe-b addr add 192.0.2.1/24 dev fbi_probe_b
probe 'client loopback up' ip -n fbi-probe-a link set lo up
probe 'gateway loopback up' ip -n fbi-probe-b link set lo up
probe 'client veth up' ip -n fbi-probe-a link set fbi_probe_a up
probe 'gateway veth up' ip -n fbi-probe-b link set fbi_probe_b up
probe 'client link and address validation' bash -c 'set -euo pipefail; ip -n fbi-probe-a -j link show dev fbi_probe_a | python3 -c '\''import json,sys; x=json.load(sys.stdin); assert len(x)==1 and x[0]["ifname"]=="fbi_probe_a" and "UP" in x[0]["flags"]'\''; ip -n fbi-probe-a -j addr show dev fbi_probe_a | python3 -c '\''import json,sys; x=json.load(sys.stdin); assert any(a.get("local")=="192.0.2.9" and a.get("prefixlen")==24 for a in x[0].get("addr_info",[]))'\'''
probe 'gateway link and address validation' bash -c 'set -euo pipefail; ip -n fbi-probe-b -j link show dev fbi_probe_b | python3 -c '\''import json,sys; x=json.load(sys.stdin); assert len(x)==1 and x[0]["ifname"]=="fbi_probe_b" and "UP" in x[0]["flags"]'\''; ip -n fbi-probe-b -j addr show dev fbi_probe_b | python3 -c '\''import json,sys; x=json.load(sys.stdin); assert any(a.get("local")=="192.0.2.1" and a.get("prefixlen")==24 for a in x[0].get("addr_info",[]))'\'''
probe 'gateway direct-subnet route' bash -c 'set -euo pipefail; ip -n fbi-probe-a -j route get 192.0.2.1 | python3 -c '\''import json,sys; x=json.load(sys.stdin); assert len(x)==1 and x[0].get("dev")=="fbi_probe_a" and x[0].get("prefsrc")=="192.0.2.9", x'\'''
probe 'gateway reachability' ip netns exec fbi-probe-a ping -I fbi_probe_a -c 1 -W 1 192.0.2.1
probe 'route add' ip -n fbi-probe-a route add table 30099 203.0.113.0/24 via 192.0.2.1 dev fbi_probe_a
probe 'route delete' ip -n fbi-probe-a route del table 30099 203.0.113.0/24 via 192.0.2.1 dev fbi_probe_a
probe 'policy rule add' ip -n fbi-probe-a rule add priority 15099 fwmark 0x40000099 lookup 30099
probe 'policy rule delete' ip -n fbi-probe-a rule del priority 15099 fwmark 0x40000099 lookup 30099
probe 'nft route-output and conntrack mark operations' bash -c 'printf "%s\n" "add table ip fbi_probe" "add chain ip fbi_probe output { type route hook output priority mangle; policy accept; }" "add rule ip fbi_probe output ct mark 0x40000099 meta mark set ct mark" "add rule ip fbi_probe output meta mark 0x40000099 ct mark set meta mark" | nsenter --net=/run/netns/fbi-probe-a -- nft -f -'
probe 'nft owned-table removal' nsenter --net=/run/netns/fbi-probe-a -- nft delete table ip fbi_probe
probe 'child namespace cleanup A' ip netns del fbi-probe-a
probe 'child namespace cleanup B' ip netns del fbi-probe-b
app_gid=$FBI_GO_CALLER_GID
if [[ $app_gid == 0 ]]; then app_gid=$FBI_GO_CALLER_UID; fi
probe 'nested nonroot application UID/GID mapping and zero effective capabilities' \
    unshare --user "--map-user=$FBI_GO_CALLER_UID" "--map-group=$app_gid" -- \
    python3 -c 'import os
uid = int(os.environ["FBI_GO_CALLER_UID"])
gid = int(os.environ["FBI_GO_CALLER_GID"]) or uid
assert os.geteuid() == uid and os.getegid() == gid, (os.geteuid(), os.getegid())
assert open("/proc/self/uid_map").read().split() == [str(uid), "0", "1"]
assert open("/proc/self/gid_map").read().split() == [str(gid), "0", "1"]
assert open("/proc/self/setgroups").read().strip() == "deny"
status = dict(line.split(":", 1) for line in open("/proc/self/status") if ":" in line)
assert int(status["CapEff"].strip(), 16) == 0, status["CapEff"]'

case ${FBI_GO_ROOTLESS_SUITE:-all} in
    all) test_filter='^TestRootless(PacketEgress|CrashRecovery|IPv6GuardCrashRecovery|ManagedApps|DesktopCompatibility|ExecutorProcessBoundary|ConcurrentExecutorWorkers)$' ;;
    process) test_filter='^TestRootless(ExecutorProcessBoundary|ConcurrentExecutorWorkers)$' ;;
    *) block 'unsupported rootless test suite' ;;
esac
go test -tags=integration -v ./internal/routing -run "$test_filter" -count=1 2>&1 | tee "$evidence/go-test.log"
