"""Child-process and packet test for an FBI-Go managed application namespace."""
import json
import os
import socket
import subprocess
import sys

prefix = sys.argv[1]
identity_file = sys.argv[2]
expected_uid = int(os.environ["FBI_GO_CALLER_UID"])
expected_gid = int(os.environ["FBI_GO_CALLER_GID"]) or expected_uid
if os.geteuid() == 0:
    raise RuntimeError("managed target must not run as UID 0")

with open("/proc/self/stat", encoding="utf-8") as stat_file:
    stat_fields = stat_file.read().rsplit(")", 1)[1].split()
with open("/proc/self/status", encoding="utf-8") as status_file:
    status = dict(line.split(":", 1) for line in status_file if ":" in line)
identity = {"id": prefix, "pid": os.getpid(), "start_ticks": int(stat_fields[19]),
            "uid": os.geteuid(), "gid": os.getegid(),
            "cap_eff": int(status["CapEff"].strip(), 16),
            "uid_map": open("/proc/self/uid_map", encoding="utf-8").read().strip(),
            "gid_map": open("/proc/self/gid_map", encoding="utf-8").read().strip(),
            "setgroups": open("/proc/self/setgroups", encoding="utf-8").read().strip(),
            "network_namespace": os.stat("/proc/self/ns/net").st_ino,
            "user_namespace": os.stat("/proc/self/ns/user").st_ino}
if (identity["uid"] != expected_uid or identity["gid"] != expected_gid or
        identity["cap_eff"] != 0 or identity["setgroups"] != "deny" or
        identity["uid_map"].split() != [str(expected_uid), "0", "1"] or
        identity["gid_map"].split() != [str(expected_gid), "0", "1"]):
    raise RuntimeError("invalid managed identity after exec: " + repr(identity))
with open(identity_file, "x", encoding="utf-8") as output:
    json.dump(identity, output)

if len(sys.argv) > 3 and sys.argv[3] == "--identity-child":
    sys.exit(0)

subprocess.check_call([sys.executable, __file__, prefix + "-child", identity_file + ".child",
                       "--identity-child"])
route_attempt = subprocess.run(["ip", "-4", "route", "add", "table", "31998",
                                "blackhole", "198.18.0.0/16"], capture_output=True, text=True)
if route_attempt.returncode == 0 or "Operation not permitted" not in route_attempt.stderr:
    raise RuntimeError("managed route mutation was not denied by capabilities: " +
                       route_attempt.stderr)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto((prefix + "-parent").encode(), ("203.0.113.7", 49494))

client = os.path.join(os.path.dirname(__file__), "flow_client.py")
for proto in ("tcp_affinity", "udp"):
    subprocess.check_call([sys.executable, client, proto, prefix + "-" + proto, "8"])
