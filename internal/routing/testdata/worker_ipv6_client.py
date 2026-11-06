"""Attempt external IPv6 TCP/UDP only after a test-owned route is installed."""
import json
import os
import socket
import sys
import time

ready, signal, result = sys.argv[1:4]
with open(ready, "x", encoding="utf-8") as output:
    output.write(str(os.getpid()))
deadline = time.monotonic() + 5
while not os.path.exists(signal):
    if time.monotonic() > deadline:
        raise RuntimeError("test route-change signal missing")
    time.sleep(0.01)

observations = []
for protocol, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
    with socket.socket(socket.AF_INET6, kind) as sock:
        sock.settimeout(0.3)
        try:
            if protocol == "tcp":
                sock.connect(("2001:db8:300::7", 8080))
            else:
                sock.sendto(b"forbidden-ipv6", ("2001:db8:300::7", 8080))
            outcome = "sent"
        except OSError as exc:
            outcome = type(exc).__name__
        observations.append({"protocol": protocol, "outcome": outcome})
with open(result, "x", encoding="utf-8") as output:
    json.dump(observations, output)
