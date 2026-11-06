#!/usr/bin/env python3
"""Attempt forbidden IPv6 flows after the test controller changes routes."""

import json
import os
import socket
import sys
import time

ready, signal, result = sys.argv[1:4]
open(ready, "w", encoding="utf-8").write(str(os.getpid()))
deadline = time.monotonic() + 5
while not os.path.exists(signal):
    if time.monotonic() > deadline:
        raise RuntimeError("route-change signal missing")
    time.sleep(0.01)

observations = []
for target in ("2001:db8:300::7", "service.lab.test"):
    if target.startswith("service"):
        addresses = socket.getaddrinfo(target, 8080, socket.AF_INET6, socket.SOCK_STREAM)
        address = addresses[0][4][0]
    else:
        address = target
    for protocol in ("tcp", "udp"):
        kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET6, kind) as conn:
            conn.settimeout(0.3)
            try:
                if protocol == "tcp":
                    conn.connect((address, 8080))
                else:
                    conn.sendto(b"forbidden-ipv6", (address, 8080))
                outcome = "sent"
            except OSError as exc:
                outcome = type(exc).__name__
        observations.append({"protocol": protocol, "destination": address, "outcome": outcome})
with open(result, "w", encoding="utf-8") as out:
    json.dump(observations, out)
