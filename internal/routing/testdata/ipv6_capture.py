#!/usr/bin/env python3
"""Observe IPv6 TCP/UDP frames on one synthetic gateway veth."""

import ipaddress
import json
import os
import socket
import sys

interface, log_path, ready_path = sys.argv[1:4]
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
sock.bind((interface, 0))
open(log_path, "a", encoding="utf-8").close()
open(ready_path, "w", encoding="utf-8").write(str(os.getpid()))
while True:
    frame = sock.recv(65535)
    if len(frame) < 54 or frame[12:14] != b"\x86\xdd":
        continue
    ip = frame[14:]
    if ip[6] not in (6, 17):
        continue
    record = {
        "protocol": "tcp" if ip[6] == 6 else "udp",
        "source": str(ipaddress.IPv6Address(ip[8:24])),
        "destination": str(ipaddress.IPv6Address(ip[24:40])),
        "interface": interface,
    }
    with open(log_path, "a", encoding="utf-8") as out:
        out.write(json.dumps(record, sort_keys=True) + "\n")
