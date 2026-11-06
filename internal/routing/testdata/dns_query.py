#!/usr/bin/env python3
"""Exercise synthetic DNS over both transports without external dependencies."""

import socket
import struct
import sys

server, transport, kind = sys.argv[1:4]
qtype = {"A": 1, "AAAA": 28}[kind]
question = b"".join(bytes([len(part)]) + part.encode("ascii") for part in "service.lab.test".split(".")) + b"\0"
request = b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)
if transport == "udp":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(request, (server, 53))
        response, _ = sock.recvfrom(512)
else:
    with socket.create_connection((server, 53), timeout=2) as sock:
        sock.sendall(struct.pack("!H", len(request)) + request)
        size = struct.unpack("!H", sock.recv(2))[0]
        response = b""
        while len(response) < size:
            part = sock.recv(size - len(response))
            if not part:
                raise RuntimeError("DNS TCP response truncated")
            response += part
if response[:2] != request[:2] or len(response) < 12 or struct.unpack("!H", response[6:8])[0] != 1:
    raise RuntimeError("DNS response has no matching answer")
print(f"{transport} {kind} answered")
