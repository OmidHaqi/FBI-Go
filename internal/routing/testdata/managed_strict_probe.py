"""Fail if an unmarked managed TCP/UDP flow escapes a missing pinned WAN."""
import socket

destination = ("203.0.113.7", 49494)
for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(1)
        try:
            if kind == socket.SOCK_STREAM:
                sock.connect(destination)
                sock.sendall(b"managed-strict-leak\n")
                sock.recv(16)
            else:
                sock.sendto(b"managed-strict-leak", destination)
                # UDP send may succeed before an ICMP error is delivered.
                sock.recvfrom(16)
        except (OSError, TimeoutError):
            continue
        raise RuntimeError("STRICT managed flow reached a destination")
