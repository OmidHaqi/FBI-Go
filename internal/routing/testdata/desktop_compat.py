#!/usr/bin/env python3
"""Controlled namespace compatibility service; no external network access."""
import json
import os
import select
import socket
import sys


def server(ready_path, socket_path, abstract_name):
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen(4)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.53", 0))
    file_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    file_socket.bind(socket_path)
    file_socket.listen(4)
    abstract_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abstract_socket.bind("\0" + abstract_name)
    abstract_socket.listen(4)
    with open(ready_path, "x", encoding="utf-8") as output:
        json.dump({"tcp_port": tcp.getsockname()[1], "udp_port": udp.getsockname()[1]}, output)
    while True:
        readable, _, _ = select.select([tcp, udp, file_socket, abstract_socket], [], [], 1)
        for listener in readable:
            if listener is udp:
                payload, address = udp.recvfrom(512)
                if payload:
                    udp.sendto(b"probe-response", address)
            else:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(1)
                    if connection.recv(32):
                        connection.sendall(b"probe-response")


def client(kind, address, port="0"):
    try:
        if kind == "tcp":
            conn = socket.create_connection((address, int(port)), timeout=0.25)
        elif kind == "udp":
            conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            conn.settimeout(0.25)
            conn.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07fixture\x07invalid\x00\x00\x01\x00\x01", (address, int(port)))
            response, _ = conn.recvfrom(512)
            print(json.dumps({"connected": response == b"probe-response"}))
            return
        elif kind in ("unix-file", "unix-abstract"):
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(0.25)
            conn.connect(("\0" if kind == "unix-abstract" else "") + address)
        else:
            raise ValueError("unknown probe")
        with conn:
            conn.sendall(b"probe")
            print(json.dumps({"connected": conn.recv(32) == b"probe-response"}))
    except (OSError, TimeoutError):
        print(json.dumps({"connected": False}))


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(*sys.argv[2:5])
    else:
        client(*sys.argv[1:])
