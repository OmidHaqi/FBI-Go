#!/usr/bin/env python3
"""Synthetic DNS and HTTP receiver for owned namespace integration tests."""

import http.server
import ipaddress
import json
import socketserver
import struct
import sys
import threading


address, log_path, wan = sys.argv[1:4]
lock = threading.Lock()


def record(**fields):
    with lock:
        with open(log_path, "a", encoding="utf-8") as output:
            output.write(json.dumps({"wan": wan, **fields}, sort_keys=True) + "\n")


def answer(payload, peer, protocol):
    if len(payload) < 17:
        return b""
    offset = 12
    labels = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(payload):
            return b""
        labels.append(payload[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(payload):
        return b""
    qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
    question = payload[12:offset + 4]
    name = ".".join(labels).lower()
    result = b""
    if name in {"service.lab.test", "service.lab.test."} and qclass == 1:
        if qtype == 1:
            result = ipaddress.IPv4Address(address).packed
        elif qtype == 28:
            result = ipaddress.IPv6Address("2001:db8:100::7").packed
    record(protocol=protocol, source=peer[0], source_port=peer[1],
           query=name, qtype=qtype, transaction=payload[:2].hex(),
           answered=bool(result))
    header = payload[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(result)), 0, 0)
    if not result:
        return header + question
    rr = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(result)) + result
    return header + question + rr


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        reply = answer(data, self.client_address, "dns_udp")
        if reply:
            sock.sendto(reply, self.client_address)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        head = self.request.recv(2)
        if len(head) != 2:
            return
        length = struct.unpack("!H", head)[0]
        data = bytearray()
        while len(data) < length:
            part = self.request.recv(length - len(data))
            if not part:
                return
            data.extend(part)
        reply = answer(bytes(data), self.client_address, "dns_tcp")
        if reply:
            self.request.sendall(struct.pack("!H", len(reply)) + reply)


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        record(protocol="http_tcp", source=self.client_address[0],
               source_port=self.client_address[1], path=self.path)
        body = b"fbi-go-test-ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ThreadedHTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True


servers = [ThreadedUDP((address, 53), UDP), ThreadedTCP((address, 53), TCP),
           ThreadedHTTP((address, 8080), HTTP)]
open(log_path, "a", encoding="utf-8").close()
for server in servers[:-1]:
    threading.Thread(target=server.serve_forever, daemon=True).start()
servers[-1].serve_forever()
