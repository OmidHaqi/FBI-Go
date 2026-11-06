"""Isolated M2 lab receiver; never used against the host network."""
import json
import socket
import sys
import threading
import time

address, port, logfile = sys.argv[1], int(sys.argv[2]), sys.argv[3]
lock = threading.Lock()


def record(item):
    with lock:
        with open(logfile, "a", encoding="utf-8") as output:
            output.write(json.dumps(item, sort_keys=True) + "\n")


def handle_tcp(conn, peer):
    start = time.monotonic_ns()
    with conn:
        conn.settimeout(3)
        stream = conn.makefile("rb")
        for data in stream:
            time.sleep(0.12)
            conn.sendall(b"ok\n")
            record({"proto": "tcp", "flow": data.decode().strip(), "source": peer[0],
                    "port": peer[1], "start_ns": start, "end_ns": time.monotonic_ns()})


udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind((address, port))
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp.bind((address, port))
tcp.listen(128)
open(logfile, "w", encoding="utf-8").close()


def udp_loop():
    while True:
        data, peer = udp.recvfrom(256)
        record({"proto": "udp", "flow": data.decode(), "source": peer[0],
                "port": peer[1], "start_ns": time.monotonic_ns()})


threading.Thread(target=udp_loop, daemon=True).start()
while True:
    conn, peer = tcp.accept()
    threading.Thread(target=handle_tcp, args=(conn, peer), daemon=True).start()
