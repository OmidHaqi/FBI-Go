"""Isolated M2 lab sender. Each socket represents a new flow."""
import concurrent.futures
import socket
import sys
import time

proto, prefix, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
mark = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0
destination = ("203.0.113.7", 49494)
udp_port_base = {"weighted": 20000, "foreign": 21000,
                 "disabled": 22000, "recovered": 23000,
                 "cg-a-udp": 26000, "cg-b-udp": 27000,
                 "unmanaged": 28000, "unmanaged-b-down": 29000,
                 "recovered-b": 30000, "recovered-a": 31000,
                 "b-while-a-down": 32000}


def send(index):
    flow = f"{prefix}-{index:04d}"
    kind = socket.SOCK_STREAM if proto.startswith("tcp") else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.settimeout(4)
        if mark:
            sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
        if proto.startswith("tcp"):
            sock.connect(destination)
            repeats = 3 if proto == "tcp_affinity" else 1
            for _ in range(repeats):
                sock.sendall((flow + "\n").encode())
                reply = b""
                while not reply.endswith(b"\n"):
                    chunk = sock.recv(16)
                    if not chunk:
                        break
                    reply += chunk
                if reply != b"ok\n":
                    raise RuntimeError(f"no acknowledgement for {flow}")
        else:
            sock.bind(("0.0.0.0", udp_port_base.get(prefix, 25000) + index))
            for _ in range(3):
                sock.sendto(flow.encode(), destination)
            time.sleep(0.001)


if proto.startswith("tcp"):
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(send, range(count)))
else:
    for i in range(count):
        send(i)
