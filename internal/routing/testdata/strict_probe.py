"""Return success only when an explicitly marked TCP connection fails closed."""
import socket
import sys

mark = int(sys.argv[1], 0)
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(2)
    sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), mark)
    try:
        sock.connect(("203.0.113.7", 49494))
    except OSError as exc:
        print(f"PASS: marked TCP flow failed closed: {exc}")
        sys.exit(0)
    sock.sendall(b"strict-leak\n")
    print("FAIL: marked flow reached a destination after pinned WAN route removal")
    sys.exit(1)
