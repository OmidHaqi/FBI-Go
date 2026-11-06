"""Test-only managed child: wait until both applications and workers are ready."""
import json
import os
import pathlib
import subprocess
import sys
import time

ready, signal, flow = map(pathlib.Path, sys.argv[1:4])
curl = sys.argv[4]
ready.write_text(json.dumps({"pid": os.getpid(), "uid": os.geteuid(),
                             "netns": os.readlink("/proc/self/ns/net")}) + "\n")
deadline = time.monotonic() + 20
while not signal.exists():
    if time.monotonic() > deadline:
        raise TimeoutError("concurrent application release missing")
    time.sleep(0.02)
for proto in ("tcp_affinity", "udp"):
    subprocess.run([sys.executable, str(flow), proto, "concurrent-" + proto, "4"],
                   check=True)
subprocess.run([curl, "--noproxy", "*", "--max-time", "5", "--fail", "--silent",
                "http://service.lab.test:8080/"], check=True)
