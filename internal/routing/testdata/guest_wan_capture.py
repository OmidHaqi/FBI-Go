#!/usr/bin/env python3
"""Test-only AF_PACKET observation at an owned synthetic interface."""

import json
import errno
import subprocess
import socket
import struct
import sys
import time


interface, output_path, ready_path, stage = sys.argv[1:5]
def open_capture():
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    capture.bind((interface, 0))
    capture.settimeout(0.05)
    return capture


def carrier_up():
    links = json.loads(subprocess.check_output(
        ["ip", "-j", "link", "show", "dev", interface], stderr=subprocess.DEVNULL))
    if len(links) != 1:
        raise RuntimeError("owned capture interface disappeared")
    link = links[0]
    # A bridged veth can retain LOWER_UP while its peer reports no carrier.
    # Match the kernel's operstate rather than relying on this flag alone.
    return ("UP" in link.get("flags", []) and
            "NO-CARRIER" not in link.get("flags", []) and
            link.get("operstate", "").lower() not in
            {"down", "lowerlayerdown", "dormant", "notpresent", "testing"} and
            "LOWER_UP" in link.get("flags", []))


sock = open_capture()
with open(output_path, "w", encoding="utf-8", buffering=1) as output:
    with open(ready_path, "x", encoding="utf-8") as ready:
        ready.write("ready\n")
    last_carrier = carrier_up()
    next_check = 0.0
    while True:
        if time.monotonic() >= next_check:
            current_carrier = carrier_up()
            if current_carrier != last_carrier:
                if sock is not None:
                    sock.close()
                sock = open_capture() if current_carrier else None
                last_carrier = current_carrier
                output.write(json.dumps({"stage": stage, "interface": interface,
                                         "event": "carrier_up" if current_carrier else "carrier_down",
                                         "time_ns": time.monotonic_ns()}) + "\n")
            next_check = time.monotonic() + 0.05
        if sock is None:
            time.sleep(0.05)
            continue
        try:
            frame, address = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError as exc:
            if exc.errno != errno.ENETDOWN:
                raise
            # Keep observing the same owned interface across a transient
            # administrative link-down event.
            output.write(json.dumps({"stage": stage, "interface": interface,
                                     "event": "carrier_down", "time_ns": time.monotonic_ns()}) + "\n")
            sock.close()
            sock = None
            last_carrier = False
            continue
        if len(frame) < 34:
            continue
        ethernet_type = struct.unpack_from("!H", frame, 12)[0]
        if ethernet_type == 0x86DD:
            row = {"stage": stage, "interface": interface, "family": "ipv6", "time_ns": time.monotonic_ns()}
        elif ethernet_type == 0x0800:
            header = frame[14:]
            ihl = (header[0] & 0x0F) * 4
            if ihl < 20 or len(header) < ihl + 4:
                continue
            protocol = {6: "tcp", 17: "udp"}.get(header[9])
            if protocol is None:
                continue
            sport, dport = struct.unpack_from("!HH", header, ihl)
            row = {
                "stage": stage,
                "interface": interface,
                "family": "ipv4",
                "protocol": protocol,
                "source": socket.inet_ntoa(header[12:16]),
                "destination": socket.inet_ntoa(header[16:20]),
                "source_port": sport,
                "destination_port": dport,
                "time_ns": time.monotonic_ns(),
                "packet_type": address[2],
            }
        else:
            continue
        output.write(json.dumps(row, separators=(",", ":")) + "\n")
