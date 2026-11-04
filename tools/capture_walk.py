#!/usr/bin/env python3
"""Countdown -> clean enable -> 60s error-concealing recording -> clean disable."""
import socket
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/opencode")
from record_video import ws_handshake, cmd386, HOST, PORT  # noqa: E402

OUT = "/tmp/opencode/camera_walk5.mp4"

# 0. kill any zombie RTSP clients from the aborted run (they wedge the camera server)
z = subprocess.run(["pkill", "-f", "rtsp://192.168.15.13"], capture_output=True)
if z.returncode == 0:
    print("killed leftover rtsp client(s)")
    time.sleep(2)

# 1. countdown - user walks to the printer
print("WALK TO THE PRINTER NOW - recording starts in 45 seconds!", flush=True)
for i in range(45, 0, -1):
    print(f"  {i}...", flush=True)
    time.sleep(1)
print("RECORDING!", flush=True)

# 2. clean enable (retry via disable if a stream slot is stuck)
s = socket.create_connection((HOST, PORT), timeout=5)
s.settimeout(5)
ws_handshake(s)
r = cmd386(s, True)
if not r or r.get("Ack") != 0:
    print(f"enable -> {r}; attempting disable/retry")
    cmd386(s, False)
    time.sleep(3)
    r = cmd386(s, True)
print(f"enable: {r}")
if not r or r.get("Ack") != 0:
    print("cannot start stream"); sys.exit(1)

# 3. record 60s, transcoding with error concealment (UDP loss tolerant)
p = subprocess.run(["ffmpeg", "-y", "-v", "warning", "-rtsp_transport", "udp",
                    "-i", "rtsp://192.168.15.13:554/video", "-t", "90",
                    "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                    "-pix_fmt", "yuv420p", OUT],
                   capture_output=True, text=True, timeout=150)
warn = [l for l in p.stderr.splitlines() if "error" in l.lower() or "lost" in l.lower()]
print(f"ffmpeg warnings: {len(warn)}")
for l in warn[:5]:
    print("  ", l[:140])

# 4. clean disable + close
print("disable:", cmd386(s, False))
s.close()

import os  # noqa: E402
sz = os.path.getsize(OUT) if os.path.exists(OUT) else 0
print(f"file: {sz} bytes")