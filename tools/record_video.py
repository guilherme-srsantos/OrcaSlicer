#!/usr/bin/env python3
"""App-faithful camera recording: SDCP session -> enable stream -> record
N seconds -> disable -> close. No killed clients, clean TEARDOWN always."""
import base64, json, os, socket, struct, subprocess, sys, time, uuid

HOST = "192.168.15.13"; PORT = 3030; PATH = "/websocket"; MBID = "d86e1f35184b0100"
URL = f"rtsp://{HOST}:554/video"
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 45
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/opencode/camera_walk.mp4"


def ws_handshake(sock):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           "Sec-WebSocket-Version: 13\r\nUser-Agent: ElegooSlicer\r\n\r\n")
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        buf += sock.recv(4096)
    if "101" not in buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace").splitlines()[0]:
        raise RuntimeError("handshake refused")


def ws_send(sock, payload: bytes, opcode=1):
    mask = os.urandom(4)
    header = bytes([0x80 | opcode]); n = len(payload)
    if n < 126: header += bytes([0x80 | n])
    elif n < 65536: header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else: header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + mask + masked)


def ws_recv(sock, leftover=b""):
    buf = leftover
    while True:
        while len(buf) < 2: buf += sock.recv(4096)
        b1, b2 = buf[0], buf[1]
        opcode, masked, length, idx = b1 & 0x0F, bool(b2 & 0x80), b2 & 0x7F, 2
        if length == 126:
            while len(buf) < idx + 2: buf += sock.recv(4096)
            length = struct.unpack(">H", buf[idx:idx + 2])[0]; idx += 2
        elif length == 127:
            while len(buf) < idx + 8: buf += sock.recv(4096)
            length = struct.unpack(">Q", buf[idx:idx + 8])[0]; idx += 8
        mask = b""
        if masked:
            while len(buf) < idx + 4: buf += sock.recv(4096)
            mask = buf[idx:idx + 4]; idx += 4
        while len(buf) < idx + length: buf += sock.recv(4096)
        payload = buf[idx:idx + length]
        if masked: payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        buf = buf[idx + length:]
        if opcode == 0x9: ws_send(sock, payload, opcode=0xA); continue
        if opcode == 0xA: continue
        if opcode in (0x1, 0x2): return payload, buf
        if opcode == 0x8: raise RuntimeError("server closed")


def envelope(cmd, payload="{}", mbid=MBID):
    return json.dumps({"Id": uuid.uuid4().hex,
        "Data": {"Cmd": cmd, "Data": json.loads(payload), "RequestID": uuid.uuid4().hex,
                 "MainboardID": mbid, "TimeStamp": int(time.time()), "From": 0},
        "Topic": f"sdcp/request/{mbid}"})


def cmd386(sock, enable, seconds=8):
    ws_send(sock, envelope(386, json.dumps({"Enable": 1 if enable else 0})).encode())
    end = time.time() + seconds
    while time.time() < end:
        sock.settimeout(max(0.2, end - time.time()))
        try: data, _ = ws_recv(sock)
        except socket.timeout: return None
        try: msg = json.loads(data)
        except Exception: continue
        d = msg.get("Data", {})
        if d.get("Cmd") == 386 and isinstance(d.get("Data"), dict):
            return d["Data"]
    return None


def main():
    sock = socket.create_connection((HOST, PORT), timeout=5); sock.settimeout(5)
    ws_handshake(sock)
    r = cmd386(sock, True)
    print(f"enable: {r}")
    if not r or r.get("Ack") != 0:
        print("cannot start stream"); return 1

    print(f"RECORDING {DURATION}s -> {OUT}")
    p = subprocess.Popen(["ffmpeg", "-y", "-v", "info", "-i", URL, "-t", str(DURATION),
                          "-c", "copy", "-movflags", "+faststart", OUT],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while p.poll() is None:
            time.sleep(15)
            try:
                ws_send(sock, envelope(0, "{}").encode())
                sock.settimeout(1.0)
                try:
                    while True: ws_recv(sock)
                except socket.timeout: pass
                sock.settimeout(5)
            except Exception as e:
                print(f"keepalive: {e}"); break
    finally:
        if p.poll() is None:
            p.terminate(); p.wait(timeout=10)
        print(f"disable: {cmd386(sock, False)}")
        sock.close()

    ok = os.path.exists(OUT) and os.path.getsize(OUT) > 10000
    print(f"recording {'OK' if ok else 'FAIL'}: {os.path.getsize(OUT) if os.path.exists(OUT) else 0} bytes")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())