#!/usr/bin/env python3
"""SDCP video stream test: Cmd 386 Enable -> RTSP URL -> ffprobe -> frame capture.
Optionally disables the stream again when DISABLE=1."""
import base64, json, os, socket, struct, subprocess, sys, time, uuid

HOST = "192.168.15.13"; PORT = 3030; PATH = "/websocket"; MBID = "d86e1f35184b0100"
DISABLE_AFTER = len(sys.argv) > 1 and sys.argv[1] == "disable"


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
    return buf.split(b"\r\n\r\n", 1)[1]


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
        if opcode in (0x1, 0x2): return opcode, payload, buf
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
        try: _, data, _ = ws_recv(sock)
        except socket.timeout: break
        except (RuntimeError, ConnectionError) as e:
            print(f"conn ended: {e}"); return None
        try: msg = json.loads(data)
        except Exception: continue
        d = msg.get("Data", {})
        if d.get("Cmd") == 386 and isinstance(d.get("Data"), dict):
            print(f"cmd386 Ack={d['Data'].get('Ack')} VideoUrl={d['Data'].get('VideoUrl')!r}")
            return d["Data"]
    print("cmd386: no response")
    return None


def main():
    sock = socket.create_connection((HOST, PORT), timeout=5); sock.settimeout(5)
    ws_handshake(sock)
    print("== Cmd 386: enable video stream ==")
    r = cmd386(sock, True)
    if not r:
        return
    url = r.get("VideoUrl", "")
    ack = r.get("Ack")
    if ack != 0 or not url:
        print(f"stream not available (ack={ack})")
        return
    with open("/tmp/opencode/rtsp_url.txt", "w") as f:
        f.write(url)
    print(f"\nRTSP URL: {url}\n")

    print("== ffprobe (rtsp over tcp) ==")
    p = subprocess.run(["ffprobe", "-v", "error", "-rtsp_transport", "tcp",
                        "-timeout", "8000000", "-i", url,
                        "-show_entries", "stream=codec_name,codec_type,width,height,avg_frame_rate",
                        "-of", "json"], capture_output=True, text=True, timeout=30)
    print(p.stdout or p.stderr)

    print("== frame capture ==")
    p = subprocess.run(["ffmpeg", "-y", "-v", "error", "-rtsp_transport", "tcp",
                        "-i", url, "-frames:v", "1", "/tmp/opencode/camera_frame.png"],
                       capture_output=True, text=True, timeout=30)
    print(p.stderr or "ffmpeg silent = OK")
    if os.path.exists("/tmp/opencode/camera_frame.png"):
        print(f"frame saved: {os.path.getsize('/tmp/opencode/camera_frame.png')} bytes")

    if DISABLE_AFTER:
        print("== Cmd 386: disable video stream ==")
        cmd386(sock, False)


if __name__ == "__main__":
    main()
