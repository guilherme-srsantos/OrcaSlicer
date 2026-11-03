#!/usr/bin/env python3
"""SDCP probe #2: addressed requests with known MainboardID + longer drains."""
import base64
import json
import os
import socket
import struct
import sys
import time
import uuid

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.15.13"
MBID = sys.argv[2] if len(sys.argv) > 2 else "d86e1f35184b0100"
PORT = 3030
PATH = "/websocket"


def ws_handshake(sock):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           "Sec-WebSocket-Version: 13\r\nUser-Agent: ElegooSlicer\r\n\r\n")
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("closed during handshake")
        buf += chunk
    status = buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace").splitlines()[0]
    print(f"handshake: {status}")
    if "101" not in status:
        raise RuntimeError("handshake refused")
    return buf.split(b"\r\n\r\n", 1)[1]


def ws_send(sock, payload: bytes, opcode=1):
    mask = os.urandom(4)
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([0x80 | n])
    elif n < 65536:
        header += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        header += bytes([0x80 | 127]) + struct.pack(">Q", n)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(header + mask + masked)


def ws_recv(sock, leftover=b""):
    buf = leftover
    while True:
        while len(buf) < 2:
            buf += sock.recv(4096)
        b1, b2 = buf[0], buf[1]
        opcode, masked, length, idx = b1 & 0x0F, bool(b2 & 0x80), b2 & 0x7F, 2
        if length == 126:
            while len(buf) < idx + 2:
                buf += sock.recv(4096)
            length = struct.unpack(">H", buf[idx:idx + 2])[0]; idx += 2
        elif length == 127:
            while len(buf) < idx + 8:
                buf += sock.recv(4096)
            length = struct.unpack(">Q", buf[idx:idx + 8])[0]; idx += 8
        mask = b""
        if masked:
            while len(buf) < idx + 4:
                buf += sock.recv(4096)
            mask = buf[idx:idx + 4]; idx += 4
        while len(buf) < idx + length:
            buf += sock.recv(4096)
        payload = buf[idx:idx + length]
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        buf = buf[idx + length:]
        if opcode == 0x9:
            ws_send(sock, payload, opcode=0xA); continue
        if opcode == 0xA:
            continue
        if opcode in (0x1, 0x2):
            return opcode, payload, buf
        if opcode == 0x8:
            raise RuntimeError("server closed")


def envelope(cmd, payload="{}", mbid=MBID):
    return json.dumps({
        "Id": uuid.uuid4().hex,
        "Data": {"Cmd": cmd, "Data": json.loads(payload), "RequestID": uuid.uuid4().hex,
                 "MainboardID": mbid, "TimeStamp": int(time.time()), "From": 0},
        "Topic": f"sdcp/request/{mbid}",
    })


def drain(sock, seconds, label):
    end = time.time() + seconds
    got = False
    while time.time() < end:
        sock.settimeout(max(0.2, end - time.time()))
        try:
            _, data, _ = ws_recv(sock)
        except socket.timeout:
            break
        except (RuntimeError, ConnectionError) as e:
            print(f"  [{label}] connection ended: {e}"); return
        got = True
        text = data.decode(errors="replace")
        print(f"  [{label}] RECV ({len(text)}B): {text[:1200]}")
    if not got:
        print(f"  [{label}] (no messages in {seconds}s)")


def main():
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(5)
    leftover = ws_handshake(sock)
    print(f"== Cmd 0 status (MBID {MBID}) ==")
    ws_send(sock, envelope(0).encode()); drain(sock, 15, "cmd0", )
    print("== Cmd 1 attributes ==")
    ws_send(sock, envelope(1).encode()); drain(sock, 15, "cmd1")
    print("== Cmd 258 file list /local/ ==")
    ws_send(sock, envelope(258, '{"Url":"/local/"}').encode()); drain(sock, 8, "cmd258")


if __name__ == "__main__":
    main()
