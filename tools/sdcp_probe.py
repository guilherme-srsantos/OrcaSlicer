#!/usr/bin/env python3
"""Minimal SDCP probe: raw WebSocket client -> ws://IP:3030/websocket.

Sequence: TCP connect -> WS handshake -> "ping" (expect "pong") ->
Cmd 0 status request -> Cmd 1 attributes request. Prints everything raw.
"""
import base64
import json
import os
import socket
import struct
import sys
import time
import uuid

HOST = sys.argv[1] if len(sys.argv) > 1 else "192.168.15.13"
PORT = 3030
PATH = "/websocket"


def ws_handshake(sock):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: ElegooSlicer\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    # read until end of headers
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during handshake")
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
    status = head.splitlines()[0]
    print(f"handshake: {status}")
    if "101" not in status:
        raise RuntimeError(f"handshake refused:\n{head}")
    return buf.split(b"\r\n\r\n", 1)[1]  # any leftover frame bytes


def ws_send(sock, payload: bytes, opcode=1):
    # client frames MUST be masked
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
    """Return one complete message (opcode, bytes). Handles fragmentation minimally."""
    buf = leftover
    while True:
        while len(buf) < 2:
            buf += sock.recv(4096)
        b1, b2 = buf[0], buf[1]
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        length = b2 & 0x7F
        idx = 2
        if length == 126:
            while len(buf) < idx + 2:
                buf += sock.recv(4096)
            length = struct.unpack(">H", buf[idx:idx + 2])[0]
            idx += 2
        elif length == 127:
            while len(buf) < idx + 8:
                buf += sock.recv(4096)
            length = struct.unpack(">Q", buf[idx:idx + 8])[0]
            idx += 8
        if masked:
            while len(buf) < idx + 4:
                buf += sock.recv(4096)
            mask = buf[idx:idx + 4]
            idx += 4
        while len(buf) < idx + length:
            buf += sock.recv(4096)
        payload = buf[idx:idx + length]
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        buf = buf[idx + length:]
        if opcode == 0x9:  # ping from server -> pong back
            ws_send(sock, payload, opcode=0xA)
            continue
        if opcode == 0xA:  # pong
            continue
        if opcode in (0x1, 0x2):  # text/binary
            return opcode, payload, buf
        if opcode == 0x8:  # close
            raise RuntimeError("server sent close frame")


def envelope(cmd, payload="{}", mainboard_id=""):
    rid = uuid.uuid4().hex
    return json.dumps({
        "Id": uuid.uuid4().hex,
        "Data": {
            "Cmd": cmd,
            "Data": json.loads(payload),
            "RequestID": rid,
            "MainboardID": mainboard_id,
            "TimeStamp": int(time.time()),
            "From": 0,
        },
        "Topic": f"sdcp/request/{mainboard_id}",
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
            print(f"  [{label}] connection ended: {e}")
            return False
        got = True
        print(f"  [{label}] RECV: {data.decode(errors='replace')[:1500]}")
    if not got:
        print(f"  [{label}] (no messages in {seconds}s)")
    return True


def main():
    # 1. TCP reachability
    print(f"== connecting tcp://{HOST}:{PORT} ==")
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(5)
    print("tcp connect: OK")
    # 2. WS handshake
    leftover = ws_handshake(sock)
    # 3. heartbeat
    print("== sending 'ping' (expect 'pong') ==")
    ws_send(sock, b"ping")
    drain(sock, 3, "ping")
    # 4. status request Cmd 0
    print("== Cmd 0 (status refresh) ==")
    ws_send(sock, envelope(0).encode())
    drain(sock, 4, "cmd0")
    # 5. attributes request Cmd 1
    print("== Cmd 1 (attributes) ==")
    ws_send(sock, envelope(1).encode())
    drain(sock, 4, "cmd1")


if __name__ == "__main__":
    main()
