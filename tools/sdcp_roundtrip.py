#!/usr/bin/env python3
"""SDCP live tests vs Saturn 4 Ultra (192.168.15.13):
  1. Command path: Pause (129) / Stop (130) while idle -> expect Acks
  2. File round-trip: probe download endpoints; upload (chunked) -> verify in
     file list (Cmd 258) -> delete (Cmd 259) -> verify gone.
Never starts a print."""
import base64, hashlib, http.client, json, os, socket, struct, time, uuid

HOST = "192.168.15.13"
PORT = 3030
PATH = "/websocket"
MBID = "d86e1f35184b0100"
TEST_NAME = "_sdcp_roundtrip_test.goo"


# ---------- WebSocket helpers ----------
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
    if "101" not in status:
        raise RuntimeError(f"handshake refused: {status}")
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


def send_cmd_expect_ack(sock, cmd, payload, label, timeout=8):
    ws_send(sock, envelope(cmd, payload).encode())
    end = time.time() + timeout
    while time.time() < end:
        sock.settimeout(max(0.2, end - time.time()))
        try:
            _, data, _ = ws_recv(sock)
        except socket.timeout:
            break
        except (RuntimeError, ConnectionError) as e:
            print(f"  [{label}] connection ended: {e}")
            return None
        try:
            msg = json.loads(data)
        except Exception:
            continue
        d = msg.get("Data", {})
        if d.get("Cmd") == cmd and isinstance(d.get("Data"), dict) and "Ack" in d["Data"]:
            ack = d["Data"]["Ack"]
            print(f"  [{label}] Ack={ack}")
            return ack
        topic = msg.get("Topic", "?")
        if topic.startswith(("sdcp/status", "sdcp/attributes")):
            print(f"  [{label}] (async push: {topic})")
    print(f"  [{label}] no Ack within {timeout}s")
    return None


def get_file_list(sock, timeout=8):
    ws_send(sock, envelope(258, '{"Url":"/local/"}').encode())
    end = time.time() + timeout
    while time.time() < end:
        sock.settimeout(max(0.2, end - time.time()))
        try:
            _, data, _ = ws_recv(sock)
        except socket.timeout:
            return None
        except (RuntimeError, ConnectionError) as e:
            print(f"  [list] connection ended: {e}"); return None
        try:
            msg = json.loads(data)
        except Exception:
            continue
        d = msg.get("Data", {})
        if d.get("Cmd") == 258 and isinstance(d.get("Data"), dict):
            return d["Data"].get("FileList", [])
    return None


def delete_files(sock, file_paths, timeout=8):
    payload = json.dumps({"FileList": file_paths, "FolderList": []})
    return send_cmd_expect_ack(sock, 259, payload, "cmd259-delete")


# ---------- HTTP helpers ----------
def http_get(path, port=3030, timeout=10):
    c = http.client.HTTPConnection(HOST, port, timeout=timeout)
    c.request("GET", path, headers={"Host": f"{HOST}:{port}", "User-Agent": "ElegooSlicer"})
    r = c.getresponse(); body = r.read(); c.close()
    return r.status, dict(r.getheaders()), body


def multipart_upload(data: bytes, remote_name: str, chunk_size=1024 * 1024):
    md5 = hashlib.md5(data).hexdigest()
    uid = uuid.uuid4().hex
    total = len(data)
    n_chunks = (total + chunk_size - 1) // chunk_size
    print(f"  uploading {total}B as '{remote_name}' in {n_chunks} chunk(s), md5={md5}")
    for i, off in enumerate(range(0, total, chunk_size), 1):
        chunk = data[off:off + chunk_size]
        boundary = uuid.uuid4().hex
        parts = []
        for k, v in [("Check", "1"), ("S-File-MD5", md5), ("Offset", str(off)),
                     ("Uuid", uid), ("TotalSize", str(total))]:
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="File"; filename="{remote_name}"\r\n'
                      "Content-Type: application/octet-stream\r\n\r\n").encode() + chunk + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        c = http.client.HTTPConnection(HOST, PORT, timeout=60)
        c.request("POST", "/uploadFile/upload", body=body, headers={
            "Host": f"{HOST}:{PORT}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
            "User-Agent": "ElegooSlicer"})
        r = c.getresponse(); rb = r.read(); c.close()
        ok = r.status == 200 and b"000000" in rb
        print(f"  chunk {i}/{n_chunks} offset={off} len={len(chunk)} -> HTTP {r.status} "
              f"{'OK' if ok else 'FAIL'}: {rb[:160].decode(errors='replace')}")
        if not ok:
            return False
    return True


# ---------- main ----------
def main():
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.settimeout(5)
    ws_handshake(sock)
    print("WS connected\n")

    print("== TEST 1: command path (idle) ==")
    a1 = send_cmd_expect_ack(sock, 129, "{}", "cmd129-pause")
    a2 = send_cmd_expect_ack(sock, 130, "{}", "cmd130-stop")
    print(f"TEST1 result: pause Ack={a1}, stop Ack={a2}\n")

    print("== TEST 2a: probe download endpoints ==")
    data = None
    candidates = ["/download?url=/local//jc.goo", "/download?url=/local/jc.goo",
                  "/download?filename=/local//jc.goo", "/api/files"]
    for cand, port in [(c, 3030) for c in candidates] + [("/download?url=/local//jc.goo", 80)]:
        try:
            status, headers, body = http_get(cand, port)
            head = body[:80]
            print(f"  GET {cand} (:{port}) -> {status}, {len(body)}B, head={head!r}")
            if status == 200 and len(body) > 100 and not body.lstrip().startswith(b"{"):
                data = body
                print(f"  -> looks like file content, using it ({len(body)}B)")
                break
        except Exception as e:
            print(f"  GET {cand} (:{port}) -> error: {e}")

    if data is not None:
        remote_name = "_sdcp_roundtrip_src.goo"
        print(f"== TEST 2b: re-upload downloaded bytes as '{remote_name}' ==")
        src_md5 = hashlib.md5(data).hexdigest()
        up_ok = multipart_upload(data, remote_name)
    else:
        print("  no download endpoint available -> synthetic payload (2 chunks to exercise Offset)")
        data = os.urandom(1_500_000)
        remote_name = TEST_NAME
        up_ok = multipart_upload(data, remote_name)

    if not up_ok:
        print("UPLOAD FAILED - aborting round-trip")
        return

    print("== TEST 2c: verify in file list (Cmd 258) ==")
    fl = get_file_list(sock)
    if fl is None:
        print("  no file list response!")
        return
    names = [e.get("name", "") for e in fl]
    hit = [n for n in names if remote_name in n]
    print(f"  {len(names)} files on /local/, test file present: {bool(hit)} -> {hit}")
    if not hit:
        print("  test file NOT in list - aborting before delete")
        return
    listed_path = hit[0]

    if data is not None and remote_name == "_sdcp_roundtrip_src.goo":
        print("== TEST 2d: re-download test file & MD5 compare ==")
        for cand in [f"/download?url={listed_path}", f"/download?url=/local/{remote_name}"]:
            try:
                status, headers, body = http_get(cand)
                print(f"  GET {cand} -> {status}, {len(body)}B")
                if status == 200 and len(body) == len(data):
                    md5 = hashlib.md5(body).hexdigest()
                    print(f"  md5 downloaded={md5} original={src_md5} MATCH={md5 == src_md5}")
                    break
            except Exception as e:
                print(f"  GET {cand} -> error: {e}")

    print("== TEST 2e: delete test file (Cmd 259) ==")
    ack = delete_files(sock, [listed_path])
    fl2 = get_file_list(sock)
    names2 = [e.get("name", "") for e in (fl2 or [])]
    gone = not any(remote_name in n for n in names2)
    print(f"  delete Ack={ack}, file gone afterwards: {gone}")
    print(f"\nROUND-TRIP: upload={'OK' if up_ok else 'FAIL'}, listed={bool(hit)}, deleted={gone}")


if __name__ == "__main__":
    main()
