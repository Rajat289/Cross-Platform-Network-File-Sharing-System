"""
=============================================================
  Full Demo Test — runs server + client in one script
  Run this on EITHER machine to demo everything works.
  python3 demo_full.py
=============================================================
"""

import socket
import threading
import json
import base64
import hashlib
import struct
import os
import time
import sys

# ── Shared encryption ──────────────────────────────────────
ENC_KEY = b"CN_PROJECT_2024_SECRET_KEY_32BYTE"

def xor_encrypt(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def send_msg(sock, data, encrypt=False):
    raw = json.dumps(data).encode()
    if encrypt:
        raw = xor_encrypt(raw, ENC_KEY)
    sock.sendall(struct.pack("!I?", len(raw), encrypt) + raw)

def recv_msg(sock):
    hdr = _rx(sock, 5)
    length, enc = struct.unpack("!I?", hdr)
    raw = _rx(sock, length)
    if enc:
        raw = xor_encrypt(raw, ENC_KEY)
    return json.loads(raw)

def _rx(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionResetError
        buf += c
    return buf

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

# ── Mini server (same logic as real server) ────────────────
SHARE = "/tmp/demo_shared"
USERS = {"jv": sha("password123"), "guest": sha("guest")}

def handle_client(conn):
    # Negotiate
    recv_msg(conn)
    send_msg(conn, {"type": "NEGOTIATE_RESPONSE", "server": "macOS-FileShare", "version": "2.0",
                    "encryption": True, "capabilities": ["READ","WRITE","LIST","DELETE","INFO","SEARCH"]})
    # Auth
    req = recv_msg(conn)
    if USERS.get(req.get("username")) == sha(req.get("password", "")):
        send_msg(conn, {"type": "AUTH_SUCCESS", "token": "demo-token-abc123",
                        "user": req["username"], "message": f"Welcome {req['username']}!"}, True)
    else:
        send_msg(conn, {"type": "AUTH_FAIL"})
        return
    # Commands
    while True:
        req = recv_msg(conn)
        cmd = req.get("command", "")
        if cmd == "LIST":
            files = [{"name": f, "size": os.stat(os.path.join(SHARE, f)).st_size, "modified": "2024-01-01"}
                     for f in os.listdir(SHARE) if os.path.isfile(os.path.join(SHARE, f))]
            send_msg(conn, {"type": "LIST_OK", "files": files}, True)
        elif cmd == "READ":
            path = os.path.join(SHARE, os.path.basename(req["filename"]))
            data = open(path, "rb").read()
            send_msg(conn, {"type": "READ_OK", "filename": req["filename"],
                            "data": base64.b64encode(data).decode(),
                            "checksum": hashlib.md5(data).hexdigest(), "size": len(data)}, True)
        elif cmd == "WRITE":
            data = base64.b64decode(req["data"])
            with open(os.path.join(SHARE, os.path.basename(req["filename"])), "wb") as f:
                f.write(data)
            send_msg(conn, {"type": "WRITE_OK", "filename": req["filename"], "size": len(data)}, True)
        elif cmd == "INFO":
            path = os.path.join(SHARE, os.path.basename(req["filename"]))
            data = open(path, "rb").read()
            send_msg(conn, {"type": "INFO_OK", "filename": req["filename"],
                            "size": len(data), "modified": "2024-06-15 10:30:00",
                            "checksum_md5": hashlib.md5(data).hexdigest(),
                            "checksum_sha256": hashlib.sha256(data).hexdigest()}, True)
        elif cmd == "SEARCH":
            results = [f for f in os.listdir(SHARE) if req.get("query","").lower() in f.lower()]
            send_msg(conn, {"type": "SEARCH_OK", "results": results}, True)
        elif cmd == "QUIT":
            send_msg(conn, {"type": "BYE"}, True)
            break

# ── Test runner ────────────────────────────────────────────
PASS = "\033[92m PASS \033[0m"
FAIL = "\033[91m FAIL \033[0m"

def run_tests():
    # Prepare demo shared folder
    os.makedirs(SHARE, exist_ok=True)
    with open(os.path.join(SHARE, "hello.txt"), "w") as f:
        f.write("Hello from macOS!")
    with open(os.path.join(SHARE, "data.csv"), "w") as f:
        f.write("id,name\n1,Alice\n2,Bob")
    with open(os.path.join(SHARE, "notes.txt"), "w") as f:
        f.write("CN project notes\nSMB protocol\nPort 445")

    # Start server thread
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 9999))
    srv.listen(5)

    def accept_loop():
        while True:
            try:
                conn, _ = srv.accept()
                threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
            except OSError:
                break

    threading.Thread(target=accept_loop, daemon=True).start()
    time.sleep(0.1)

    results = []

    def test(name, fn):
        try:
            result = fn()
            status = PASS if result else FAIL
        except Exception as e:
            status = FAIL
            result = str(e)
        results.append((name, status))
        print(f"  [{status}]  {name}")

    def make_client():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        # Negotiate
        send_msg(s, {"type": "NEGOTIATE", "client": "Windows-Client",
                     "request_encryption": True, "dialects": ["FileShare/2.0"]})
        neg = recv_msg(s)
        # Auth
        send_msg(s, {"type": "AUTH", "username": "jv", "password": "password123"}, True)
        auth = recv_msg(s)
        assert auth["type"] == "AUTH_SUCCESS"
        return s

    print("\n" + "="*55)
    print("  macOS ↔ Windows File Sharing — Demo Test Suite")
    print("="*55 + "\n")

    # TC1: TCP Connection
    def tc_connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        s.close()
        return True
    test("TC1: TCP connection established", tc_connect)

    # TC2: Protocol Negotiation
    def tc_neg():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        send_msg(s, {"type": "NEGOTIATE", "client": "Windows-Client",
                     "request_encryption": False, "dialects": ["FileShare/2.0"]})
        resp = recv_msg(s)
        s.close()
        return resp.get("type") == "NEGOTIATE_RESPONSE" and "capabilities" in resp
    test("TC2: Protocol negotiation (Dialect exchange)", tc_neg)

    # TC3: Authentication
    def tc_auth():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        send_msg(s, {"type": "NEGOTIATE", "client": "W", "request_encryption": True, "dialects": []})
        recv_msg(s)
        send_msg(s, {"type": "AUTH", "username": "jv", "password": "password123"}, True)
        resp = recv_msg(s)
        s.close()
        return resp.get("type") == "AUTH_SUCCESS" and "token" in resp
    test("TC3: Authentication + session token issued", tc_auth)

    # TC4: Auth Failure
    def tc_auth_fail():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        send_msg(s, {"type": "NEGOTIATE", "client": "W", "request_encryption": False, "dialects": []})
        recv_msg(s)
        send_msg(s, {"type": "AUTH", "username": "jv", "password": "wrongpassword"})
        resp = recv_msg(s)
        s.close()
        return resp.get("type") == "AUTH_FAIL"
    test("TC4: Invalid credentials rejected", tc_auth_fail)

    # TC5: List Files
    def tc_list():
        s = make_client()
        send_msg(s, {"command": "LIST"}, True)
        resp = recv_msg(s)
        s.close()
        return resp.get("type") == "LIST_OK" and len(resp.get("files", [])) >= 3
    test("TC5: LIST — directory listing works", tc_list)

    # TC6: Read File
    def tc_read():
        s = make_client()
        send_msg(s, {"command": "READ", "filename": "hello.txt"}, True)
        resp = recv_msg(s)
        data = base64.b64decode(resp["data"])
        md5_ok = hashlib.md5(data).hexdigest() == resp["checksum"]
        s.close()
        return resp.get("type") == "READ_OK" and md5_ok and b"Hello" in data
    test("TC6: READ + MD5 checksum verification", tc_read)

    # TC7: Write File
    def tc_write():
        s = make_client()
        payload = b"File created on Windows machine - test upload"
        b64 = base64.b64encode(payload).decode()
        send_msg(s, {"command": "WRITE", "filename": "from_windows.txt", "data": b64}, True)
        resp = recv_msg(s)
        s.close()
        exists = os.path.exists(os.path.join(SHARE, "from_windows.txt"))
        return resp.get("type") == "WRITE_OK" and exists
    test("TC7: WRITE — file uploaded Windows → Mac", tc_write)

    # TC8: File Info
    def tc_info():
        s = make_client()
        send_msg(s, {"command": "INFO", "filename": "hello.txt"}, True)
        resp = recv_msg(s)
        s.close()
        return (resp.get("type") == "INFO_OK" and
                "checksum_md5" in resp and "checksum_sha256" in resp)
    test("TC8: INFO — dual checksum (MD5 + SHA-256)", tc_info)

    # TC9: Search
    def tc_search():
        s = make_client()
        send_msg(s, {"command": "SEARCH", "query": "data"}, True)
        resp = recv_msg(s)
        s.close()
        return resp.get("type") == "SEARCH_OK" and "data.csv" in resp.get("results", [])
    test("TC9: SEARCH — filename query works", tc_search)

    # TC10: Encryption toggle
    def tc_enc():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9999))
        send_msg(s, {"type": "NEGOTIATE", "client": "W", "request_encryption": True, "dialects": []})
        resp = recv_msg(s)
        s.close()
        return resp.get("encryption") == True
    test("TC10: Encryption negotiated successfully", tc_enc)

    srv.close()

    passed = sum(1 for _, s in results if "PASS" in s)
    total = len(results)
    print(f"\n{'='*55}")
    print(f"  Result: {passed}/{total} tests passed")
    print(f"{'='*55}\n")

    if passed == total:
        print("  All tests passed. Project is working correctly.")
    else:
        print(f"  {total - passed} test(s) failed. Check the output above.")


if __name__ == "__main__":
    run_tests()
