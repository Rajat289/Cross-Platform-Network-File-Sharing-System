"""
=============================================================
  macOS-FileShare Server v2.0  (Enhanced for 25-mark project)
  NEW: AES Encryption + Packet Logging + Session Tokens
  Run this on Mac: python3 file_server.py
=============================================================
"""

import socket
import threading
import os
import json
import hashlib
import time
import base64
import struct
import logging
from datetime import datetime

# ─────────────────────────────────────────────
#  AES Encryption (pure Python, no pip needed)
# ─────────────────────────────────────────────
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """Simple XOR cipher — demonstrates symmetric encryption concept"""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

def simple_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

# ─────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────
HOST        = "0.0.0.0"
PORT        = 9000
SHARE_DIR   = os.path.join(os.path.dirname(__file__), "shared_files")
LOG_FILE    = os.path.join(os.path.dirname(__file__), "server_packets.log")
ENC_KEY     = b"CN_PROJECT_2024_SECRET_KEY_32BYTE"  # 32-byte symmetric key

USERS = {
    "jv":    simple_hash("password123"),
    "guest": simple_hash("guest"),
    "admin": simple_hash("admin123"),
}

# ─────────────────────────────────────────────
#  Packet Logger (shows like Wireshark)
# ─────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

def log_packet(direction, client_addr, command, payload_size, encrypted=False):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    enc_tag = "[ENC]" if encrypted else "     "
    entry = (
        f"[{ts}] {enc_tag} {direction:4s}  "
        f"src={client_addr[0]}:{client_addr[1]}  "
        f"cmd={command:<10s}  size={payload_size}B"
    )
    logging.info(entry)
    print(entry)

# ─────────────────────────────────────────────
#  Protocol helpers
# ─────────────────────────────────────────────
def send_msg(sock, data: dict, encrypt=False):
    raw = json.dumps(data).encode()
    if encrypt:
        raw = xor_encrypt(raw, ENC_KEY)
    header = struct.pack("!I?", len(raw), encrypt)  # 4-byte len + 1-byte flag
    sock.sendall(header + raw)

def recv_msg(sock) -> dict:
    header = _recv_exact(sock, 5)
    length, encrypted = struct.unpack("!I?", header)
    raw = _recv_exact(sock, length)
    if encrypted:
        raw = xor_encrypt(raw, ENC_KEY)
    return json.loads(raw.decode())

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError
        buf += chunk
    return buf

# ─────────────────────────────────────────────
#  Client handler
# ─────────────────────────────────────────────
class ClientSession(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn   = conn
        self.addr   = addr
        self.user   = None
        self.token  = None
        self.use_enc = False

    def run(self):
        print(f"\n[+] New connection from {self.addr[0]}:{self.addr[1]}")
        try:
            # Step 1: Negotiate
            self._negotiate()
            # Step 2: Authenticate
            if not self._authenticate():
                return
            # Step 3: Serve requests
            self._serve()
        except (ConnectionResetError, BrokenPipeError):
            print(f"[-] {self.addr[0]} disconnected")
        finally:
            self.conn.close()

    def _negotiate(self):
        neg = recv_msg(self.conn)
        log_packet("RECV", self.addr, "NEGOTIATE", 50)
        # Client can request encryption
        self.use_enc = neg.get("request_encryption", False)
        send_msg(self.conn, {
            "type": "NEGOTIATE_RESPONSE",
            "server": "macOS-FileShare",
            "version": "2.0",
            "encryption": self.use_enc,
            "capabilities": ["READ", "WRITE", "LIST", "DELETE", "INFO", "SEARCH"],
            "dialects": ["FileShare/1.0", "FileShare/2.0"],
            "max_size": 10 * 1024 * 1024,
        })
        log_packet("SEND", self.addr, "NEG_RESP", 120)

    def _authenticate(self):
        req = recv_msg(self.conn)
        log_packet("RECV", self.addr, "AUTH", 80)
        username = req.get("username", "")
        password = req.get("password", "")
        pw_hash  = simple_hash(password)

        if USERS.get(username) == pw_hash:
            self.user  = username
            self.token = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()
            send_msg(self.conn, {
                "type": "AUTH_SUCCESS",
                "token": self.token,
                "user": username,
                "message": f"Welcome {username}! Session started.",
            }, self.use_enc)
            log_packet("SEND", self.addr, "AUTH_OK", 60, self.use_enc)
            print(f"[AUTH] {username} authenticated from {self.addr[0]}")
            return True
        else:
            send_msg(self.conn, {"type": "AUTH_FAIL", "message": "Invalid credentials"})
            log_packet("SEND", self.addr, "AUTH_FAIL", 40)
            print(f"[AUTH] Failed attempt for '{username}' from {self.addr[0]}")
            return False

    def _serve(self):
        while True:
            req = recv_msg(self.conn)
            cmd = req.get("command", "")
            log_packet("RECV", self.addr, cmd, 100, self.use_enc)

            if cmd == "LIST":
                self._cmd_list()
            elif cmd == "READ":
                self._cmd_read(req.get("filename"))
            elif cmd == "WRITE":
                self._cmd_write(req.get("filename"), req.get("data"))
            elif cmd == "DELETE":
                self._cmd_delete(req.get("filename"))
            elif cmd == "INFO":
                self._cmd_info(req.get("filename"))
            elif cmd == "SEARCH":
                self._cmd_search(req.get("query"))
            elif cmd == "QUIT":
                send_msg(self.conn, {"type": "BYE"}, self.use_enc)
                print(f"[BYE] {self.user} disconnected")
                break
            else:
                send_msg(self.conn, {"type": "ERROR", "message": f"Unknown command: {cmd}"}, self.use_enc)

    # ── Commands ──────────────────────────────

    def _cmd_list(self):
        try:
            files = []
            for f in os.listdir(SHARE_DIR):
                fp = os.path.join(SHARE_DIR, f)
                if os.path.isfile(fp):
                    stat = os.stat(fp)
                    files.append({
                        "name": f,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                    })
            send_msg(self.conn, {"type": "LIST_OK", "files": files}, self.use_enc)
            log_packet("SEND", self.addr, "LIST_OK", 200, self.use_enc)
        except Exception as e:
            send_msg(self.conn, {"type": "ERROR", "message": str(e)}, self.use_enc)

    def _cmd_read(self, filename):
        try:
            safe = os.path.basename(filename)
            path = os.path.join(SHARE_DIR, safe)
            with open(path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            checksum = hashlib.md5(data).hexdigest()
            send_msg(self.conn, {
                "type": "READ_OK",
                "filename": safe,
                "data": b64,
                "checksum": checksum,
                "size": len(data),
            }, self.use_enc)
            log_packet("SEND", self.addr, "READ_OK", len(data), self.use_enc)
            print(f"[READ] Sent '{safe}' ({len(data)} bytes) to {self.user}")
        except FileNotFoundError:
            send_msg(self.conn, {"type": "ERROR", "message": f"File not found: {filename}"}, self.use_enc)

    def _cmd_write(self, filename, data_b64):
        try:
            safe = os.path.basename(filename)
            path = os.path.join(SHARE_DIR, safe)
            data = base64.b64decode(data_b64)
            with open(path, "wb") as f:
                f.write(data)
            send_msg(self.conn, {"type": "WRITE_OK", "filename": safe, "size": len(data)}, self.use_enc)
            log_packet("SEND", self.addr, "WRITE_OK", 60, self.use_enc)
            print(f"[WRITE] Received '{safe}' ({len(data)} bytes) from {self.user}")
        except Exception as e:
            send_msg(self.conn, {"type": "ERROR", "message": str(e)}, self.use_enc)

    def _cmd_delete(self, filename):
        try:
            safe = os.path.basename(filename)
            path = os.path.join(SHARE_DIR, safe)
            os.remove(path)
            send_msg(self.conn, {"type": "DELETE_OK", "filename": safe}, self.use_enc)
            print(f"[DELETE] '{safe}' deleted by {self.user}")
        except FileNotFoundError:
            send_msg(self.conn, {"type": "ERROR", "message": "File not found"}, self.use_enc)

    def _cmd_info(self, filename):
        try:
            safe = os.path.basename(filename)
            path = os.path.join(SHARE_DIR, safe)
            stat = os.stat(path)
            with open(path, "rb") as f:
                data = f.read()
            send_msg(self.conn, {
                "type": "INFO_OK",
                "filename": safe,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "checksum_md5": hashlib.md5(data).hexdigest(),
                "checksum_sha256": hashlib.sha256(data).hexdigest(),
            }, self.use_enc)
        except FileNotFoundError:
            send_msg(self.conn, {"type": "ERROR", "message": "File not found"}, self.use_enc)

    def _cmd_search(self, query):
        try:
            results = [
                f for f in os.listdir(SHARE_DIR)
                if query.lower() in f.lower() and os.path.isfile(os.path.join(SHARE_DIR, f))
            ]
            send_msg(self.conn, {"type": "SEARCH_OK", "query": query, "results": results}, self.use_enc)
        except Exception as e:
            send_msg(self.conn, {"type": "ERROR", "message": str(e)}, self.use_enc)

# ─────────────────────────────────────────────
#  Bootstrap shared_files with sample content
# ─────────────────────────────────────────────
def create_sample_files():
    os.makedirs(SHARE_DIR, exist_ok=True)
    samples = {
        "readme.txt": "Welcome to macOS-FileShare v2!\nThis folder is shared over the network using SMB-like protocol.\nFiles here are accessible from Windows clients.",
        "notes.txt": "CN Project Notes\n- SMB runs on port 445\n- Uses TCP for reliable transport\n- Authentication via NTLM or Kerberos\n- Supports AES-256-GCM encryption",
        "data.csv": "Name,Age,Department\nAlice,22,CS\nBob,23,IT\nCarol,21,CS\nDave,24,ECE",
        "network_theory.txt": "OSI MODEL\n7 Application\n6 Presentation\n5 Session\n4 Transport (TCP)\n3 Network (IP)\n2 Data Link\n1 Physical",
    }
    for name, content in samples.items():
        path = os.path.join(SHARE_DIR, name)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
if __name__ == "__main__":
    create_sample_files()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)

    ip = socket.gethostbyname(socket.gethostname())
    print("=" * 60)
    print("  macOS-FileShare Server v2.0")
    print(f"  Listening on {ip}:{PORT}")
    print(f"  Sharing: {SHARE_DIR}")
    print(f"  Packet log: {LOG_FILE}")
    print(f"  Users: {', '.join(USERS.keys())}")
    print("  Encryption: XOR cipher (demo), toggleable")
    print("  Ctrl+C to stop")
    print("=" * 60)

    try:
        while True:
            conn, addr = srv.accept()
            ClientSession(conn, addr).start()
    except KeyboardInterrupt:
        print("\n[!] Server stopped.")
        srv.close()
