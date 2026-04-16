"""
=============================================================
  Network Packet Monitor  (run on Mac alongside server)
  Shows all packets in Wireshark-like format
  Run: python3 packet_monitor.py
=============================================================
"""

import socket
import threading
import json
import struct
import time
import os
from datetime import datetime

# Mirrors the same decoding as the server
ENC_KEY = b"CN_PROJECT_2024_SECRET_KEY_32BYTE"

def xor_decrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

PROXY_PORT  = 9001   # Monitor listens on 9001
SERVER_PORT = 9000   # Forwards to real server on 9000

packet_count = 0
session_stats = {}

def display_packet(direction, src, dst, raw_bytes, decrypted=None):
    global packet_count
    packet_count += 1
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    arrow = "→" if direction == "C→S" else "←"
    color_start = "\033[94m" if direction == "C→S" else "\033[92m"
    reset = "\033[0m"

    print(f"\n{color_start}{'─'*65}{reset}")
    print(f"{color_start}  #{packet_count:03d}  {ts}  {direction}  {src} {arrow} {dst}{reset}")
    print(f"  Raw bytes ({len(raw_bytes)}B): {raw_bytes[:32].hex()} {'...' if len(raw_bytes)>32 else ''}")

    try:
        payload_json = json.loads(decrypted or raw_bytes)
        cmd = payload_json.get("command") or payload_json.get("type") or "?"
        print(f"  Decoded:  command={cmd}")
        # Show key fields but not the full data
        for k, v in payload_json.items():
            if k == "data": continue  # skip base64 blob
            if k == "password": v = "***"
            val_str = str(v)
            if len(val_str) > 60: val_str = val_str[:57] + "..."
            print(f"            {k}: {val_str}")
    except Exception:
        print(f"  (binary / non-JSON payload)")

def proxy_connection(client_conn, client_addr):
    """Sits between client and server, logs everything"""
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv_sock.connect(("127.0.0.1", SERVER_PORT))
    except ConnectionRefusedError:
        print(f"[!] Server not running on port {SERVER_PORT}. Start file_server.py first.")
        client_conn.close()
        return

    def forward(src, dst, direction, label):
        try:
            while True:
                header = _recv_exact(src, 5)
                length, encrypted = struct.unpack("!I?", header)
                body = _recv_exact(src, length)

                decrypted = None
                if encrypted:
                    try:
                        decrypted = xor_decrypt(body, ENC_KEY)
                    except Exception:
                        pass

                display_packet(direction, label, "?", body, decrypted)
                dst.sendall(header + body)
        except (ConnectionResetError, BrokenPipeError, struct.error):
            pass

    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError
            buf += chunk
        return buf

    t1 = threading.Thread(
        target=forward, args=(client_conn, srv_sock, "C→S", client_addr[0]), daemon=True
    )
    t2 = threading.Thread(
        target=forward, args=(srv_sock, client_conn, "S→C", "server"), daemon=True
    )
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client_conn.close()
    srv_sock.close()


if __name__ == "__main__":
    print("=" * 65)
    print("  Network Packet Monitor — FileShare Protocol Analyzer")
    print(f"  Listening on port {PROXY_PORT} → forwarding to {SERVER_PORT}")
    print("  Point your client to port 9001 instead of 9000")
    print("  e.g.:  python file_client.py 192.168.1.5 9001")
    print("  Ctrl+C to stop")
    print("=" * 65)

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(("0.0.0.0", PROXY_PORT))
    proxy.listen(5)

    try:
        while True:
            conn, addr = proxy.accept()
            print(f"\n[+] Monitoring connection from {addr[0]}:{addr[1]}")
            threading.Thread(target=proxy_connection, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print(f"\n\n[!] Monitor stopped. Total packets captured: {packet_count}")
        proxy.close()
