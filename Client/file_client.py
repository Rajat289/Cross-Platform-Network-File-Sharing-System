"""
=============================================================
  Windows File Client v2.0
  Run on Windows: python file_client.py <MAC_IP>
  Example:        python file_client.py 192.168.1.5
=============================================================
"""

import socket
import sys
import os
import json
import base64
import hashlib
import struct
import time

# ─── Encryption (must match server) ──────────
ENC_KEY = b"CN_PROJECT_2024_SECRET_KEY_32BYTE"

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))

# ─── Protocol ─────────────────────────────────
def send_msg(sock, data: dict, encrypt=False):
    raw = json.dumps(data).encode()
    if encrypt:
        raw = xor_encrypt(raw, ENC_KEY)
    header = struct.pack("!I?", len(raw), encrypt)
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

# ─── Download folder ──────────────────────────
DOWNLOAD_DIR = os.path.join(os.path.dirname(__file__), "downloaded_files")
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ─── Helpers ──────────────────────────────────
def hr(): print("-" * 55)
def banner(text): print(f"\n{'='*55}\n  {text}\n{'='*55}")

def format_size(n):
    if n < 1024: return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    return f"{n/1024**2:.2f} MB"

# ─── Main client ──────────────────────────────
def main():
    server_ip = sys.argv[1] if len(sys.argv) > 1 else input("Server IP: ").strip()
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    use_enc = "--encrypt" in sys.argv

    print(f"\nConnecting to {server_ip}:{port}...")
    if use_enc:
        print("[ENC] Encryption mode ON")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((server_ip, port))
    except Exception as e:
        print(f"[ERROR] Cannot connect: {e}")
        print("Tips:\n  • Is the server running on Mac?\n  • Same Wi-Fi network?\n  • Check firewall settings")
        sys.exit(1)

    sock.settimeout(None)
    print("Connected!\n")

    # Step 1: Negotiate
    send_msg(sock, {
        "type": "NEGOTIATE",
        "client": "Windows-Client",
        "version": "2.0",
        "request_encryption": use_enc,
        "dialects": ["FileShare/1.0", "FileShare/2.0"],
    })
    neg = recv_msg(sock)
    print(f"Server:        {neg.get('server')}")
    print(f"Protocol:      {neg.get('version')}")
    print(f"Capabilities:  {', '.join(neg.get('capabilities', []))}")
    print(f"Encryption:    {'ON' if neg.get('encryption') else 'OFF'}")
    hr()

    # Step 2: Authenticate
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    send_msg(sock, {
        "type": "AUTH",
        "username": username,
        "password": password,
    }, use_enc)
    auth = recv_msg(sock)

    if auth.get("type") != "AUTH_SUCCESS":
        print(f"\n[!] Authentication failed: {auth.get('message')}")
        sock.close()
        sys.exit(1)

    print(f"\n{auth.get('message')}")
    print(f"Session token: {auth.get('token', '')[:16]}...")
    hr()

    # Step 3: Interactive shell
    print_help()

    while True:
        try:
            line = input("\nfileshare> ").strip()
        except (EOFError, KeyboardInterrupt):
            line = "quit"

        if not line:
            continue

        parts = line.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd in ("quit", "exit", "q"):
            send_msg(sock, {"command": "QUIT"}, use_enc)
            print("Goodbye!")
            break

        elif cmd == "list" or cmd == "ls":
            send_msg(sock, {"command": "LIST"}, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "LIST_OK":
                files = resp.get("files", [])
                if not files:
                    print("(No files in shared folder)")
                else:
                    print(f"\n{'Name':<30} {'Size':>10}  {'Modified'}")
                    hr()
                    for f in files:
                        print(f"  {f['name']:<28} {format_size(f['size']):>10}  {f['modified']}")
                    print(f"\n  {len(files)} file(s)")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "read" or cmd == "get":
            if not arg:
                print("Usage: read <filename>")
                continue
            t0 = time.time()
            send_msg(sock, {"command": "READ", "filename": arg}, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "READ_OK":
                data = base64.b64decode(resp["data"])
                # Verify checksum
                local_md5 = hashlib.md5(data).hexdigest()
                ok = "✓" if local_md5 == resp["checksum"] else "✗ MISMATCH"
                elapsed = time.time() - t0
                speed = format_size(len(data) / max(elapsed, 0.001)) + "/s"
                # Save file
                out_path = os.path.join(DOWNLOAD_DIR, resp["filename"])
                with open(out_path, "wb") as f:
                    f.write(data)
                print(f"\n  Downloaded: {resp['filename']}")
                print(f"  Size:       {format_size(len(data))}")
                print(f"  MD5:        {local_md5} {ok}")
                print(f"  Speed:      {speed}")
                print(f"  Saved to:   {out_path}")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "write" or cmd == "put":
            if not arg:
                print("Usage: write <local_file_path>")
                continue
            if not os.path.exists(arg):
                print(f"[ERR] File not found: {arg}")
                continue
            with open(arg, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
            t0 = time.time()
            send_msg(sock, {
                "command": "WRITE",
                "filename": os.path.basename(arg),
                "data": b64,
            }, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "WRITE_OK":
                elapsed = time.time() - t0
                speed = format_size(len(data) / max(elapsed, 0.001)) + "/s"
                print(f"\n  Uploaded: {resp['filename']} ({format_size(len(data))}) @ {speed}")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "delete" or cmd == "del" or cmd == "rm":
            if not arg:
                print("Usage: delete <filename>")
                continue
            confirm = input(f"Delete '{arg}' on server? [y/N]: ").strip().lower()
            if confirm != "y":
                print("Cancelled.")
                continue
            send_msg(sock, {"command": "DELETE", "filename": arg}, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "DELETE_OK":
                print(f"  Deleted: {resp['filename']}")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "info":
            if not arg:
                print("Usage: info <filename>")
                continue
            send_msg(sock, {"command": "INFO", "filename": arg}, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "INFO_OK":
                print(f"\n  File:       {resp['filename']}")
                print(f"  Size:       {format_size(resp['size'])}")
                print(f"  Modified:   {resp['modified']}")
                print(f"  MD5:        {resp['checksum_md5']}")
                print(f"  SHA-256:    {resp['checksum_sha256'][:32]}...")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "search" or cmd == "find":
            if not arg:
                print("Usage: search <query>")
                continue
            send_msg(sock, {"command": "SEARCH", "query": arg}, use_enc)
            resp = recv_msg(sock)
            if resp.get("type") == "SEARCH_OK":
                results = resp.get("results", [])
                print(f"\n  Results for '{arg}': {len(results)} file(s)")
                for r in results:
                    print(f"    • {r}")
            else:
                print(f"[ERR] {resp.get('message')}")

        elif cmd == "help" or cmd == "?":
            print_help()

        else:
            print(f"Unknown command: '{cmd}'. Type 'help' for commands.")

    sock.close()


def print_help():
    print("""
  Commands:
    list              Show all files on Mac server
    read <filename>   Download file from Mac to Windows
    write <path>      Upload file from Windows to Mac
    info <filename>   Show file details + checksums
    search <query>    Search files by name
    delete <filename> Delete file from server
    help              Show this help
    quit              Disconnect
""")


if __name__ == "__main__":
    main()
