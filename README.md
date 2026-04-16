# Cross-Platform Network File Sharing System

A custom TCP-based file sharing protocol built in Python, implementing core concepts from the OSI model including session management, authentication, encryption, and checksum verification. Inspired by real-world protocols like SMB (Server Message Block).

---

## Project Overview

This project was developed as part of a Computer Networks course to demonstrate practical implementation of network communication concepts. The system allows a **macOS machine (server)** and a **Windows machine (client)** to share files over a local Wi-Fi network using raw TCP sockets.

**Protocol:** FileShare/2.0 (custom application-layer protocol)  
**Transport:** TCP (port 9000)  
**Packet Monitor:** Port 9001 (proxy/analyzer)

---

## Features

- TCP socket-based client-server architecture
- Custom binary message framing (5-byte header: 4-byte length + 1-byte encryption flag)
- Protocol negotiation (version handshake before any data transfer)
- SHA-256 password hashing for authentication
- Session token issued after successful login
- XOR symmetric encryption (negotiated per session via `--encrypt` flag)
- MD5 + SHA-256 dual checksum verification for file integrity
- Commands: `LIST`, `READ`, `WRITE`, `DELETE`, `INFO`, `SEARCH`
- Transfer speed display (KB/s)
- Live packet monitor — Wireshark-style application-layer analyzer
- Automated test suite (10/10 passing)

---

## OSI Layer Mapping

| Layer | What We Implemented |
|-------|---------------------|
| Layer 7 — Application | LIST, READ, WRITE, DELETE, INFO, SEARCH commands |
| Layer 6 — Presentation | XOR encryption, Base64 encoding for file transfer, JSON serialization |
| Layer 5 — Session | Session token after login, stateful connection |
| Layer 4 — Transport | TCP sockets (SOCK_STREAM) |
| Layer 3 — Network | IP addressing (IPv4) |
| Layer 2 — Data Link | Handled by OS/hardware |
| Layer 1 — Physical | Wi-Fi (handled by hardware) |

---

## Folder Structure

```
cn-project/
│
├── server/
│   └── file_server.py         # Run this on Mac
│
├── client/
│   └── file_client.py         # Run this on Windows
│
├── monitor/
│   └── packet_monitor.py         # Run this on Mac (alongside server)
│
├── tests/
│   └── demo_full.py              # Automated test suite (10 test cases)
│
├── screenshots/
│   ├── mac_server_output.png     # Terminal output from Mac (server side)
│   ├── windows_client_output.png # Terminal output from Windows (client side)
│   └── packet_monitor_output.png # Packet monitor live view
│
└── README.md
```

> **Note:** Both Mac and Windows outputs go in the same `screenshots/` folder — just with different filenames so it is clear which machine produced which output.

---

## Setup Instructions

### Requirements

- Python 3.8 or above on both machines
- Both machines connected to the **same Wi-Fi network**

### Step 1 — Find Mac's IP address

On Mac, open Terminal:

```bash
ipconfig getifaddr en0
```

Note the IP address (e.g., `192.168.1.5`). You will need this on Windows.

### Step 2 — Run the server on Mac

```bash
cd server/
python3 file_server.py
```

Expected output:
```
macOS-FileShare Server v2.0
Listening on 192.168.1.5:9000
```

### Step 3 — Run the packet monitor on Mac (second terminal)

```bash
cd monitor/
python3 packet_monitor.py
```

Expected output:
```
Network Packet Monitor — FileShare Protocol Analyzer
Listening on port 9001 → forwarding to 9000
```

### Step 4 — Connect from Windows

```bash
cd client/
python file_client.py <MAC_IP> 9001 --encrypt
```

Replace `<MAC_IP>` with the IP from Step 1.

Login credentials:
```
Username: 
Password: 
```

### Step 5 — Available commands

```
fileshare> list              # List all files on Mac
fileshare> read hello.txt    # Download file from Mac to Windows
fileshare> write C:\path\to\file.txt   # Upload file from Windows to Mac
fileshare> info notes.txt    # Show file size, date, MD5, SHA-256
fileshare> search data       # Search files by name keyword
fileshare> quit              # Exit
```

---

## Running the Test Suite

Run this on Mac to verify all 10 test cases pass (server must be running first):

```bash
python3 tests/demo_full.py
```

Expected result:
```
10/10 tests passed
```

> The `ConnectionResetError` messages in the background are expected — each test deliberately closes the connection after finishing, which triggers a cleanup message from the server thread. All tests pass successfully.

---

## How Encryption Works

By default, encryption is OFF. To enable it, pass `--encrypt` when starting the client.

When enabled:
- The client sends `"request_encryption": true` during the NEGOTIATE phase
- Both sides use the same pre-shared XOR key
- Every packet is encrypted before sending and decrypted after receiving
- The packet monitor shows `[ENC]` next to encrypted packets

```bash
# Encryption ON
python file_client.py 192.168.1.5 9001 --encrypt

# Encryption OFF (default)
python file_client.py 192.168.1.5 9001
```

---

## How File Integrity Works

When a file is transferred (READ or WRITE):
1. The sender calculates MD5 and SHA-256 checksums of the file
2. The file is Base64-encoded and sent over TCP along with both checksums
3. The receiver decodes the file and independently recalculates the checksums
4. If checksums match → file arrived without corruption ✓
5. If checksums do not match → file was corrupted during transfer ✗

---

## Screenshots

| Mac — Server Terminal | Windows — Client Terminal |
|---|---|
| ![Mac Server](screenshots/mac_server_output.png) | ![Windows Client](screenshots/windows_client_output.png) |

| Packet Monitor (Mac) |
|---|
| ![Packet Monitor](screenshots/packet_monitor_output.png) |

---

## Test Cases

| Test | What It Verifies | Result |
|------|-----------------|--------|
| TC01 | TCP connection established | PASS |
| TC02 | Protocol negotiation (version handshake) | PASS |
| TC03 | Authentication with correct credentials | PASS |
| TC04 | Authentication rejection with wrong password | PASS |
| TC05 | LIST command returns file list | PASS |
| TC06 | READ command transfers file correctly | PASS |
| TC07 | WRITE command uploads file to server | PASS |
| TC08 | MD5 + SHA-256 checksum verification | PASS |
| TC09 | XOR encryption negotiation | PASS |
| TC10 | Session token issued and validated | PASS |

---

## Protocol Flow

```
Windows Client                          Mac Server
      |                                      |
      |-------- TCP CONNECT (port 9001) ---->|
      |                                      |
      |-------- NEGOTIATE (version, enc) --->|
      |<------- NEG_RESPONSE (agreed) -------|
      |                                      |
      |-------- AUTH (username, SHA-256) --->|
      |<------- AUTH_OK (session token) -----|
      |                                      |
      |-------- COMMAND (LIST/READ/WRITE) -->|
      |<------- RESPONSE (data + checksum) --|
      |                                      |
      |-------- QUIT ------------------------|
```

---

---


