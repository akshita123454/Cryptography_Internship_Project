# Cryptography P2P Secure Chat

A modern, peer-to-peer (P2P) secure communication system with a graphical chat interface. This project demonstrates advanced cryptographic engineering, secure file and message transfer, and automatic peer discovery on local networks.

---

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Architecture & Security](#architecture--security)
4. [How to Run](#how-to-run)
5. [Technical Details](#technical-details)
6. [Project Structure](#project-structure)
7. [Sample Session](#sample-session)
8. [License](#license)

---

## Overview

This application enables secure, real-time chat and file transfer between peers on a local network. All communication is encrypted and authenticated using industry-standard cryptography. The GUI is built with Tkinter for ease of use.

---

## Features
- **Peer-to-peer chat and file transfer** over UDP
- **AES-256 (CBC mode)** symmetric encryption for confidentiality
- **SHA-256 HMAC** for message and file integrity
- **RSA (2048-bit) key exchange** for secure session key sharing
- **Automatic peer discovery** using UDP broadcast
- **Modern, user-friendly GUI**

---

## Architecture & Security

### Cryptographic Design
- **Key Derivation:**
  - Uses PBKDF2-HMAC-SHA256 with 100,000 iterations to derive two 32-byte keys (AES and HMAC) from a shared password and random salt.
- **Encryption:**
  - AES-256 in CBC mode with random IV per message/file.
  - PKCS7-style padding for block alignment.
- **Integrity:**
  - HMAC-SHA256 is computed over ciphertext; tag is verified before decryption.
- **Key Exchange:**
  - Each peer generates an ephemeral 2048-bit RSA key pair at startup.
  - Public keys are exchanged at session start; session keys can be encrypted with the peer's public key for forward secrecy.
- **Auto-Discovery:**
  - Peers broadcast their presence (port) every 5 seconds via UDP to a common broadcast port.
  - Peers listen for these broadcasts to dynamically populate the active peer list.
- **File Transfer:**
  - Files are split into 1024-byte chunks, each chunk is encrypted and HMAC-protected.
  - Chunks are reassembled and integrity-checked before saving.

### Network Protocol
- **UDP Sockets:** Used for all communication (messages, files, discovery, key exchange).
- **Message Types:**
  - `msg` — Encrypted chat message
  - `fchunk` — Encrypted file chunk (with chunking header)
  - `file` — Legacy single-packet file transfer
  - `pubk` — Public key exchange
  - `DISCOVER_SECURE_CHAT` — Peer discovery broadcast

---

## How to Run

### Prerequisites
- Python 3.7+
- Install dependencies:
  ```bash
  pip install cryptography pycryptodome
  ```

### Start the Application
1. Open a terminal in the project directory.
2. Run:
   ```bash
   python app_final_version.py
   ```
3. The GUI window will open. Enter:
   - Shared password (must match on both peers)
   - Your port (e.g., 5001)
   - Peer IP and port (e.g., 127.0.0.1 and 5002)
   - Click **Start Listening**
4. Repeat on another machine or terminal with a different port.
5. Use the chat window to send messages or files securely.

---

## Technical Details

### Cryptographic Flow
- **Key Derivation:**
  - `PBKDF2HMAC(SHA256, 100,000 iterations)` → 64 bytes → split into AES key (32 bytes) and HMAC key (32 bytes)
- **Encryption:**
  - Data is padded, encrypted with AES-256-CBC, and HMAC is computed over ciphertext
  - Final packet: `[salt][iv][hmac][ciphertext]`
- **Decryption:**
  - Extract salt, IV, HMAC, ciphertext
  - Derive keys, verify HMAC, then decrypt and unpad
- **RSA Key Exchange:**
  - Public keys are exchanged at session start
  - Session keys can be encrypted with peer's public key for secure delivery
- **File Transfer:**
  - Files are split into chunks, each chunk is sent as: `[file_id|filename|chunk_num|total_chunks||data]`
  - Chunks are encrypted and HMAC-protected like messages
  - Receiver reassembles and saves file after all chunks are received
- **Auto-Discovery:**
  - Every 5 seconds, each peer broadcasts their port to the network
  - Peers listen for broadcasts and update the discovered peer list

### GUI & Usability
- Built with Tkinter for cross-platform compatibility
- Modern, dark-themed interface
- Real-time chat log, file dialog for sending files
- Error handling and status messages in the chat log

---

## Project Structure

```
Cryptography_Internship_Project/
├── app_final_version.py         # Main GUI application (run this file)
├── gui_for_p2p/                 # Supporting modules for GUI and cryptography
│   ├── autodis.py
│   ├── gui.py
│   ├── p2pclient.py
│   └── rsa.py
├── Auto discovery.py            # Standalone peer discovery script
├── p2pclient.py                 # Core P2P communication logic
├── RSA Algorithm.py             # RSA cryptography utilities
├── README.md                    # Project documentation
└── ...
```

---

## Sample Session

```
[Listening on port 5001]
[Discovered Peer] 127.0.0.1:5002
[Sent] Hello peer!
[Message from 5002] Hello peer!
[File sent: example.txt in 3 chunks]
[File received: example.txt]
```

---

## License
This project is for educational and research purposes only.


