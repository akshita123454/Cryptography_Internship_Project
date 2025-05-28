# Cryptography Project  
# P2P Secure Communication System (Internship Project 2025)

---

## Project Overview

This project demonstrates a peer-to-peer (P2P) secure communication system developed during the **DRDO Cryptography Internship (2025)**. The system replicates several critical components of secure communication protocols like **SSL/TLS**, including:

- Symmetric encryption and decryption using **AES (CBC mode)**  
- **SHA-256** hash-based integrity verification  
- Secure **RSA-based key exchange mechanism**  
- Auto-discovery of active clients over a local network using **UDP broadcast**

The application is built entirely in **Python**, using standard and cryptography libraries, and facilitates secure messaging and file transfer across networked peers.

---

## Table of Contents

1. [Project Overview](#project-overview)  
2. [Features Implemented](#features-implemented)  
3. [Repository Structure](#repository-structure)  
4. [Implementation](#implementation)  
5. [Working Principle](#working-principle)  
  - [AES Encryption/Decryption](#aes-encryptiondecryption)  
  - [SHA-256-Based Integrity Check](#sha-256-based-integrity-check)
  - [RSA Key Exchange](#rsa-key-exchange)
  - [Auto Discovery of Clients](#auto-discovery-of-clients)
6. [Sample Output](#sample-output)  

---

## Features Implemented

- Peer-to-peer file and message transmission over **UDP sockets**  
- **AES (CBC mode)** symmetric encryption for confidentiality  
- **SHA-256** hash (digest) for verifying message and file integrity  
- **RSA key exchange** to securely share session keys  
- **Auto-discovery** of clients in the local network using **broadcast**

---

## Repository Structure

```
Cryptography_Internship_Project/
├── Auto discovery.py                  # Broadcast-based peer discovery module
├── Cryptology_Project_Report.docx     # Detailed technical report
├── RSA Algorithm.py                   # RSA key generation, encryption/decryption
├── p2pclient.py                       # Secure communication implementation
├── README.md                          # Project documentation
├── .gitignore                         # Git ignore configuration
└── __pycache__/                       # Python bytecode cache

```

---


---

## Implementation

### Prerequisites

Install required libraries using:

```bash
pip install cryptography pycryptodome


```


### Execution

Run two clients on different terminals (or different machines).

**Client 1 (Port 5000):**
```bash
python p2p_client.py --host 127.0.0.1 --port 5000
```

**Client 2 (Port 5001):**
```bash
python p2p_client.py --host 127.0.0.1 --port 5001 --connect 127.0.0.1:5000
```

### Commands 

```
msg     # Send an encrypted message with hash
file    # Send a file with encrypted content and integrity check
exit    # Exit the application


```

## Working Principle
### AES Encryption/Decryption
- The shared password is used to derive both:
    - a 32-byte AES key
    - a 32-byte HMAC key
- Data is padded using PKCS7, encrypted using AES in CBC mode, and sent with a random IV.
- The same process (in reverse) is used for decryption on the receiver side.

### SHA-256-Based Integrity Check
- A SHA-256 HMAC is computed for the encrypted content before sending.
- The receiver recalculates the HMAC to verify authenticity.
- If the HMAC verification fails, an integrity warning is raised and the data is rejected.

### RSA Key Exchange
- Each peer generates an RSA key pair.
- The session key used for AES encryption is encrypted with the recipient's public key.
- Only the recipient can decrypt it using their private key.

### Auto Discovery of Clients
- Clients periodically broadcast their IP and port using UDP on a common port.
- Other clients listen for these broadcasts to dynamically populate the list of active peers.
- This avoids the need to manually configure peer IPs.


---

## Sample Output

```
Enter shared password: secret123
Enter your port: 5001
Enter peer's port: 5000
[LISTENING] on port 5001...

Type msg / file / exit: msg
Enter message: Hello peer!
[SENT] Encrypted message sent.

[MESSAGE from ('127.0.0.1', 5000)] Hello peer!

```

---


